/**
 * server.js — gateway transport layer.
 *
 * Runs a working Internet Gateway Device: answers PCP and NAT-PMP on UDP 5351,
 * answers SSDP on 1900, serves the device description and SOAP control over
 * HTTP, and hands approved mappings to an enforcement adapter that makes them
 * real.
 *
 * One handler covers both protocol families. A gateway does not care whether a
 * request arrived as PCP or as a SOAP envelope — the decision is the same, so
 * 'port-request' is emitted from here with the same control object shape in
 * both cases, exactly as the DHCP server does for 'discover' and 'request'.
 *
 * Nothing is granted by default and nothing is enforced by default. Those are
 * two separate opt-ins because they fail differently: without a policy the
 * gateway politely refuses, while without enforcement it agrees and quietly
 * forwards nothing. Both defaults are the safe one.
 *
 *   import { createServer, enforce } from 'port-mapper'
 *
 *   const igd = createServer({ externalIp: '81.2.3.4', enforce: enforce.all() })
 *
 *   igd.on('port-request', function (request, control) {
 *     if (request.externalPort < 1024) return control.reject()
 *     control.allow()
 *   })
 *
 *   igd.listen(function (err, info) { })
 */

import dgram from 'node:dgram';
import http from 'node:http';
import os from 'node:os';
import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import PMPServerSession from './pmp_server_session.js';
import UPnPServerSession from './upnp_server_session.js';
import { select } from './enforce/index.js';
import { wrap_control_listener, remove_control_listener } from './control.js';
import { candidates as interface_candidates, same_subnet } from './interfaces.js';
import { noop } from './enforce/relay.js';
import * as wire from './wire.js';
import * as ssdp from './ssdp.js';
import { PortMapNetworkError, PortMapValidationError, PortMapStateError } from './errors.js';


/* ========================= Identity ========================= */

/**
 * A device's UDN must survive restarts: control points key their caches on it,
 * and a gateway that presents a new one every boot looks like a new device
 * every boot. Derived from the host's MAC address, which is stable and unique
 * enough, unless the caller supplies one.
 */
function derive_udn(seed) {
  var material = seed;
  if (!material) {
    var ifaces = os.networkInterfaces();
    for (var name in ifaces) {
      for (var i = 0; i < ifaces[name].length; i++) {
        var a = ifaces[name][i];
        if (!a.internal && a.mac && a.mac !== '00:00:00:00:00:00') { material = a.mac; break; }
      }
      if (material) break;
    }
  }
  if (!material) material = os.hostname();

  var hash = crypto.createHash('sha1').update('port-mapper:' + material).digest('hex');
  return 'uuid:' + hash.slice(0, 8) + '-' + hash.slice(8, 12) + '-' + hash.slice(12, 16) +
         '-' + hash.slice(16, 20) + '-' + hash.slice(20, 32);
}


function detect_address(preferred, family) {
  var ifaces = os.networkInterfaces();
  for (var name in ifaces) {
    var addrs = ifaces[name];
    for (var i = 0; i < addrs.length; i++) {
      var a = addrs[i];
      if (a.internal) continue;
      var is4 = (a.family === 'IPv4' || a.family === 4);
      if (family === 'ipv6' ? is4 : !is4) continue;
      if (preferred && preferred !== 'auto') {
        if (a.address === preferred) return { name: name, address: a.address, netmask: a.netmask };
        continue;
      }
      return { name: name, address: a.address, netmask: a.netmask };
    }
  }
  return null;
}


/* ============================ Server ============================ */

function PortMapServer(options) {
  if (!(this instanceof PortMapServer)) return new PortMapServer(options);
  options = options || {};

  var self = this;
  var ev = new EventEmitter();
  ev.setMaxListeners(0);

  var family = options.family === 'ipv6' ? 'ipv6' : 'ipv4';
  var iface = detect_address(options.interface, family);
  if (!iface) {
    throw new PortMapNetworkError(
      'No ' + family + ' interface found. Specify { interface: "..." } explicitly.');
  }

  var lan_address = iface.address;
  var http_port   = options.httpPort || 0;         // 0 → an ephemeral port
  var udn         = options.udn || derive_udn(options.udnSeed);

  var want_pmp  = options.protocols ? options.protocols.some(function(p) {
    return p === 'pcp' || p === 'natpmp';
  }) : true;
  var want_upnp = options.protocols ? options.protocols.indexOf('upnp') !== -1 : true;
  if (!want_pmp && !want_upnp) {
    throw new PortMapValidationError(
      'protocols must contain at least one of pcp, natpmp, upnp', 'protocols');
  }

  // Nothing is enforced unless an adapter is supplied. A gateway that grants
  // mappings and forwards nothing is a worse failure than one that refuses,
  // because it fails silently — so this is opt-in and reported at startup.
  var adapters = options.enforce;
  if (adapters && !Array.isArray(adapters)) adapters = [adapters];
  if (!adapters) adapters = [noop()];

  var enforcer = null;
  var enforcer_info = null;

  var pmp = null;
  var upnp = null;
  var pmp_socket = null;
  var ssdp_socket = null;
  var http_server = null;

  var listening = false;
  var destroyed = false;
  var location = null;
  var http_port_actual = null;


  function describe_url(address) {
    return 'http://' + (String(address).indexOf(':') !== -1 ? '[' + address + ']' : address) +
           ':' + http_port_actual + '/rootDesc.xml';
  }


  /**
   * The description URL for one client.
   *
   * A gateway serving two LAN segments has to hand each of them an address on
   * their own segment. Advertising a single one means every control point on
   * the other network discovers the device and then cannot fetch its
   * description — which reads as a broken gateway rather than a wrong URL.
   */
  function location_for_client(address) {
    if (!address || !http_port_actual) return location;

    var list = interface_candidates({ family: family });
    for (var i = 0; i < list.length; i++) {
      if (same_subnet(address, list[i].address, list[i].netmask)) {
        return describe_url(list[i].address);
      }
    }
    return location;
  }


  /* ===================== Protocol engines ===================== */

  /**
   * Requests approved by either engine become real here. An enforcement
   * failure is not swallowed: the mapping is revoked again, because a gateway
   * that reports success while forwarding nothing is the failure this whole
   * layer exists to avoid.
   */
  function wire_enforcement(session) {
    session.on('port-mapped', function(mapping) {
      apply(mapping, session);
      ev.emit('port-mapped', mapping);
    });

    session.on('port-renewed', function(mapping) {
      ev.emit('port-renewed', mapping);
    });

    session.on('port-unmapped', function(mapping, reason) {
      withdraw(mapping);
      ev.emit('port-unmapped', mapping, reason);
    });

    session.on('port-expired', function(mapping) {
      withdraw(mapping);
      ev.emit('port-expired', mapping);
    });

    ['port-rejected', 'quota-exceeded', 'third-party-blocked', 'address-mismatch',
     'discovered', 'pinhole-opened', 'pinhole-closed', 'epoch-reset', 'external-ip',
     'warning'].forEach(function(name) {
      session.on(name, function() {
        ev.emit.apply(ev, [name].concat(Array.prototype.slice.call(arguments)));
      });
    });
  }


  /**
   * Deliver an event to every subscriber. The session decides what to send and
   * to whom; posting it is transport work, and it is best-effort — a
   * subscriber that has gone away simply stops being one.
   */
  function post_notifications(messages) {
    messages.forEach(function(m) {
      var req;
      try {
        req = http.request(m.url, { method: 'NOTIFY', headers: m.headers, timeout: 3000 });
      } catch (e) { return; }
      req.on('error', function() {});
      req.on('timeout', function() { req.destroy(); });
      req.end(Buffer.from(m.body));
    });
  }


  function apply(mapping, session) {
    if (!enforcer) return;
    enforcer.add({
      protocol:     mapping.protocol,
      externalPort: mapping.externalPort,
      internalIp:   mapping.internalIp,
      internalPort: mapping.internalPort
    }, function(err) {
      if (!err) return;
      ev.emit('enforce-failed', mapping, err);
      // Take the mapping back, so the client is told rather than left with a
      // grant that carries no traffic
      if (session && session.revoke) session.revoke(mapping.protocol, mapping.externalPort);
    });
  }


  function withdraw(mapping) {
    if (!enforcer) return;
    enforcer.remove({ protocol: mapping.protocol, externalPort: mapping.externalPort },
      function(err) {
        if (err) ev.emit('warning', 'Could not remove the rule for ' +
                                    mapping.protocol + '/' + mapping.externalPort +
                                    ': ' + err.message);
      });
  }


  /* ======================= Control forwarding ======================= */

  /**
   * The control object travels unchanged from the engine to the caller, so a
   * handler registered here steers a request that arrived by either protocol.
   *
   * The forwarders below are declared with exactly two parameters on purpose:
   * an engine inspects the arity of its listeners to decide whether to wait
   * for a `done` callback, and a variadic forwarder would defeat that. The
   * waiting is instead arranged here, on the caller's own handler.
   */
  function forward_control(session, name) {
    session.on(name, function(request, control) {
      ev.emit(name, request, control);
    });
  }




  var CONTROLLED = { 'port-request': true, 'pinhole-request': true };


  /* ============================ Sockets ============================ */

  function open_pmp_socket(cb) {
    var sock = dgram.createSocket({
      type: family === 'ipv6' ? 'udp6' : 'udp4',
      reuseAddr: true
    });

    sock.on('error', function(err) {
      ev.emit('error', new PortMapNetworkError('PMP socket error: ' + err.message, err));
    });

    sock.on('message', function(msg, rinfo) {
      if (!destroyed) pmp.process_packet(msg, rinfo);
    });

    pmp.on('packet', function(buf, dest) {
      if (destroyed || !sock) return;
      sock.send(buf, 0, buf.length, dest.port, dest.address, function(err) {
        if (err) ev.emit('warning', 'PMP send failed: ' + err.message);
      });
    });

    sock.bind(wire.SERVER_PORT, options.bindAddress || undefined, function() {
      try { sock.setBroadcast(true); } catch (e) {}
      try { sock.setMulticastTTL(1); } catch (e) {}
      cb(null, sock);
    });
  }


  function open_ssdp_socket(cb) {
    var sock = dgram.createSocket({
      type: family === 'ipv6' ? 'udp6' : 'udp4',
      reuseAddr: true
    });

    sock.on('error', function(err) {
      ev.emit('warning', 'SSDP socket error: ' + err.message);
    });

    sock.on('message', function(msg, rinfo) {
      if (!destroyed) upnp.process_packet(msg, rinfo);
    });

    upnp.on('packet', function(buf, dest) {
      if (destroyed || !sock) return;
      sock.send(buf, 0, buf.length, dest.port, dest.address, function(err) {
        if (err) ev.emit('warning', 'SSDP send failed: ' + err.message);
      });
    });

    // A device has to hear searches, so unlike the client this binds the SSDP
    // port itself and joins the group
    sock.bind(ssdp.MULTICAST_PORT, function() {
      try { sock.setMulticastTTL(4); } catch (e) {}
      var group = ssdp.multicast_for(family);
      try { sock.addMembership(group, family === 'ipv6' ? undefined : lan_address); }
      catch (e) { ev.emit('warning', 'Could not join ' + group + ': ' + e.message); }
      cb(null, sock);
    });
  }


  function open_http(cb) {
    var server = http.createServer(function(req, res) {
      var chunks = [];
      var length = 0;

      req.on('data', function(chunk) {
        length += chunk.length;
        // A control request is a few hundred bytes; anything larger is not a
        // control point
        if (length > (options.maxRequestBytes || 65536)) {
          res.writeHead(413).end();
          req.destroy();
          return;
        }
        chunks.push(chunk);
      });

      req.on('end', function() {
        upnp.handle_http({
          method:  req.method,
          url:     req.url,
          headers: req.headers,
          body:    new Uint8Array(Buffer.concat(chunks)),
          remote:  { address: normalise_address(req.socket.remoteAddress) }
        }, function(err, out) {
          if (err) { res.writeHead(500).end(); return; }
          var body = typeof out.body === 'string' ? out.body : Buffer.from(out.body || '');
          res.writeHead(out.statusCode, Object.assign({
            'Content-Length': Buffer.byteLength(body),
            'Server': 'Node/UPnP/1.1 port-mapper/1.0'
          }, out.headers || {}));
          res.end(body);
        });
      });
    });

    server.on('error', function(err) {
      ev.emit('error', new PortMapNetworkError('HTTP server error: ' + err.message, err));
    });

    server.listen(http_port, options.bindAddress || undefined, function() {
      cb(null, server, server.address().port);
    });
  }


  /**
   * Node reports an IPv4 peer on a dual-stack socket as ::ffff:a.b.c.d, and
   * the address is compared against what a client claims, so the two forms
   * have to be reduced to one or every such request would look like a
   * third-party attempt.
   */
  function normalise_address(address) {
    if (!address) return null;
    return address.indexOf('::ffff:') === 0 ? address.slice(7) : address;
  }


  /* ============================ Startup ============================ */

  function listen(cb) {
    cb = cb || function() {};
    if (listening) return cb(new PortMapStateError('Server already listening', 'listening'));
    if (destroyed) return cb(new PortMapStateError('Server destroyed', 'destroyed'));

    select(adapters, { require: options.require }, function(err, chosen) {
      if (err) return cb(err);

      enforcer = chosen.adapter;
      enforcer_info = chosen;

      enforcer.init({
        wanInterface: options.wanInterface,
        lanInterface: options.lanInterface,
        bindAddress:  options.bindAddress
      }, function(init_err) {
        if (init_err) return cb(init_err);

        chosen.warnings.forEach(function(w) { ev.emit('warning', w); });
        ev.emit('enforce-selected', {
          name:         chosen.name,
          capabilities: chosen.capabilities,
          rejected:     chosen.rejected
        });

        start_transports(cb);
      });
    });
  }


  function start_transports(cb) {
    var pending = 1;
    var failure = null;

    function done_one(err) {
      if (err && !failure) failure = err;
      if (--pending > 0) return;
      if (failure) return cb(failure);

      listening = true;
      if (pmp) pmp.listening();
      if (upnp) upnp.listening();

      var info = {
        udn:        udn,
        family:     family,
        interface:  iface.name,
        address:    lan_address,
        externalIp: options.externalIp || null,
        location:   location,
        protocols:  [].concat(want_pmp ? ['pcp', 'natpmp'] : [], want_upnp ? ['upnp'] : []),
        enforce:    enforcer_info ? enforcer_info.name : null,
        policy:     options.policy || 'deny-all'
      };

      ev.emit('listening', info);
      cb(null, info);
    }

    // HTTP first: the description URL has to exist before SSDP advertises it
    if (want_upnp) {
      pending++;
      open_http(function(err, server, port) {
        if (err) return done_one(err);
        http_server = server;
        http_port_actual = port;
        location = describe_url(lan_address);

        build_upnp_session();
        pending++;
        open_ssdp_socket(function(err2, sock) {
          ssdp_socket = sock;
          done_one(err2);
        });
        done_one(null);
      });
    }

    if (want_pmp) {
      pending++;
      build_pmp_session();
      open_pmp_socket(function(err, sock) {
        pmp_socket = sock;
        done_one(err);
      });
    }

    done_one(null);
  }


  function build_pmp_session() {
    if (pmp) return;
    build_sessions_for('pmp');
  }

  function build_upnp_session() {
    if (upnp) return;
    build_sessions_for('upnp');
  }

  function build_sessions_for(which) {
    if (which === 'pmp' && want_pmp) {
      pmp = new PMPServerSession({
        externalIp:     options.externalIp || null,
        policy:         options.policy || 'deny-all',
        maxLifetime:    options.maxLifetime,
        minLifetime:    options.minLifetime,
        maxMappings:    options.maxMappings,
        maxPerClient:   options.maxPerClient,
        controlTimeout: options.controlTimeout
      });
      wire_enforcement(pmp);
      forward_control(pmp, 'port-request');
    }

    if (which === 'upnp' && want_upnp) {
      upnp = new UPnPServerSession({
        udn:                 udn,
        // A function, so the address advertised is one the asking client can
        // reach — see location_for_client
        location:            location_for_client,
        igdVersion:          options.igdVersion || 2,
        externalIp:          options.externalIp || null,
        friendlyName:        options.friendlyName,
        manufacturer:        options.manufacturer,
        modelName:           options.modelName,
        policy:              options.policy || 'deny-all',
        allowThirdPartyMappings: options.allowThirdPartyMappings,
        maxLifetime:         options.maxLifetime,
        maxMappings:         options.maxMappings,
        maxPerClient:        options.maxPerClient,
        controlTimeout:      options.controlTimeout,
        connectionType:      options.connectionType,
        wanAccessType:       options.wanAccessType,
        upstreamBitRate:     options.upstreamBitRate,
        downstreamBitRate:   options.downstreamBitRate
      });
      wire_enforcement(upnp);
      upnp.on('notify', post_notifications);
      forward_control(upnp, 'port-request');
      forward_control(upnp, 'pinhole-request');
    }
  }


  /* =========================== Reconciliation =========================== */

  /**
   * Bring the enforcement layer back in step with what this gateway believes.
   *
   * Worth calling at startup with a persistent adapter: nftables and iptables
   * rules outlive the process, so a restart leaves rules in the kernel with no
   * mapping behind them. Those forward traffic nobody asked for any more, and
   * nothing else will ever remove them.
   */
  function reconcile(cb) {
    cb = cb || function() {};
    if (!enforcer) return cb(null, { adopted: 0, pruned: 0 });

    enforcer.list(function(err, rules) {
      if (err) return cb(err);

      var held = Object.create(null);
      getMappings().forEach(function(m) { held[m.protocol + ':' + m.externalPort] = m; });

      var orphans = rules.filter(function(r) {
        return !held[String(r.protocol).toLowerCase() + ':' + r.externalPort];
      });

      var pruned = 0;
      function step(i) {
        if (i >= orphans.length) {
          ev.emit('reconciled', { adopted: 0, pruned: pruned, inspected: rules.length });
          return cb(null, { adopted: 0, pruned: pruned, inspected: rules.length });
        }
        enforcer.remove(orphans[i], function() {
          pruned++;
          // An adapter that removes synchronously — noop does — would
          // otherwise recurse once per orphan
          setImmediate(function() { step(i + 1); });
        });
      }
      step(0);
    });
  }


  /* ============================ Accessors ============================ */

  function getMappings() {
    var out = [];
    if (pmp) out = out.concat(pmp.getMappings());
    if (upnp) out = out.concat(upnp.getMappings());
    return out;
  }


  function revoke(protocol, external_port) {
    var removed = null;
    if (pmp) removed = pmp.revoke(protocol, external_port) || removed;
    if (upnp) removed = upnp.revoke(protocol, external_port) || removed;
    return removed;
  }


  function setExternalIp(ip) {
    if (pmp) pmp.setExternalIp(ip);
    if (upnp) upnp.setExternalIp(ip);
  }


  /** Declare that every mapping is gone — a reboot, or a cleared table. */
  function resetEpoch() {
    getMappings().forEach(withdraw);
    if (pmp) pmp.resetEpoch();
  }


  self.listen = listen;
  self.reconcile = reconcile;
  self.getMappings = getMappings;
  self.revoke = revoke;
  self.setExternalIp = setExternalIp;
  self.resetEpoch = resetEpoch;

  self.getEnforcer = function(cb) {
    var info = enforcer_info ? {
      name:         enforcer_info.name,
      capabilities: enforcer_info.capabilities,
      rejected:     enforcer_info.rejected,
      warnings:     enforcer_info.warnings
    } : null;
    return cb ? cb(null, info) : info;
  };

  self.getStats = function() {
    return { pmp: pmp ? pmp.getStats() : null, upnp: upnp ? upnp.getStats() : null };
  };

  self.getConfig = function() {
    return {
      udn:       udn,
      family:    family,
      address:   lan_address,
      location:  location,
      policy:    options.policy || 'deny-all',
      enforce:   enforcer_info ? enforcer_info.name : null,
      protocols: [].concat(want_pmp ? ['pcp', 'natpmp'] : [], want_upnp ? ['upnp'] : [])
    };
  };

  self.close = function(cb) {
    cb = cb || function() {};
    if (destroyed) return setImmediate(cb);
    destroyed = true;
    listening = false;

    // Withdraw the rules before the engines forget which ones exist
    getMappings().forEach(withdraw);

    if (pmp) pmp.destroy();
    if (upnp) upnp.destroy();          // sends ssdp:byebye on its way out

    var pending = 1;
    function done_one() { if (--pending === 0) finish(); }

    function finish() {
      if (!enforcer) return setImmediate(cb);
      enforcer.destroy(function() { cb(); });
    }

    [pmp_socket, ssdp_socket].forEach(function(s) {
      if (!s) return;
      pending++;
      try { s.close(done_one); } catch (e) { done_one(); }
    });

    if (http_server) {
      pending++;
      try { http_server.close(done_one); } catch (e) { done_one(); }
    }

    done_one();
  };

  self.destroy = self.close;

  self.on = function(name, fn) {
    ev.on(name, CONTROLLED[name] ? wrap_control_listener(fn) : fn);
  };
  self.once = function(name, fn) {
    ev.once(name, CONTROLLED[name] ? wrap_control_listener(fn) : fn);
  };
  self.off = function(name, fn) { remove_control_listener(ev, name, fn); };

  Object.defineProperty(self, 'udn', { get: function() { return udn; }, enumerable: true });
  Object.defineProperty(self, 'location', { get: function() { return location; }, enumerable: true });

  return self;
}


function createServer(options) {
  return new PortMapServer(options);
}


export { PortMapServer, createServer, derive_udn };
export default PortMapServer;
