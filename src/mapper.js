/**
 * mapper.js — client transport layer for all three protocols.
 *
 * Wires PMPSession and UPnPSession to real sockets, auto-detects the gateway
 * and our own address, negotiates which protocol the gateway actually speaks,
 * and presents one API over whichever won.
 *
 * Three sockets and an HTTP client, because the protocols share no transport:
 *
 *   PMP request socket   ephemeral port → gateway:5351. The gateway replies to
 *                        the source port, so nothing privileged is needed.
 *   PMP announce socket  bound to 5350 and joined to 224.0.0.1. RFC 6886
 *                        §3.2.1 has the gateway multicast its address and
 *                        epoch on boot and on external-address change, which
 *                        is how a reboot is noticed without waiting for the
 *                        next renewal. Best-effort: another process may hold
 *                        the port, which is not fatal.
 *   SSDP socket          ephemeral port → 239.255.255.250:1900 for M-SEARCH,
 *                        joined to the same group so NOTIFY is heard too.
 *   http()               injected into UPnPSession; SOAP control is HTTP.
 *
 * References:
 *   RFC 6886 §3     — send to the default gateway; only meaningful behind NAT
 *   RFC 6886 §3.2.1 — bind specifically to 224.0.0.1:5350, allow port reuse
 *   RFC 6886 §3.8   — an ICMP Port Unreachable means "no support here"
 *   RFC 6886 §9.3   — IGD replies are XML of unbounded size; cap them
 *   UPnP DA 1.1 §1  — SSDP on 239.255.255.250:1900
 */

import dgram from 'node:dgram';
import http from 'node:http';
import os from 'node:os';
import fs from 'node:fs';
import { execSync } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { safe_timeout, clear_safe_timeout } from './timers.js';
import PMPSession from './pmp_session.js';
import UPnPSession from './upnp_session.js';
import { negotiate } from './negotiate.js';
import * as reachability from './reachability.js';
import * as interfaces from './interfaces.js';
import * as wire from './wire.js';
import * as ssdp from './ssdp.js';
import {
  CGNATError,
  NoGatewayError,
  PortMapNetworkError,
  PortMapStateError,
  PortMapTimeoutError,
  PortMapValidationError
} from './errors.js';
import { dbg } from './debug.js';


/* ========================= Auto-detection ========================= */

/**
 * Find the primary non-internal IPv4 interface.
 * Returns { name, address, netmask } or null.
 */
/**
 * Find a usable address, for one family.
 *
 * For IPv6 the choice matters more than it does for IPv4. A machine normally
 * holds several v6 addresses at once — a link-local fe80:: one that always
 * exists and is never routable, plus possibly a unique-local fd00:: and a
 * global one. Only the global address is worth mapping, and it is not
 * necessarily listed first, so the candidates are ranked rather than taken in
 * order.
 */
function detect_interface(preferred_ip, family) {
  family = family || 'ipv4';
  var ifaces = os.networkInterfaces();
  var candidates = [];

  for (var name in ifaces) {
    var addrs = ifaces[name];
    for (var i = 0; i < addrs.length; i++) {
      var a = addrs[i];
      if (a.internal) continue;

      var is4 = (a.family === 'IPv4' || a.family === 4);
      var is6 = (a.family === 'IPv6' || a.family === 6);
      if (family === 'ipv4' && !is4) continue;
      if (family === 'ipv6' && !is6) continue;

      var entry = {
        name:     name,
        address:  a.address,
        netmask:  a.netmask,
        family:   is6 ? 'ipv6' : 'ipv4',
        scopeid:  a.scopeid
      };

      if (preferred_ip && preferred_ip !== 'auto') {
        if (a.address === preferred_ip) return entry;
        continue;
      }
      candidates.push(entry);
    }
  }

  if (preferred_ip && preferred_ip !== 'auto') return null;
  if (!candidates.length) return null;
  if (family === 'ipv4') return candidates[0];

  // Global unicast first, then unique-local, and link-local only as a last
  // resort — a pinhole on fe80:: could never be reached from anywhere
  var rank = { public: 0, ula: 1, linklocal: 2 };
  candidates.sort(function(a, b) {
    var ra = rank[wire.classify_ipv6_address(a.address)];
    var rb = rank[wire.classify_ipv6_address(b.address)];
    return (ra === undefined ? 3 : ra) - (rb === undefined ? 3 : rb);
  });
  return candidates[0];
}


/**
 * Detect the default gateway by parsing OS-specific routing tables.
 * Returns IP string or null.
 */
/**
 * The IPv6 default route. There is no equivalent of /proc/net/route worth
 * parsing here — /proc/net/ipv6_route is hex triples without a stable column
 * layout — so the routing tools are asked instead, as they are on the other
 * platforms.
 */
function detect_gateway6() {
  try {
    if (process.platform === 'linux') {
      var out = execSync('ip -6 route show default 2>/dev/null', { encoding: 'utf8' });
      var m = /default\s+via\s+([0-9a-fA-F:]+)/.exec(out);
      if (m) return m[1];
    } else if (process.platform === 'darwin') {
      var mac = execSync('route -n get -inet6 default 2>/dev/null', { encoding: 'utf8' });
      var mm = /gateway:\s+([0-9a-fA-F:]+(?:%\w+)?)/.exec(mac);
      if (mm) return mm[1];
    } else if (process.platform === 'win32') {
      var win = execSync('netsh interface ipv6 show route', { encoding: 'utf8' });
      var lines = win.split('\n');
      for (var i = 0; i < lines.length; i++) {
        if (lines[i].indexOf('::/0') === -1) continue;
        var w = /([0-9a-fA-F]{0,4}:[0-9a-fA-F:]+)\s*$/.exec(lines[i].trim());
        if (w) return w[1];
      }
    }
  } catch (e) {
    dbg('transport', 'IPv6 gateway detection failed:', e.message);
  }
  return null;
}


function detect_gateway(family) {
  if (family === 'ipv6') return detect_gateway6();
  try {
    if (process.platform === 'linux') {
      // /proc/net/route — destination 00000000 is the default route,
      // gateway is little-endian hex
      var route_data = fs.readFileSync('/proc/net/route', 'utf8');
      var lines = route_data.split('\n');
      for (var i = 1; i < lines.length; i++) {
        var fields = lines[i].split(/\s+/);
        if (fields.length < 3) continue;
        if (fields[1] === '00000000') {
          var hex = fields[2];
          var b1 = parseInt(hex.slice(6, 8), 16);
          var b2 = parseInt(hex.slice(4, 6), 16);
          var b3 = parseInt(hex.slice(2, 4), 16);
          var b4 = parseInt(hex.slice(0, 2), 16);
          return b1 + '.' + b2 + '.' + b3 + '.' + b4;
        }
      }
    } else if (process.platform === 'darwin') {
      var output = execSync('route -n get default 2>/dev/null', { encoding: 'utf8' });
      var match = output.match(/gateway:\s+(\d+\.\d+\.\d+\.\d+)/);
      if (match) return match[1];
    } else if (process.platform === 'win32') {
      var output_w = execSync('route print -4 0.0.0.0', { encoding: 'utf8' });
      var lines_w = output_w.split('\n');
      for (var j = 0; j < lines_w.length; j++) {
        var m = lines_w[j].match(/0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)/);
        if (m) return m[1];
      }
    }
  } catch (e) {
    dbg('transport', 'gateway detection failed:', e.message);
  }
  return null;
}


/* ============================ HTTP client ============================ */

/**
 * Minimal HTTP client for SOAP control and description fetches.
 *
 * Bounded on purpose. RFC 6886 §9.3 observes that IGD replies are XML of
 * unbounded size — a 4-byte external address routinely arrives inside a
 * document of several kilobytes, with nothing in the specification stopping
 * it being far larger — so a client cannot know in advance how much memory to
 * allow. Everything past the cap is discarded and the request fails cleanly.
 */
function make_http_client(options) {
  var timeout = options.httpTimeout || 5000;
  var max_bytes = options.maxResponseBytes || 1024 * 1024;

  return function do_http(req, cb) {
    var called = false;
    function finish(err, res) {
      if (called) return;
      called = true;
      cb(err, res);
    }

    var request;
    try {
      request = http.request(req.url, {
        method:  req.method || 'GET',
        headers: req.headers || {},
        timeout: timeout
      });
    } catch (e) {
      return finish(new PortMapNetworkError('Bad control URL ' + req.url + ': ' + e.message, e));
    }

    request.on('response', function(res) {
      var chunks = [];
      var length = 0;
      var overflowed = false;

      res.on('data', function(chunk) {
        if (overflowed) return;
        length += chunk.length;
        if (length > max_bytes) {
          overflowed = true;
          res.destroy();
          return finish(new PortMapNetworkError(
            'Gateway response exceeded ' + max_bytes + ' bytes'));
        }
        chunks.push(chunk);
      });

      res.on('end', function() {
        if (overflowed) return;
        finish(null, {
          statusCode: res.statusCode,
          headers:    res.headers,
          body:       new Uint8Array(Buffer.concat(chunks))
        });
      });

      res.on('error', function(e) {
        finish(new PortMapNetworkError('Response error from ' + req.url + ': ' + e.message, e));
      });
    });

    request.on('timeout', function() {
      request.destroy();
      // Distinct from a network error on purpose: a gateway that never answers
      // is a different situation from one that refused the connection, and a
      // caller deciding whether to retry needs to tell them apart.
      finish(new PortMapTimeoutError(
        'Request to ' + req.url + ' timed out after ' + timeout + 'ms', timeout));
    });

    request.on('error', function(e) {
      finish(new PortMapNetworkError('Request to ' + req.url + ' failed: ' + e.message, e));
    });

    if (req.body) request.end(Buffer.from(req.body));
    else request.end();
  };
}


/* ============================== Mapper ============================== */

function Mapper(options) {
  if (!(this instanceof Mapper)) return new Mapper(options);
  options = options || {};

  var self = this;
  var ev = new EventEmitter();
  ev.setMaxListeners(0);

  // Which address family this Mapper works in.
  //
  // One Mapper handles one family, deliberately. An IPv4 mapping and an IPv6
  // pinhole are not two flavours of one operation: the first translates an
  // address and yields an external port that differs from the internal one,
  // while the second only lifts a firewall rule and has no external port at
  // all. Collapsing them into a single call would mean inventing a result
  // shape that fits neither. Run two Mappers to do both.
  var family = options.family || 'ipv4';
  if (family !== 'ipv4' && family !== 'ipv6') {
    throw new PortMapValidationError('family must be "ipv4" or "ipv6"', 'family');
  }

  // The gateway is worked out first, because which interface to use is
  // decided by which one can reach it
  var probe_gateway = (options.gateway === undefined || options.gateway === 'auto')
    ? detect_gateway(family) : options.gateway;

  var iface = interfaces.select({
    family:    family,
    gateway:   probe_gateway,
    preferred: options.interface
  });
  if (!iface) {
    throw new PortMapNetworkError(
      'No ' + family + ' interface found' +
      (family === 'ipv6'
        ? ' — this host may have no IPv6 connectivity, or only a link-local address'
        : '') +
      '. Specify { interface: "..." } explicitly.');
  }

  if (family === 'ipv6' && wire.classify_ipv6_address(iface.address) === 'linklocal') {
    // Worth saying out loud: a pinhole for fe80:: can never be reached
    dbg('transport', 'only a link-local IPv6 address is available');
  }

  var gateway = probe_gateway;
  if (gateway) {
    try { wire.encode_ip(gateway); }
    catch (e) { throw new PortMapValidationError('gateway invalid: ' + e.message, 'gateway'); }
  }

  // Which engines to build. UPnP discovers by multicast and can work without
  // a known default route, so a missing gateway is only fatal for PCP/NAT-PMP.
  var wanted = options.protocols || ['pcp', 'natpmp', 'upnp'];
  var pmp_protocols = wanted.filter(function(p) { return p === 'pcp' || p === 'natpmp'; });
  var want_upnp = wanted.indexOf('upnp') !== -1;

  // RFC 6886 defines NAT-PMP over IPv4 only — there is no version of it that
  // carries a v6 address, and no gateway that would answer one. PCP replaced
  // it partly for that reason, so a v6 Mapper simply drops it.
  if (family === 'ipv6') {
    pmp_protocols = pmp_protocols.filter(function(p) { return p !== 'natpmp'; });
  }

  if (!pmp_protocols.length && !want_upnp) {
    throw new PortMapValidationError(
      'protocols must contain at least one of pcp, natpmp, upnp', 'protocols');
  }
  if (pmp_protocols.length && !gateway) {
    if (!want_upnp) {
      throw new NoGatewayError(
        'Could not determine the default gateway, which PCP and NAT-PMP require. ' +
        'Specify { gateway: "192.168.1.1" }, or use { protocols: ["upnp"] }.',
        [process.platform]);
    }
    pmp_protocols = [];   // carry on with UPnP alone
  }

  var do_http = options.http || make_http_client(options);

  var pmp = pmp_protocols.length ? new PMPSession({
    gateway:             gateway,
    clientIp:            iface.address,
    protocols:           pmp_protocols,
    lifetime:            options.lifetime,
    retransmitAttempts:  options.retransmitAttempts,
    rebootRecreateDelay: options.rebootRecreateDelay
  }) : null;

  var upnp = want_upnp ? new UPnPSession({
    family:        family,
    localIp:       iface.address,
    netmask:       iface.netmask,
    gateway:       gateway,
    http:          do_http,
    lifetime:      options.lifetime,
    description:   options.description,
    searchTimeout: options.searchTimeout,
    searchUnicast: options.searchUnicast,
    allowOffPath:  options.allowOffPath
  }) : null;

  /**
   * Events forwarded from the protocol engines to the caller.
   *
   * Everything an engine emits is listed except the transport-internal ones
   * ('packet', 'listening', 'ready', 'destroyed', 'error'), which belong to
   * this layer rather than above it. Keeping the list exhaustive is checked by
   * a test rather than by discipline: a session gaining an event and this list
   * not gaining it is silent — the event simply never reaches anyone, which is
   * exactly how the first external-ip-changed notification was lost.
   */
  var FORWARDED = [
    // mapping lifecycle
    'mapped', 'renewed', 'lost', 'remapped', 'unmapped', 'conflict', 'empty-port',
    // gateway state
    'gateway-reboot', 'gateway-gone', 'gateway-restarted', 'gateway-updated',
    'external-ip-changed', 'degraded', 'device', 'quirks', 'service-described',
    // eventing
    'subscribed', 'unsubscribed', 'event', 'events-missed',
    // IPv6 and housekeeping
    'pinhole', 'pinhole-closed', 'stale-removed',
    'warning'
  ];

  FORWARDED.forEach(function(name) {
    function relay() { ev.emit.apply(ev, [name].concat(Array.prototype.slice.call(arguments))); }
    if (pmp)  pmp.on(name, relay);
    if (upnp) upnp.on(name, relay);
  });

  var pmp_socket = null;
  var announce_socket = null;
  var ssdp_socket = null;

  var started = false;
  var destroyed = false;
  var chosen = null;
  var bind_address = options.bindAddress || '0.0.0.0';
  var listen_announcements = options.announcements !== false;
  var exit_hook = null;

  // protocol:internalPort → external port, so unmap() can be called the same
  // way whichever engine won: PMP deletes by internal port, UPnP by external.
  var index = Object.create(null);


  /* ================ Outgoing datagrams ================ */

  if (pmp) {
    pmp.on('packet', function(buf, dest) {
      if (!started || destroyed || !pmp_socket) return;
      pmp_socket.send(buf, 0, buf.length, dest.port, dest.address, function(err) {
        if (!err) return;
        // RFC 6886 §3.8 — a device not acting as a NAT should answer ICMP Port
        // Unreachable, which surfaces as ECONNREFUSED. A definite "no support
        // here", not a reason to keep retransmitting.
        if (err.code === 'ECONNREFUSED') {
          ev.emit('unsupported', { gateway: dest.address, reason: 'ICMP port unreachable' });
          return;
        }
        ev.emit('warning', 'PMP send error to ' + dest.address + ':' + dest.port + ': ' + err.message);
      });
    });
  }

  if (upnp) {
    upnp.on('packet', function(buf, dest) {
      if (!started || destroyed || !ssdp_socket) return;
      ssdp_socket.send(buf, 0, buf.length, dest.port, dest.address, function(err) {
        if (err) ev.emit('warning', 'SSDP send error: ' + err.message);
      });
    });
  }


  /* ================ Sockets ================ */

  var socket_type = family === 'ipv6' ? 'udp6' : 'udp4';
  var wildcard = family === 'ipv6' ? '::' : '0.0.0.0';

  function open_pmp_socket(cb) {
    var sock = dgram.createSocket({ type: socket_type, reuseAddr: true });
    sock.on('error', function(e) {
      ev.emit('error', new PortMapNetworkError('PMP socket error: ' + e.message, e));
    });
    sock.on('message', function(msg, rinfo) {
      if (!destroyed) pmp.process_packet(msg, rinfo);
    });
    // Ephemeral source port — the gateway replies to wherever we sent from
    sock.bind(0, bind_address || wildcard, function() { cb(sock); });
  }


  /**
   * Best-effort multicast listener for NAT-PMP/PCP announcements. RFC 6886
   * §3.2.1 notes that several processes on one host may want these, so the
   * socket allows reuse; any failure is a warning, not an error.
   */
  function open_announce_socket() {
    var sock = dgram.createSocket({ type: socket_type, reuseAddr: true });

    sock.on('error', function(err) {
      ev.emit('warning', 'Announcement listener unavailable: ' + err.message);
      try { sock.close(); } catch (e) {}
      if (announce_socket === sock) announce_socket = null;
    });

    sock.on('message', function(msg, rinfo) {
      if (destroyed || !pmp) return;
      dbg('transport', 'announcement from', rinfo.address);
      pmp.process_packet(msg, rinfo);
    });

    try {
      sock.bind(wire.CLIENT_PORT, function() {
        // RFC 6887 §8.1 — PCP announcements reach IPv6 clients on ff02::1,
        // the all-nodes link-local group, rather than on the v4 group
        var group = family === 'ipv6' ? wire.PCP_MULTICAST_V6 : wire.NATPMP_MULTICAST;
        try {
          sock.addMembership(group, family === 'ipv6' ? undefined : iface.address);
        } catch (e) {
          ev.emit('warning', 'Could not join ' + group + ': ' + e.message);
        }
      });
    } catch (e) {
      ev.emit('warning', 'Announcement listener unavailable: ' + e.message);
      return null;
    }

    return sock;
  }


  function open_ssdp_socket(cb) {
    var sock = dgram.createSocket({ type: socket_type, reuseAddr: true });

    sock.on('error', function(e) { ev.emit('warning', 'SSDP socket error: ' + e.message); });
    sock.on('message', function(msg, rinfo) {
      if (!destroyed) upnp.process_packet(msg, rinfo);
    });

    // M-SEARCH replies come back unicast to the source port, so an ephemeral
    // bind is enough for discovery. Joining the group as well lets us hear
    // NOTIFY ssdp:byebye when the gateway leaves the network.
    sock.bind(0, bind_address || wildcard, function() {
      try { sock.setBroadcast(true); } catch (e) {}
      try { sock.setMulticastTTL(4); } catch (e) {}

      // Which interface multicast *leaves* by. Membership only governs what
      // arrives; without this the kernel picks the outgoing route itself, and
      // on a host with docker0 or a VPN up that is frequently the wrong one —
      // the M-SEARCH then goes out an interface the gateway is not on and
      // discovery quietly finds nothing.
      try { sock.setMulticastInterface(iface.address); }
      catch (e) { dbg('transport', 'could not pin multicast egress:', e.message); }

      var group = ssdp.multicast_for(family);
      try { sock.addMembership(group, family === 'ipv6' ? undefined : iface.address); }
      catch (e) { dbg('transport', 'SSDP group join failed:', e.message); }
      cb(sock);
    });
  }


  /* ================ Start ================ */

  function start(cb) {
    cb = cb || function() {};
    if (started)   return cb(new PortMapStateError('Mapper already started', 'started'));
    if (destroyed) return cb(new PortMapStateError('Mapper destroyed', 'destroyed'));

    var waiting = 1;   // held until both opens have been requested
    function ready() {
      if (--waiting > 0) return;
      started = true;
      if (pmp) pmp.listening();
      run_negotiation(cb);
    }

    if (pmp) {
      waiting++;
      open_pmp_socket(function(sock) {
        pmp_socket = sock;
        if (listen_announcements) announce_socket = open_announce_socket();
        ready();
      });
    }

    if (upnp) {
      waiting++;
      open_ssdp_socket(function(sock) { ssdp_socket = sock; ready(); });
    }

    ready();
  }


  function run_negotiation(cb) {
    negotiate({
      pmp:     pmp,
      upnp:    upnp,
      timeout: options.negotiateTimeout || 10000
    }, function(err, result) {
      if (destroyed) return;

      chosen = result;

      var info = {
        family:     family,
        gateway:    gateway,
        interface:  iface.name,
        localIp:    iface.address,
        protocol:   result ? result.protocol : null,
        externalIp: result ? result.externalIp : null,
        device:     result ? result.device : null,
        results:    result ? result.results : null,
        // RFC 6886 §3 — the protocol is only meaningful when our own address
        // is private. A public address means there is no NAT to ask.
        behindNat:  wire.is_private_address(iface.address)
      };

      if (err) {
        ev.emit('unavailable', info);
        return cb(err, info);
      }

      if (!info.behindNat) {
        ev.emit('warning',
          'Local address ' + iface.address + ' is not in a private range — there may be ' +
          'no NAT in front of this host, in which case no mapping is needed.');
      }

      if (options.cleanupOnExit !== false) install_exit_hook();
      if (options.watchdog) startWatchdog(typeof options.watchdog === 'object' ? options.watchdog : {});

      // Ask once, here.
      //
      // PCP and NAT-PMP hand the external address back with the probe, but
      // UPnP does not — it is a separate action — so a caller that has only
      // started the Mapper knows nothing about the address until the first
      // mapping succeeds. That is exactly backwards for anything that wants to
      // decide *whether* to map based on where it is, and it is one round trip.
      if (chosen && chosen.protocol === 'upnp' && !info.externalIp) {
        return upnp.getExternalIp(function(_, res) {
          var address = res && res.externalIp;
          if (address) {
            info.externalIp = address;
            chosen.externalIp = address;
            info.addressKind = wire.classify_external_address(address);
          }
          ev.emit('ready', info);
          cb(null, info);
        });
      }

      if (info.externalIp) info.addressKind = wire.classify_external_address(info.externalIp);
      ev.emit('ready', info);
      cb(null, info);
    });
  }


  /**
   * Delete our mappings when the process ends.
   *
   * Best-effort by nature: 'exit' runs synchronously and cannot wait for a
   * socket, and a crash or a kill -9 skips it entirely. That is fine, and it
   * is why the mappings carry a finite lease in the first place — RFC 6886
   * §9.5 makes the same point, that an abruptly disconnected client's
   * mappings are reclaimed when they are not renewed. This just returns the
   * ports sooner in the common case.
   */
  function install_exit_hook() {
    if (exit_hook) return;

    exit_hook = function() {
      if (destroyed) return;
      var mappings = self.getMappings();
      for (var i = 0; i < mappings.length; i++) {
        // Fire and forget: there is no time left to wait for replies
        try { unmap({ protocol: mappings[i].protocol, internalPort: mappings[i].internalPort }); }
        catch (e) {}
      }
    };

    process.on('beforeExit', exit_hook);
    process.on('SIGINT', exit_hook);
    process.on('SIGTERM', exit_hook);
  }


  function remove_exit_hook() {
    if (!exit_hook) return;
    process.removeListener('beforeExit', exit_hook);
    process.removeListener('SIGINT', exit_hook);
    process.removeListener('SIGTERM', exit_hook);
    exit_hook = null;
  }


  /* ================ Mapping ================ */

  function require_ready(cb) {
    if (destroyed) { cb(new PortMapStateError('Mapper destroyed', 'destroyed')); return false; }
    if (!chosen || !chosen.session) {
      cb(new PortMapStateError('Not started, or no gateway available — call start() first', 'new'));
      return false;
    }
    return true;
  }


  var status_checked = false;

  /**
   * A gateway whose WAN side is down will accept a mapping that cannot carry
   * any traffic. Only IGD reports its connection state, so this is checked
   * once, before the first mapping, and reported as a warning rather than an
   * error — the state variable is not always maintained accurately, and
   * refusing to map because of it would be worse than mapping in vain.
   */
  function check_status_once(cb) {
    if (status_checked || chosen.protocol !== 'upnp') return cb();
    status_checked = true;

    chosen.session.getStatus(function(err, st) {
      if (!err && st && !st.connected) {
        ev.emit('warning',
          'The gateway reports its internet connection as "' + st.status + '"' +
          (st.lastError && st.lastError !== 'ERROR_NONE' ? ' (' + st.lastError + ')' : '') +
          '. A mapping made now may not carry any traffic.');
      }
      cb();
    });
  }


  /**
   * Map a port. The returned handle abandons the request if it has not been
   * answered yet — useful because the retransmission schedule can run for over
   * two minutes against a gateway that never replies.
   */
  function map(opts, cb) {
    cb = cb || function() {};
    if (!require_ready(cb)) return { cancel: function() { return false; } };
    opts = opts || {};

    var inner = null;
    var cancelled = false;
    var settled = false;

    check_status_once(function() {
      if (cancelled) return;
      inner = do_map(opts, function() {
        settled = true;
        cb.apply(null, arguments);
      });
    });

    return {
      cancel: function(reason) {
        if (cancelled || settled) return false;
        cancelled = true;
        if (inner && inner.cancel) return inner.cancel(reason);
        // Cancelled before the status check finished, so nothing was sent
        cb(cancel_error(reason));
        return true;
      }
    };
  }


  function cancel_error(reason) {
    var err = new PortMapStateError(reason || 'Cancelled', 'cancelled');
    err.cancelled = true;
    return err;
  }


  function do_map(opts, cb) {
    // Mapping a port with nothing behind it is the most common mistake here,
    // and it looks like a complete success from every side: the gateway does
    // exactly what it was asked and the traffic arrives nowhere. Advisory
    // only — a service bound to one specific address can be invisible to this.
    if (options.checkLocalPort === false || !opts.internalPort) {
      return send_map(opts, cb);
    }

    // The check is quick but not instant, so the handle has to survive it:
    // a caller that cancels during the check must still stop the request that
    // the check is about to start
    var inner = null;
    var abandoned = false;

    interfaces.port_in_use({
      port: opts.internalPort, protocol: opts.protocol || 'tcp'
    }, function(_, res) {
      if (abandoned) return;
      if (res && res.inUse === false) {
        ev.emit('warning',
          'Nothing is listening on ' + (opts.protocol || 'tcp') + '/' +
          opts.internalPort + ' — the mapping will be created, but traffic ' +
          'sent to it will arrive nowhere.');
        ev.emit('empty-port', { protocol: opts.protocol || 'tcp',
                                internalPort: opts.internalPort });
      }
      inner = send_map(opts, cb);
    });

    return {
      cancel: function(reason) {
        if (inner && inner.cancel) return inner.cancel(reason);
        if (abandoned) return false;
        abandoned = true;
        cb(cancel_error(reason));
        return true;
      }
    };
  }


  function send_map(opts, cb) {
    // On IPv6 there is no translation, so WANIPConnection is the wrong service
    // entirely: what is wanted is a hole in the firewall. PCP needs no such
    // branch — its MAP opcode covers both, because its addresses were always
    // sixteen bytes.
    if (family === 'ipv6' && chosen.protocol === 'upnp') {
      chosen.session.addPinhole({
        internalIp:   iface.address,
        internalPort: opts.internalPort,
        protocol:     opts.protocol || 'tcp',
        remoteHost:   opts.remoteHost,
        remotePort:   opts.remotePort,
        lifetime:     opts.lifetime
      }, function(err, pinhole) {
        if (err) return cb(err);
        cb(null, {
          protocol:     pinhole.protocol,
          internalIp:   pinhole.internalIp,
          internalPort: pinhole.internalPort,
          // A pinhole has no external port: the address is already the one the
          // internet reaches, so the port on the wire is the port it is bound to
          externalPort: pinhole.internalPort,
          externalIp:   pinhole.internalIp,
          uniqueId:     pinhole.uniqueId,
          lifetime:     pinhole.leaseTime,
          via:          'upnp-pinhole',
          state:        'ACTIVE'
        });
      });
      return { cancel: function() { return false; } };
    }

    return chosen.session.map(opts, function(err, mapping) {
      if (err) return cb(err);
      index[(mapping.protocol || 'tcp') + ':' + mapping.internalPort] = mapping.externalPort;
      cb(null, mapping);
    });
  }


  /**
   * Delete by internal port whichever engine won. PMP addresses a mapping by
   * its internal port and UPnP by its external one, so the external port is
   * recovered from what map() recorded.
   */
  function unmap(opts, cb) {
    cb = cb || function() {};
    if (!require_ready(cb)) return;
    if (typeof opts === 'number') opts = { internalPort: opts };
    opts = opts || {};

    var protocol = (opts.protocol || 'tcp').toLowerCase();
    var key = protocol + ':' + opts.internalPort;

    if (chosen.protocol === 'upnp') {
      var external = opts.externalPort || index[key];
      if (!external) {
        return cb(new PortMapValidationError(
          'externalPort required — this mapping was not created by this Mapper, so its ' +
          'external port is not known here', 'externalPort'));
      }
      return chosen.session.unmap({ protocol: protocol, externalPort: external }, function(err, m) {
        delete index[key];
        cb(err, m);
      });
    }

    chosen.session.unmap({ protocol: protocol, internalPort: opts.internalPort }, function(err, m) {
      delete index[key];
      cb(err, m);
    });
  }


  function getExternalIp(cb) {
    if (!require_ready(cb)) return;
    chosen.session.getExternalIp(cb);
  }


  /**
   * Work out whether a mapping made here can actually be reached, and say why
   * when it cannot.
   *
   * The check that matters is the address the gateway calls its own external
   * one. A mapping can be created successfully and still be useless: if that
   * address is in RFC 1918 space the gateway is itself behind another NAT, and
   * if it is in RFC 6598 shared space the ISP is translating too. In both
   * cases inbound packets stop at the upstream device, which holds no mapping.
   */
  function diagnose(cb) {
    cb = cb || function() {};

    var report = {
      reachable:  null,
      reason:     null,
      detail:     null,
      suggestion: null,
      // 'inferred' from the address the gateway reports, or 'verified' against
      // what a STUN server on the internet actually observes
      method:     'inferred',
      gateway:    gateway,
      localIp:    iface.address,
      externalIp: null,
      publicAddress: null,
      natType:    null,
      protocol:   chosen ? chosen.protocol : null,
      device:     chosen ? chosen.device : null,
      protocols:  chosen ? chosen.results : null,
      behindNat:  wire.is_private_address(iface.address)
    };

    if (!chosen || !chosen.session) {
      report.reachable  = false;
      report.reason     = 'NO_GATEWAY';
      report.detail     = 'No gateway on this network answered PCP, NAT-PMP or UPnP-IGD.';
      report.suggestion = 'Check that UPnP or NAT-PMP is enabled in the router settings.';
      return cb(null, report);
    }

    chosen.session.getExternalIp(function(err, res) {
      if (err) {
        report.reachable  = null;
        report.reason     = 'UNKNOWN';
        report.detail     = 'The gateway would not report its external address: ' + err.message;
        report.suggestion = 'Mappings may still work; try one and test it from outside.';
        return cb(null, report);
      }

      report.externalIp = res ? res.externalIp : null;
      var kind = wire.classify_external_address(report.externalIp);

      // Everything below is a conclusion drawn from the address alone. Where
      // STUN is available it either confirms it or overturns it, so the
      // verification runs first and the wording follows from what it found.
      reachability.verify(report.externalIp, options, function(_, seen) {
        report.method        = seen.method;
        report.publicAddress = seen.publicAddress;
        report.natType       = seen.natType;
        if (seen.natDetail) report.natDetail = seen.natDetail;

        conclude(report, kind, seen, cb);
      });
    });
  }


  function conclude(report, kind, seen, cb) {
    // A gateway can hold a public address and still not be the one the world
    // sees us through — an upstream device may be translating as well, and
    // only the comparison catches that
    if (seen.agrees === false) {
      report.reachable = false;
      report.reason    = 'UPSTREAM_NAT';
      report.detail    = 'The gateway reports ' + report.externalIp + ', but the ' +
                         'internet sees this host as ' + seen.publicAddress + '. ' +
                         'Something upstream is translating as well, so a mapping ' +
                         'made here is not reachable from outside.';
      report.suggestion = seen.advice ||
                          'Map on the upstream device too, or use a relay.';
      return cb(null, report);
    }

      if (kind === 'public') {
        report.reachable = true;
        report.reason    = 'OK';
        report.detail    = seen.method === 'verified'
          ? 'The gateway holds a globally routable address, confirmed against ' +
            'what the internet sees.'
          : 'The gateway holds a globally routable address.';
        return cb(null, report);
      }

      if (kind === 'cgnat') {
        report.reachable = false;
        report.reason    = 'CGNAT';
        report.detail    = 'The gateway reports ' + report.externalIp + ', which is in the ' +
                           'RFC 6598 shared range used by carrier-grade NAT. The ISP is ' +
                           'translating as well, so inbound connections never reach this router.';
        report.suggestion = 'Port forwarding cannot work behind CGNAT. Ask the ISP for a ' +
                            'public IPv4 address, use IPv6, or use a relay or tunnel.' +
                            (seen.advice ? ' ' + seen.advice : '');
        // A ready-made error, for a caller that would rather throw than branch
        // on a string. Attached rather than returned, because a diagnosis
        // succeeding is not the same as the network being usable.
        report.error = new CGNATError(report.detail, report.externalIp);
        return cb(null, report);
      }

      if (kind === 'private') {
        report.reachable = false;
        report.reason    = 'DOUBLE_NAT';
        report.detail    = 'The gateway reports ' + report.externalIp + ' as its external ' +
                           'address, which is a private RFC 1918 address. This router is ' +
                           'itself behind another NAT, so a mapping made here is only ' +
                           'reachable from that upstream network, not from the internet.';
        report.suggestion = 'Put the upstream device in bridge mode, or add a matching ' +
                            'forward on it to ' + report.externalIp + '.' +
                            (seen.advice ? ' ' + seen.advice : '');
        // Deliberately not a CGNATError: an upstream NAT under your own control
        // can be fixed by configuring it, which carrier-grade NAT cannot, and
        // conflating the two would send people to their ISP for no reason.
        return cb(null, report);
      }

      report.reachable  = false;
      report.reason     = kind.toUpperCase();
      report.detail     = 'The gateway reports ' + report.externalIp +
                          ', which is not a usable external address (' + kind + ').';
      report.suggestion = 'The router probably has no upstream connection yet.';
      cb(null, report);
  }


  /** Whether a verified diagnosis is possible on this install. */
  self.diagnostics = function(cb) { return reachability.available(cb); };


  function getRouterMappings(cb) {
    if (!require_ready(cb)) return;
    // Neither PCP nor NAT-PMP can enumerate the gateway's table; only IGD
    // exposes an action for it. Prefer the IGD:2 bulk action when it exists —
    // one call instead of one per entry.
    if (!upnp || upnp.state !== 'ready') return cb(null, null);

    var device = upnp.getDevice();
    if (device && device.igdVersion >= 2) {
      return upnp.getListOfPortMappings({ protocol: 'tcp' }, function(err, list) {
        if (!err) return cb(null, list);
        upnp.getRouterMappings(cb);      // some IGD:2 gateways refuse it anyway
      });
    }
    upnp.getRouterMappings(cb);
  }


  /* ================= Persistence and verification ================= */

  /**
   * Serialise the mappings this Mapper holds.
   *
   * The point is not to recreate them on the next run — a mapping outlives the
   * process anyway, until its lease expires — but to *adopt* them. A program
   * that restarts within the lease can pick up the renewal schedule where it
   * left off instead of asking the gateway for ports it already has, which on
   * a gateway with a small table is the difference between continuing and
   * being refused.
   *
   * The PCP nonce is included because it is what proves ownership: without it
   * a renewal is a new mapping, and the gateway may hand back a different
   * port.
   */
  function exportMappings() {
    return {
      version:    1,
      savedAt:    new Date().toISOString(),
      gateway:    gateway,
      localIp:    iface.address,
      protocol:   chosen ? chosen.protocol : null,
      externalIp: chosen ? chosen.externalIp : null,
      mappings:   self.getMappings().map(function(m) {
        return {
          protocol:     m.protocol,
          internalPort: m.internalPort,
          externalPort: m.externalPort,
          externalIp:   m.externalIp,
          lifetime:     m.lifetime,
          description:  m.description || null,
          nonceHex:     m.nonceHex || null,
          expiresAt:    m.expiresAt ? m.expiresAt.toISOString() : null
        };
      })
    };
  }


  /**
   * Take back mappings saved by an earlier run.
   *
   * Every entry is checked against the gateway before it is adopted, because
   * the file says what was true when it was written and nothing more: the
   * lease may have expired, the gateway may have restarted, the address may
   * have changed, or another host may hold the port now. An entry that cannot
   * be confirmed is reported rather than assumed.
   *
   * cb(err, { adopted, expired, vanished, stolen, foreign })
   */
  function importMappings(saved, cb) {
    cb = cb || function() {};
    if (!require_ready(cb)) return;
    if (!saved || !Array.isArray(saved.mappings)) {
      return cb(new PortMapValidationError('nothing to import', 'mappings'));
    }

    var report = { adopted: [], expired: [], vanished: [], stolen: [], foreign: [] };
    var now = Date.now();

    // A file written on a different network describes a different gateway's
    // table, and adopting it would mean claiming ports on the wrong device
    if (saved.gateway && gateway && saved.gateway !== gateway) {
      report.foreign = saved.mappings.slice();
      return cb(null, report);
    }

    var entries = saved.mappings.filter(function(m) {
      if (m.expiresAt && Date.parse(m.expiresAt) <= now) { report.expired.push(m); return false; }
      return true;
    });

    function step(i) {
      if (i >= entries.length) return cb(null, report);
      var m = entries[i];

      verify_one(m, function(_, res) {
        if (res && res.stolen) report.stolen.push(m);
        else if (res && res.present === false) report.vanished.push(m);
        else if (res && res.present) {
          adopt(m);
          report.adopted.push(m);
        } else {
          // The gateway would not say; treat it as gone rather than adopt
          // something that may not be there
          report.vanished.push(m);
        }
        setImmediate(function() { step(i + 1); });
      });
    }

    step(0);
  }


  /**
   * Resume renewing a mapping the gateway already holds, without asking for
   * it again.
   */
  function adopt(m) {
    chosen.session.map({
      protocol:     m.protocol,
      internalPort: m.internalPort,
      externalPort: m.externalPort,
      lifetime:     m.lifetime,
      description:  m.description
    }, function(err, mapping) {
      if (err) return;
      index[m.protocol + ':' + m.internalPort] = mapping.externalPort;
      ev.emit('adopted', mapping);
    });
  }


  function verify_one(m, cb) {
    if (!chosen || !chosen.session.verify) return cb(null, { present: null });
    chosen.session.verify({
      protocol:     m.protocol,
      internalPort: m.internalPort,
      externalPort: m.externalPort,
      internalIp:   iface.address
    }, cb);
  }


  /**
   * Check every mapping against the gateway.
   *
   * A gateway can drop a mapping without saying so — reclaimed for being idle,
   * cleared on a firmware quirk, evicted for a client with a better claim —
   * and a renewal that reports success does not rule any of that out. This
   * asks, which on UPnP is a genuine read and on PCP is a reassertion.
   */
  function verifyMappings(cb) {
    cb = cb || function() {};
    if (!require_ready(cb)) return;

    var mappings = self.getMappings();
    var report = { checked: 0, present: [], vanished: [], stolen: [], unknown: [] };

    function step(i) {
      if (i >= mappings.length) {
        ev.emit('verified', report);
        return cb(null, report);
      }
      var m = mappings[i];
      report.checked++;

      verify_one(m, function(_, res) {
        if (res && res.stolen) {
          report.stolen.push(m);
          ev.emit('mapping-stolen', m, res.reason);
        } else if (res && res.present === false) {
          report.vanished.push(m);
          ev.emit('mapping-vanished', m, res.reason);
        } else if (res && res.present) {
          report.present.push(m);
        } else {
          report.unknown.push(m);
        }
        setImmediate(function() { step(i + 1); });
      });
    }

    step(0);
  }


  /**
   * Check periodically, and put back whatever has gone missing.
   *
   * Off by default: it costs a round trip per mapping per interval, and on a
   * gateway that behaves there is nothing to find. It earns its keep on the
   * ones that quietly reclaim.
   */
  var watchdog_timer = null;

  function startWatchdog(opts) {
    opts = opts || {};
    var interval = opts.interval || 300000;      // five minutes

    stopWatchdog();

    watchdog_timer = safe_timeout(function again() {
      if (destroyed) return;
      verifyMappings(function(_, report) {
        if (report && opts.restore !== false) {
          report.vanished.forEach(function(m) {
            map({ protocol: m.protocol, internalPort: m.internalPort,
                  externalPort: m.externalPort }, function(err, restored) {
              if (!err) ev.emit('remapped', restored, m.externalPort);
            });
          });
        }
        if (!destroyed) watchdog_timer = safe_timeout(again, interval);
      });
    }, interval);

    return { stop: stopWatchdog };
  }


  function stopWatchdog() {
    if (watchdog_timer) { clear_safe_timeout(watchdog_timer); watchdog_timer = null; }
  }


  /* ========================= Event subscription ========================= */

  var event_server = null;
  var event_url = null;

  /**
   * Subscribe to the gateway's evented state, opening a listener to receive
   * the notifications.
   *
   * The gateway delivers events by POSTing to a URL we give it, so a
   * subscriber has to be reachable — which means running an HTTP server. Every
   * UPnP control point does this; there is no way to subscribe without one.
   * The port is ephemeral and the address is the interface the gateway will
   * reach us on, since that is the only one it can post to.
   *
   * This is what gives UPnP an equivalent of the NAT-PMP announcement: a
   * changed ExternalIPAddress arrives here rather than being discovered on the
   * next renewal, or not at all.
   */
  function subscribe(opts, cb) {
    if (typeof opts === 'function') { cb = opts; opts = {}; }
    opts = opts || {};
    cb = cb || function() {};

    if (!upnp) return cb(new PortMapStateError('UPnP is not enabled on this Mapper', 'new'));
    if (!chosen) return cb(new PortMapStateError('Not started — call start() first', 'new'));

    function go() {
      upnp.subscribe({ callbackUrl: event_url, timeout: opts.timeout }, function(err, sub) {
        if (err) return cb(err);

        // The subscription lapses, and a lapsed one stops delivering without
        // saying so, so it is renewed at two thirds of the granted lifetime
        if (sub.timeout) {
          sub._timer = safe_timeout(function renew() {
            upnp.renewSubscription(sub.sid, { timeout: opts.timeout }, function(e, r) {
              if (e) { ev.emit('warning', 'Subscription renewal failed: ' + e.message); return; }
              if (r && r.timeout) sub._timer = safe_timeout(renew, r.timeout * 1000 * 2 / 3);
            });
          }, sub.timeout * 1000 * 2 / 3);
        }

        cb(null, sub);
      });
    }

    if (event_server) return go();

    event_server = http.createServer(function(req, res) {
      var chunks = [];
      req.on('data', function(c) { chunks.push(c); });
      req.on('end', function() {
        // A NOTIFY is answered before it is processed: the gateway is waiting,
        // and some stop delivering to a subscriber that answers slowly
        res.writeHead(200, { 'Content-Length': 0 }).end();
        if (req.method !== 'NOTIFY') return;
        upnp.handle_notify(req.headers, new Uint8Array(Buffer.concat(chunks)));
      });
    });

    event_server.on('error', function(err) {
      ev.emit('warning', 'Event listener error: ' + err.message);
    });

    event_server.listen(opts.port || 0, iface.address, function() {
      var port = event_server.address().port;
      event_url = 'http://' +
        (family === 'ipv6' ? '[' + iface.address + ']' : iface.address) +
        ':' + port + '/notify';
      dbg('transport', 'listening for events on', event_url);
      go();
    });
  }


  function unsubscribe(sid, cb) {
    cb = cb || function() {};
    if (!upnp) return cb(null);
    upnp.unsubscribe(sid, cb);
  }


  /**
   * IPv6 pinholes. These do not go through negotiation: only UPnP has an
   * equivalent, and it is a different service on the same device. PCP does
   * support IPv6 firewall control, but through the same MAP opcode rather
   * than a separate action, so a caller that wants v6 asks for it explicitly.
   */
  function addPinhole(opts, cb) {
    cb = cb || function() {};
    if (!upnp) return cb(new PortMapStateError('UPnP is not enabled on this Mapper', 'new'));
    upnp.addPinhole(opts, cb);
  }

  function deletePinhole(id, cb) {
    cb = cb || function() {};
    if (!upnp) return cb(new PortMapStateError('UPnP is not enabled on this Mapper', 'new'));
    upnp.deletePinhole(id, cb);
  }

  function getFirewallStatus(cb) {
    if (!upnp) return cb(new PortMapStateError('UPnP is not enabled on this Mapper', 'new'));
    upnp.getFirewallStatus(cb);
  }


  /** Delete mappings this library left behind in earlier runs. UPnP only. */
  function cleanup(opts, cb) {
    if (typeof opts === 'function') { cb = opts; opts = {}; }
    cb = cb || function() {};
    if (!upnp || upnp.state !== 'ready') return cb(null, []);
    upnp.cleanup(opts, cb);
  }


  /* ================ Accessors ================ */

  self.start = start;
  self.map = map;
  self.unmap = unmap;
  self.getExternalIp = getExternalIp;
  self.getRouterMappings = getRouterMappings;
  self.diagnose = diagnose;
  self.cleanup = cleanup;
  self.addPinhole = addPinhole;
  self.deletePinhole = deletePinhole;
  self.updatePinhole = function(id, lease, cb) {
    if (!upnp) return (cb || function() {})(new PortMapStateError('UPnP is not enabled', 'new'));
    upnp.updatePinhole(id, lease, cb);
  };
  self.checkPinholeWorking = function(id, cb) {
    if (!upnp) return cb(new PortMapStateError('UPnP is not enabled', 'new'));
    upnp.checkPinholeWorking(id, cb);
  };
  self.getPinholes = function() { return upnp ? upnp.getPinholes() : []; };
  self.getFirewallStatus = getFirewallStatus;
  self.exportMappings = exportMappings;
  self.importMappings = importMappings;
  self.verifyMappings = verifyMappings;
  self.startWatchdog = startWatchdog;
  self.stopWatchdog = stopWatchdog;
  self.subscribe = subscribe;
  self.unsubscribe = unsubscribe;
  self.getSubscriptions = function() { return upnp ? upnp.getSubscriptions() : []; };

  self.getMappings = function() {
    return chosen && chosen.session ? chosen.session.getMappings() : [];
  };

  /** Abandon every request still queued or in flight, without shutting down. */
  self.cancelAll = function(reason) {
    var n = 0;
    if (pmp && pmp.cancelAll) n += pmp.cancelAll(reason);
    return n;
  };

  /**
   * Every IGD device discovery heard from, not just the one in use. Empty
   * unless UPnP was one of the protocols tried.
   */
  self.getCandidates = function() {
    return upnp && upnp.getCandidates ? upnp.getCandidates() : [];
  };

  /** Every address this host has, ranked, with the reason for the ordering. */
  self.getInterfaces = function() {
    return interfaces.candidates({ family: family, gateway: gateway });
  };

  /**
   * Everything the UPnP engine can answer that this layer had no reason to
   * wrap. They were reachable only through `mapper.upnp`, which meant reading
   * the source to find out they existed.
   *
   * Each returns a clear error rather than undefined when the gateway in use
   * is not a UPnP one, because "this gateway cannot tell you" is a different
   * answer from "the call went wrong".
   */
  function upnp_only(name) {
    return function() {
      var args = Array.prototype.slice.call(arguments);
      var cb = typeof args[args.length - 1] === 'function' ? args.pop() : function() {};
      if (!upnp || !chosen || chosen.protocol !== 'upnp') {
        return cb(new PortMapStateError(
          name + '() needs a UPnP-IGD gateway; this one is speaking ' +
          (chosen ? chosen.protocol : 'nothing yet'), chosen ? 'ready' : 'new'));
      }
      upnp[name].apply(upnp, args.concat([cb]));
    };
  }

  // Gateway information
  self.getStatus            = upnp_only('getStatus');
  self.getConnectionType    = upnp_only('getConnectionType');
  self.getMappingCount      = upnp_only('getMappingCount');
  self.getLinkProperties    = upnp_only('getLinkProperties');
  self.getTrafficCounters   = upnp_only('getTrafficCounters');

  // Service description
  self.loadServiceDescription = upnp_only('loadServiceDescription');
  self.supportsAction         = upnp_only('supportsAction');

  // Bulk table operations (IGD:2)
  self.getListOfPortMappings  = upnp_only('getListOfPortMappings');
  self.deletePortMappingRange = upnp_only('deletePortMappingRange');

  // Pinhole detail
  self.getPinholePackets        = upnp_only('getPinholePackets');
  self.getOutboundPinholeTimeout = upnp_only('getOutboundPinholeTimeout');

  self.renewSubscription = function(sid, opts, cb) {
    if (!upnp) return (cb || opts)(new PortMapStateError('UPnP is not enabled', 'new'));
    upnp.renewSubscription(sid, opts, cb);
  };

  /** What this gateway is known to do differently. Empty for a PMP gateway. */
  self.getQuirks = function() { return upnp && upnp.getQuirks ? upnp.getQuirks() : []; };
  self.getQuirkEffects = function() {
    return upnp && upnp.getQuirkEffects ? upnp.getQuirkEffects() : {};
  };

  /**
   * Call any SOAP action on the connection service.
   *
   * An escape hatch, and a deliberate one: IGD is an extensible service and
   * vendors add actions to it, so a library that only exposes what it knows
   * about would force a fork for anything it had not anticipated. Arguments go
   * out in the order given, which some gateways care about.
   */
  self.call = function(action, args, cb) {
    if (typeof args === 'function') { cb = args; args = {}; }
    cb = cb || function() {};
    if (!upnp || !chosen || chosen.protocol !== 'upnp') {
      return cb(new PortMapStateError(
        'call() needs a UPnP-IGD gateway; this one is speaking ' +
        (chosen ? chosen.protocol : 'nothing yet'), chosen ? 'ready' : 'new'));
    }
    upnp.call(action, args, cb);
  };

  self.getProtocol = function() { return chosen ? chosen.protocol : null; };
  self.getDevice   = function() { return upnp ? upnp.getDevice() : null; };
  self.getResults  = function() { return chosen ? chosen.results : null; };

  self.getStats = function() {
    return { pmp: pmp ? pmp.getStats() : null, upnp: upnp ? upnp.getStats() : null };
  };

  self.getConfig = function() {
    return {
      family:    family,
      gateway:   gateway,
      interface: iface.name,
      localIp:   iface.address,
      netmask:   iface.netmask,
      protocols: wanted.slice(),
      protocol:  chosen ? chosen.protocol : null
    };
  };

  /**
   * Delete every mapping this Mapper created, then shut down. Prefer this to
   * stop() when the process is ending cleanly: stop() closes the sockets
   * immediately, which leaves the mappings on the gateway until their lease
   * expires.
   */
  function close(cb) {
    cb = cb || function() {};
    if (destroyed || !chosen || !chosen.session) return self.stop(cb);

    var mappings = self.getMappings();
    var pending = mappings.length;
    if (!pending) return self.stop(cb);

    var timed_out = false;
    var guard = setTimeout(function() { timed_out = true; self.stop(cb); }, options.closeTimeout || 3000);

    mappings.forEach(function(m) {
      unmap({ protocol: m.protocol, internalPort: m.internalPort }, function() {
        if (timed_out) return;
        if (--pending > 0) return;
        clearTimeout(guard);
        self.stop(cb);
      });
    });
  }


  self.close = close;

  self.stop = function(cb) {
    if (destroyed) { if (cb) setImmediate(cb); return; }
    destroyed = true;
    remove_exit_hook();

    if (pmp) pmp.destroy();
    if (upnp) upnp.destroy();

    // Cancel every subscription before the listener goes away, or the gateway
    // keeps posting to a port that no longer answers
    if (upnp) {
      upnp.getSubscriptions().forEach(function(sub) {
        if (sub._timer) clear_safe_timeout(sub._timer);
        upnp.unsubscribe(sub.sid, function() {});
      });
    }
    stopWatchdog();
    if (event_server) { try { event_server.close(); } catch (e) {} event_server = null; }

    [announce_socket, ssdp_socket, pmp_socket].forEach(function(s) {
      if (s) { try { s.close(); } catch (e) {} }
    });
    announce_socket = ssdp_socket = pmp_socket = null;
    started = false;

    if (cb) setImmediate(cb);
  };

  self.destroy = self.stop;

  Object.defineProperty(self, 'family', { get: function() { return family; }, enumerable: true });

  self.on   = function(name, fn) { ev.on(name, fn); };
  self.off  = function(name, fn) { ev.off(name, fn); };
  self.once = function(name, fn) { ev.once(name, fn); };

  Object.defineProperty(self, 'interface', { get: function() { return iface; }, enumerable: true });
  Object.defineProperty(self, 'gateway',   { get: function() { return gateway; }, enumerable: true });

  return self;
}


function createMapper(options) {
  return new Mapper(options);
}


export {
  Mapper, createMapper, detect_gateway, detect_gateway6, detect_interface,
  make_http_client
};
export default Mapper;
