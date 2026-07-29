/**
 * enforce/relay.js — userspace forwarding.
 *
 * The only enforcement adapter that is pure JavaScript. Instead of asking the
 * kernel to rewrite packet destinations, this process listens on the external
 * port itself and copies bytes between two connections.
 *
 * Why it exists: the kernel cannot be reached from Node without a native
 * module. netfilter is configured over AF_NETLINK sockets, which Node's `net`
 * and `dgram` do not expose, so the only alternatives are a compiled binding
 * or shelling out to `nft` / `iptables`. Both need root and neither runs on
 * Windows. A relay needs no privileges above port 1024 and runs anywhere,
 * which makes it the right default and the only option in a container.
 *
 * What it costs, and callers are told through `capabilities`:
 *
 *   The source address is lost. The internal host sees the connection coming
 *   from this gateway, not from the real client. Anything on the inside that
 *   logs, rate-limits or filters by client address is working with the wrong
 *   value. There is no way around this at the NAT layer — PROXY protocol or
 *   X-Forwarded-For work only when the inner service understands them.
 *
 *   Every packet crosses the kernel/userspace boundary twice in each
 *   direction, where a DNAT rule would have copied nothing.
 *
 *   The external port must actually be free on this machine, because the
 *   relay binds it. A kernel rule has no such constraint.
 *
 * The source address can be handed on at a higher layer, though. With
 * `proxyProtocol: true` every TCP connection is prefixed with one line naming
 * the real client — the HAProxy PROXY protocol, understood by nginx, HAProxy,
 * Postgres and others. That does not restore the address at the IP layer, so
 * `preservesSourceIp` stays false, but it does carry the information, which is
 * what a log or a rate limiter actually needs. It is off by default because a
 * service that does not expect the prefix will read it as corrupt input.
 */

import net from 'node:net';
import dgram from 'node:dgram';
import { dbg } from '../debug.js';
import { PortMapNetworkError } from '../errors.js';


function relay(options) {
  options = options || {};

  var bind_address = options.bindAddress || null;   // null → dual-stack
  var proxy_protocol = options.proxyProtocol === true;
  var udp_idle_ms  = options.udpIdleTimeout || 60000;
  var sweep_ms     = options.udpSweepInterval || 10000;
  var max_udp_sessions = options.maxUdpSessions || 1024;

  var handles = Object.create(null);   // 'tcp:8080' → handle
  var seq = 0;
  var destroyed = false;


  function key_of(protocol, port) { return protocol + ':' + port; }


  function is_v6(address) {
    return typeof address === 'string' && address.indexOf(':') !== -1;
  }


  /**
   * Which socket family to use for the outbound leg. It follows the internal
   * address, not the inbound connection: a v6 client may perfectly well be
   * forwarded to a v4 service and the other way round.
   */
  function udp_type_for(address) { return is_v6(address) ? 'udp6' : 'udp4'; }


  /**
   * Listening address. With none configured, the v6 wildcard is tried first:
   * on every mainstream platform it accepts IPv4 connections as well, as
   * IPv4-mapped addresses, so one listener serves both families.
   *
   * Plenty of environments have no IPv6 at all, though — containers with it
   * disabled, older kernels, some hosts — and there the bind fails with
   * EAFNOSUPPORT or EADDRNOTAVAIL. That is a fact about the machine rather
   * than an error to report, so it is detected once and remembered.
   */
  var dual_stack = null;      // null = not yet known

  function listen_address() {
    if (bind_address !== null) return bind_address;
    return dual_stack === false ? '0.0.0.0' : '::';
  }

  function is_family_error(err) {
    return err && (err.code === 'EAFNOSUPPORT' || err.code === 'EADDRNOTAVAIL' ||
                   err.code === 'EINVAL');
  }


  /**
   * PROXY protocol v1 — one ASCII line before any payload, as HAProxy defined
   * it. The text form is used rather than the binary v2 because it is what the
   * widest set of servers accepts, and one short line per connection costs
   * nothing next to the copying the relay is already doing.
   *
   *   PROXY TCP4 203.0.113.7 192.168.1.42 54321 8080\r\n
   */
  function proxy_header(inbound, mapping) {
    var src = inbound.remoteAddress || '';
    var v6 = is_v6(src) && src.indexOf('::ffff:') !== 0;

    // Node reports an IPv4 peer on a dual-stack socket as ::ffff:a.b.c.d
    if (src.indexOf('::ffff:') === 0) src = src.slice(7);

    var dst = v6 ? (inbound.localAddress || '::1') : (mapping.internalIp || '127.0.0.1');
    if (dst.indexOf('::ffff:') === 0) dst = dst.slice(7);

    return 'PROXY ' + (v6 ? 'TCP6' : 'TCP4') + ' ' +
           src + ' ' + dst + ' ' +
           (inbound.remotePort || 0) + ' ' + mapping.externalPort + '\r\n';
  }


  /* ============================== TCP ============================== */

  function open_tcp(mapping, cb) {
    var server = net.createServer(function(inbound) {
      var outbound = net.connect(mapping.internalPort, mapping.internalIp);

      if (proxy_protocol) {
        // Written before the pipes are attached, not on 'connect'. Node
        // queues writes made before the socket is up and flushes them in
        // order, so writing here guarantees the header leads; deferring it to
        // the connect event would let piped payload queue ahead of it.
        try { outbound.write(proxy_header(inbound, mapping)); } catch (e) {}
      }

      // pipe() applies backpressure in both directions for free: if the
      // internal service reads slowly, reads from the outside are paused
      // rather than buffered without limit.
      inbound.pipe(outbound);
      outbound.pipe(inbound);

      function shutdown() {
        inbound.destroy();
        outbound.destroy();
      }
      inbound.on('error', shutdown);
      outbound.on('error', shutdown);
      inbound.on('close', function() { outbound.destroy(); });
      outbound.on('close', function() { inbound.destroy(); });
    });

    server.on('error', function(err) {
      // No IPv6 here — fall back to the v4 wildcard and remember
      if (bind_address === null && dual_stack === null && is_family_error(err)) {
        dual_stack = false;
        dbg('enforce', 'no IPv6 on this host, binding IPv4 only');
        try { server.close(); } catch (e) {}
        return open_tcp(mapping, cb);
      }

      cb(new PortMapNetworkError(
        'Could not bind tcp/' + mapping.externalPort + ': ' + err.message +
        (err.code === 'EACCES'
          ? ' — ports below 1024 need root, or CAP_NET_BIND_SERVICE'
          : ''), err));
    });

    server.listen(mapping.externalPort, listen_address(), function() {
      if (dual_stack === null) dual_stack = true;
      server.removeAllListeners('error');
      server.on('error', function(err) { dbg('enforce', 'tcp relay error:', err.message); });
      cb(null, server);
    });
  }


  /* ============================== UDP ============================== */

  /**
   * UDP has no connections, so the association has to be built here: one
   * outbound socket per remote peer, aged out after an idle period. This is
   * the same soft state a NAT keeps, only in userspace.
   */
  function open_udp(mapping, cb) {
    var family = udp_type_for(listen_address());
    var inbound = dgram.createSocket({ type: family, reuseAddr: true });
    var out_family = udp_type_for(mapping.internalIp);
    var sessions = new Map();
    var sweeper = null;

    inbound.on('message', function(msg, rinfo) {
      var peer = rinfo.address + ':' + rinfo.port;
      var session = sessions.get(peer);

      if (!session) {
        if (sessions.size >= max_udp_sessions) {
          dbg('enforce', 'udp session table full, dropping from', peer);
          return;
        }

        var sock = dgram.createSocket({ type: out_family });
        session = { sock: sock, lastSeen: Date.now() };

        sock.on('message', function(reply) {
          session.lastSeen = Date.now();
          inbound.send(reply, rinfo.port, rinfo.address);
        });
        sock.on('error', function() {
          try { sock.close(); } catch (e) {}
          sessions.delete(peer);
        });

        sessions.set(peer, session);
      }

      session.lastSeen = Date.now();
      session.sock.send(msg, mapping.internalPort, mapping.internalIp);
    });

    inbound.on('error', function(err) {
      if (bind_address === null && dual_stack === null && is_family_error(err)) {
        dual_stack = false;
        dbg('enforce', 'no IPv6 on this host, binding IPv4 only');
        clearInterval(sweeper);
        try { inbound.close(); } catch (e) {}
        return open_udp(mapping, cb);
      }
      cb(new PortMapNetworkError(
        'Could not bind udp/' + mapping.externalPort + ': ' + err.message, err));
    });

    sweeper = setInterval(function() {
      var now = Date.now();
      sessions.forEach(function(s, peer) {
        if (now - s.lastSeen <= udp_idle_ms) return;
        try { s.sock.close(); } catch (e) {}
        sessions.delete(peer);
      });
    }, sweep_ms);
    sweeper.unref();

    inbound.bind(mapping.externalPort, listen_address(), function() {
      if (dual_stack === null) dual_stack = true;
      inbound.removeAllListeners('error');
      inbound.on('error', function(err) { dbg('enforce', 'udp relay error:', err.message); });
      cb(null, {
        close: function() {
          clearInterval(sweeper);
          sessions.forEach(function(s) { try { s.sock.close(); } catch (e) {} });
          sessions.clear();
          try { inbound.close(); } catch (e) {}
        },
        get sessions() { return sessions.size; }
      });
    });
  }


  /* ============================== API ============================== */

  return {
    name: 'relay',

    capabilities: {
      platforms:         ['linux', 'darwin', 'win32', 'freebsd', 'openbsd', 'sunos', 'aix'],
      requiresRoot:      false,
      requiresPort:      true,
      preservesSourceIp: false,
      // The address is not restored at the IP layer, but it is handed on in
      // band when the PROXY header is enabled — a distinct, weaker guarantee
      // that some callers can use and others cannot
      forwardsSourceIp:  proxy_protocol,
      protocols:         ['tcp', 'udp'],
      families:          ['ipv4', 'ipv6'],
      hairpin:           true,
      throughput:        'medium',
      persistent:        false
    },

    check: function(cb) {
      cb(null, { available: !destroyed });
    },

    init: function(config, cb) {
      if (typeof config === 'function') { cb = config; config = {}; }
      if (config && config.bindAddress !== undefined) bind_address = config.bindAddress;
      cb(null);
    },

    add: function(mapping, cb) {
      if (destroyed) return cb(new PortMapNetworkError('relay destroyed'));

      var protocol = String(mapping.protocol).toLowerCase();
      var key = key_of(protocol, mapping.externalPort);

      if (handles[key]) {
        // Re-pointing an existing relay means closing and reopening: the
        // listening socket carries the destination in its closure.
        handles[key].close();
        delete handles[key];
      }

      function done(err, listener) {
        if (err) return cb(err);
        seq++;
        var handle = {
          id:           seq,
          protocol:     protocol,
          externalPort: mapping.externalPort,
          internalIp:   mapping.internalIp,
          internalPort: mapping.internalPort,
          close: function() {
            try { listener.close(); } catch (e) {}
          },
          listener: listener
        };
        handles[key] = handle;
        dbg('enforce', 'relay open', key, '→', mapping.internalIp + ':' + mapping.internalPort);
        cb(null, { handle: seq });
      }

      if (protocol === 'tcp') return open_tcp(mapping, done);
      if (protocol === 'udp') return open_udp(mapping, done);
      cb(new PortMapNetworkError('relay supports tcp and udp only, not ' + protocol));
    },

    remove: function(mapping, cb) {
      cb = cb || function() {};
      var key = key_of(String(mapping.protocol).toLowerCase(), mapping.externalPort);
      var handle = handles[key];
      // Removing what is not there is a success, so a caller reconciling
      // state does not have to check first
      if (!handle) return cb(null);
      handle.close();
      delete handles[key];
      dbg('enforce', 'relay closed', key);
      cb(null);
    },

    list: function(cb) {
      var out = Object.keys(handles).map(function(k) {
        var h = handles[k];
        return {
          protocol:     h.protocol,
          externalPort: h.externalPort,
          internalIp:   h.internalIp,
          internalPort: h.internalPort,
          handle:       h.id
        };
      });
      cb(null, out);
    },

    destroy: function(cb) {
      cb = cb || function() {};
      if (destroyed) return cb(null);
      destroyed = true;
      Object.keys(handles).forEach(function(k) { handles[k].close(); });
      handles = Object.create(null);
      cb(null);
    }
  };
}


/**
 * The adapter that enforces nothing.
 *
 * Not a placeholder: it is the right choice for a gateway that is acting as a
 * policy or monitoring layer in front of something else, and it is what makes
 * the whole protocol stack testable without root or a kernel.
 */
function noop() {
  var entries = Object.create(null);
  var seq = 0;

  return {
    name: 'noop',

    capabilities: {
      platforms:         ['linux', 'darwin', 'win32', 'freebsd', 'openbsd', 'sunos', 'aix'],
      requiresRoot:      false,
      requiresPort:      false,
      preservesSourceIp: false,
      forwardsSourceIp:  false,
      protocols:         ['tcp', 'udp'],
      families:          ['ipv4', 'ipv6'],
      hairpin:           false,
      throughput:        'none',
      persistent:        false
    },

    check: function(cb) { cb(null, { available: true }); },
    init: function(config, cb) { if (typeof config === 'function') cb = config; cb(null); },

    add: function(mapping, cb) {
      seq++;
      entries[mapping.protocol + ':' + mapping.externalPort] = {
        protocol:     mapping.protocol,
        externalPort: mapping.externalPort,
        internalIp:   mapping.internalIp,
        internalPort: mapping.internalPort,
        handle:       seq
      };
      cb(null, { handle: seq });
    },

    remove: function(mapping, cb) {
      delete entries[mapping.protocol + ':' + mapping.externalPort];
      cb(null);
    },

    list: function(cb) {
      cb(null, Object.keys(entries).map(function(k) { return entries[k]; }));
    },

    destroy: function(cb) {
      entries = Object.create(null);
      cb(null);
    }
  };
}


export { relay, noop };
export default relay;
