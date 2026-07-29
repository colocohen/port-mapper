/**
 * interfaces.js — choosing the right interface, and checking a local port.
 *
 * Taking the first non-internal address is wrong on any machine that has more
 * than one, and most developer machines do. A host running Docker has a
 * `docker0` bridge with a private address on it; a VPN adds `tun0` or `utun3`;
 * a hypervisor adds `vmnet` or `vboxnet`. All of them are non-internal, all of
 * them look plausible, and a mapping made for one of them points the gateway
 * at an address no packet will ever reach.
 *
 * The default route settles it. The address that shares a subnet with the
 * default gateway is the one this host reaches the internet through, and that
 * is the only one worth mapping. Where the route is unknown, the interface
 * name is the fallback signal — virtual interfaces are named recognisably on
 * every platform, and it is better to guess by name than to take whatever came
 * first out of an unordered object.
 */

import os from 'node:os';
import net from 'node:net';
import dgram from 'node:dgram';
import { dbg } from './debug.js';
import * as wire from './wire.js';


/**
 * Interfaces created by container runtimes, VPNs and hypervisors. Matching by
 * name is a heuristic, but a well-founded one: these names are conventions
 * their software has used for years, and being wrong only costs a demotion in
 * the ordering, never an exclusion.
 */
const VIRTUAL_PATTERNS = [
  /^docker/i, /^br-[0-9a-f]{12}/i, /^veth/i,          // Docker and friends
  /^lxc/i, /^lxd/i, /^cni/i, /^flannel/i, /^cali/i,   // other container runtimes
  /^tun\d/i, /^tap\d/i, /^utun/i, /^ppp/i,            // VPN tunnels
  /^wg\d/i, /^zt/i, /^tailscale/i, /^nordlynx/i,      // WireGuard, ZeroTier, etc
  /^vmnet/i, /^vboxnet/i, /^virbr/i, /^vnet/i,        // hypervisors
  /^Hyper-V/i, /^vEthernet/i,                         // Windows
  /^awdl/i, /^llw/i, /^bridge\d/i                     // macOS
];


function is_virtual(name) {
  for (var i = 0; i < VIRTUAL_PATTERNS.length; i++) {
    if (VIRTUAL_PATTERNS[i].test(name)) return true;
  }
  return false;
}


/** Turn a dotted netmask into a prefix length. */
function mask_to_prefix(netmask) {
  if (!netmask) return null;
  var parts = String(netmask).split('.');
  if (parts.length !== 4) return null;
  var bits = 0;
  for (var i = 0; i < 4; i++) {
    var n = parseInt(parts[i], 10);
    for (var b = 7; b >= 0; b--) if (n & (1 << b)) bits++;
  }
  return bits;
}


/** Are two IPv4 addresses on the same subnet? */
function same_subnet(a, b, netmask) {
  if (!a || !b || !netmask) return false;
  try {
    var pa = a.split('.').map(Number), pb = b.split('.').map(Number),
        pm = netmask.split('.').map(Number);
    for (var i = 0; i < 4; i++) {
      if ((pa[i] & pm[i]) !== (pb[i] & pm[i])) return false;
    }
    return true;
  } catch (e) { return false; }
}


/**
 * List every candidate address for a family, ranked best first.
 *
 * The ranking, in order of weight:
 *   1. shares a subnet with the default gateway — decisive when known
 *   2. is not a virtual interface
 *   3. for IPv6, is globally routable rather than unique-local or link-local
 *
 * Each entry carries `reason`, so a caller can report why one was chosen and
 * a bug report says which interfaces were on the machine.
 */
function candidates(options) {
  options = options || {};
  var family = options.family === 'ipv6' ? 'ipv6' : 'ipv4';
  var gateway = options.gateway || null;

  var ifaces = os.networkInterfaces();
  var out = [];

  for (var name in ifaces) {
    var addrs = ifaces[name] || [];
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
        mac:      a.mac,
        prefix:   is4 ? mask_to_prefix(a.netmask) : null,
        virtual:  is_virtual(name),
        onDefaultRoute: false,
        score:    0,
        reason:   []
      };

      if (family === 'ipv4' && gateway && same_subnet(a.address, gateway, a.netmask)) {
        entry.onDefaultRoute = true;
        entry.score += 100;
        entry.reason.push('shares a subnet with the default gateway');
      }

      if (entry.virtual) {
        entry.score -= 50;
        entry.reason.push('looks like a virtual interface');
      } else {
        entry.score += 10;
      }

      if (family === 'ipv6') {
        var kind = wire.classify_ipv6_address(a.address);
        if (kind === 'public') { entry.score += 30; entry.reason.push('globally routable'); }
        else if (kind === 'ula') { entry.score += 5; entry.reason.push('unique local'); }
        else if (kind === 'linklocal') {
          entry.score -= 20;
          entry.reason.push('link-local, so it can never be reached from elsewhere');
        }
      }

      out.push(entry);
    }
  }

  out.sort(function(a, b) { return b.score - a.score; });
  return out;
}


/**
 * Pick one. A named address always wins; otherwise the ranking decides.
 */
function select(options) {
  options = options || {};

  var list = candidates(options);

  if (options.preferred && options.preferred !== 'auto') {
    for (var i = 0; i < list.length; i++) {
      if (list[i].address === options.preferred || list[i].name === options.preferred) {
        return list[i];
      }
    }
    return null;
  }

  if (!list.length) return null;

  var chosen = list[0];
  if (chosen.virtual && list.length > 1) {
    dbg('transport', 'best interface is virtual (' + chosen.name + ') — no better one exists');
  }
  if (!chosen.onDefaultRoute && options.gateway) {
    dbg('transport', 'no interface shares a subnet with', options.gateway);
  }
  return chosen;
}


/* ===================== Is anything listening there? ===================== */

/**
 * Check whether a local port has a service on it, by trying to bind it.
 *
 * Binding is used rather than connecting because it answers the right
 * question. A connection test says whether something accepts connections from
 * this host on this address, which is not the same as whether a service is
 * bound and reachable at the address the gateway will forward to. If the bind
 * succeeds, nothing is listening; the port is then released immediately.
 *
 * This matters because mapping an empty port is the most common mistake in
 * this whole area, and every implementation — this one included, until now —
 * reports it as a complete success. The gateway did exactly what it was asked;
 * there is simply nothing at the other end.
 *
 * The answer is advisory. A service that binds one specific address may be
 * invisible to a wildcard bind test, so a false "nothing there" is possible
 * and this should warn rather than refuse.
 */
function port_in_use(options, cb) {
  options = options || {};
  var port = options.port;
  var protocol = (options.protocol || 'tcp').toLowerCase();
  var address = options.address || '0.0.0.0';

  if (!port) return cb(null, { inUse: null, reason: 'no port given' });

  if (protocol === 'udp') {
    var sock = dgram.createSocket({
      type: address.indexOf(':') !== -1 ? 'udp6' : 'udp4',
      // Without this the test would report every UDP port as free, since the
      // option is what lets two sockets share one
      reuseAddr: false
    });

    var udp_done = false;
    function finish_udp(result) {
      if (udp_done) return;
      udp_done = true;
      try { sock.close(); } catch (e) {}
      cb(null, result);
    }

    sock.on('error', function(err) {
      if (udp_done) return;
      udp_done = true;
      cb(null, {
        inUse:  err.code === 'EADDRINUSE',
        reason: err.code === 'EADDRINUSE' ? 'a socket already holds it' : err.message
      });
    });

    try {
      sock.bind(port, address, function() { finish_udp({ inUse: false }); });
    } catch (e) {
      cb(null, { inUse: null, reason: e.message });
    }
    return;
  }

  var server = net.createServer();
  var tcp_done = false;

  server.on('error', function(err) {
    if (tcp_done) return;
    tcp_done = true;
    cb(null, {
      inUse:  err.code === 'EADDRINUSE',
      reason: err.code === 'EADDRINUSE' ? 'a socket is listening on it' : err.message
    });
  });

  server.listen(port, address, function() {
    if (tcp_done) return;
    tcp_done = true;
    server.close(function() { cb(null, { inUse: false }); });
  });
}


export {
  candidates, select, is_virtual, same_subnet, mask_to_prefix, port_in_use,
  VIRTUAL_PATTERNS
};
