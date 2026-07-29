/**
 * upnp_server_session.js — UPnP-IGD gateway protocol engine.
 *
 * The other half of upnp_session.js. Transport-agnostic in the same shape as
 * the rest of the library, with the same asymmetry the client side has:
 * SSDP is datagrams, so it leaves as 'packet' (buf, dest) and arrives through
 * process_packet(); HTTP is request/response, so the transport calls
 * handle_http(req, cb) and sends back whatever it returns.
 *
 * Two things here are stricter than the specification, on purpose.
 *
 *   Nothing is granted by default. A 'port-request' listener must call
 *   control.allow(), or the policy must be set to 'allow-all' explicitly.
 *   RFC 6886 §9.2 explains why this matters more for IGD than for NAT-PMP:
 *   because UPnP IGD exposes every gateway setting rather than just port
 *   mapping, the scope for mischief is far larger, and a single piece of
 *   malicious web content can reach it through the browser of anyone on the
 *   LAN and make a persistent change without the user knowing.
 *
 *   NewInternalClient must match the packet source. IGD:1 lets a client name
 *   any internal address it likes, which is what allows one host to expose
 *   another — a neighbour's camera, a NAS, the gateway's own admin page.
 *   NAT-PMP forbids this structurally by having no such field at all
 *   (RFC 6886 §3.3); here it is enforced in code. Set
 *   allowThirdPartyMappings to lift it.
 *
 * References:
 *   UPnP Device Architecture 1.1 §1 (discovery), §2 (description), §3 (control)
 *   IGD:1 / IGD:2 WANIPConnection, WANIPv6FirewallControl:1
 */

import { EventEmitter } from 'node:events';
import * as ssdp from './ssdp.js';
import * as soap from './soap.js';
import { safe_timeout, clear_safe_timeout } from './timers.js';
import {
  make_control, when_control_done, wrap_control_listener, remove_control_listener
} from './control.js';
import { dbg } from './debug.js';
import { PortMapValidationError } from './errors.js';


function validate_options(opts) {
  if (!opts.udn) {
    throw new PortMapValidationError(
      'udn required — the unique device name a control point uses to tell this ' +
      'gateway apart from others, e.g. "uuid:...". It must stay the same across ' +
      'restarts or clients will treat the gateway as a new device.', 'udn');
  }
  if (!opts.location) {
    throw new PortMapValidationError(
      'location required — the absolute URL of the device description document, ' +
      'or a function (clientAddress) → url for a gateway with several LAN interfaces',
      'location');
  }
  if (opts.policy !== undefined && opts.policy !== 'deny-all' && opts.policy !== 'allow-all') {
    throw new PortMapValidationError('policy must be "deny-all" (default) or "allow-all"', 'policy');
  }
}


// Which search targets this device answers to
function search_targets(udn, version) {
  var out = [ssdp.ST.ROOT_DEVICE, udn,
             'urn:schemas-upnp-org:device:InternetGatewayDevice:' + version,
             'urn:schemas-upnp-org:device:WANDevice:' + version,
             'urn:schemas-upnp-org:device:WANConnectionDevice:' + version,
             'urn:schemas-upnp-org:service:WANIPConnection:' + version];
  return out;
}


const DYNAMIC_PORT_MIN = 49152;
const DYNAMIC_PORT_MAX = 65535;


function UPnPServerSession(options) {
  if (!(this instanceof UPnPServerSession)) return new UPnPServerSession(options);
  options = options || {};
  validate_options(options);

  var ev = new EventEmitter();
  ev.setMaxListeners(0);

  var version = options.igdVersion || 1;

  var context = {
    state: 'new',                 // new | listening | destroyed

    udn:        options.udn,
    location:   options.location,
    // A gateway with more than one LAN interface cannot advertise a single
    // address: the description URL has to be reachable by whoever asked, and
    // a client on the second network cannot reach the first network's address.
    // Given a function, it is called with the requester's address.
    locationFor: typeof options.location === 'function' ? options.location : null,
    igdVersion: version,
    externalIp: options.externalIp || null,

    friendlyName: options.friendlyName || 'Node Router',
    manufacturer: options.manufacturer || 'port-mapper',
    modelName:    options.modelName || 'Node IGD',
    server:       options.server || 'Node/UPnP/1.1 port-mapper/1.0',

    controlUrl:         options.controlUrl || '/ctl/IPConn',
    firewallControlUrl: options.firewallControlUrl || (version >= 2 ? '/ctl/IPv6FC' : null),

    connectionStatus: options.connectionStatus || 'Connected',
    // 'IP_Routed' is the normal NAT case; a device in 'IP_Bridged' mode is not
    // translating anything, so a mapping on it would have no effect
    connectionType:   options.connectionType || 'IP_Routed',
    uptimeStart:      Date.now(),

    wanAccessType:     options.wanAccessType || 'Ethernet',
    upstreamBitRate:   options.upstreamBitRate === undefined ? 1000000000 : options.upstreamBitRate,
    downstreamBitRate: options.downstreamBitRate === undefined ? 1000000000 : options.downstreamBitRate,
    linkStatus:        options.linkStatus || 'Up',
    // ui4 counters, so they wrap around 4 GB exactly as real gateways do
    counters: { bytesSent: 0, bytesReceived: 0, packetsSent: 0, packetsReceived: 0 },

    policy: options.policy || 'deny-all',
    // Lifting this is what makes a gateway able to expose one host at another
    // host's request
    allowThirdPartyMappings: options.allowThirdPartyMappings === true,

    maxLifetime:  options.maxLifetime === undefined ? 86400 : options.maxLifetime,
    maxMappings:  options.maxMappings === undefined ? 100 : options.maxMappings,
    maxPerClient: options.maxPerClient === undefined ? 20 : options.maxPerClient,
    controlTimeout: options.controlTimeout || 5000,

    // UDA 1.1 — clients cache advertisements for max-age seconds, so a
    // gateway must re-announce before that expires or it vanishes from view
    maxAge:   options.maxAge || 1800,
    bootId:   options.bootId === undefined ? Math.floor(Date.now() / 1000) : options.bootId,
    configId: options.configId === undefined ? 1 : options.configId,
    // Where this device listens for a unicast M-SEARCH, when that is not 1900.
    // Announced so a control point can aim one; a device that does not set it
    // is assumed to be on the standard port.
    searchPort: options.searchPort || null,

    targets: search_targets(options.udn, version),

    subscribers: Object.create(null),
    subscriberSeq: 0,

    mappings: Object.create(null),   // 'tcp:8080' → entry, keyed by external port
    pinholes: Object.create(null),   // uniqueId → entry
    nextPinholeId: 1,

    announceTimer: null,

    stats: {
      searchesSeen:      0,
      searchesAnswered:  0,
      advertisements:    0,
      soapRequests:      0,
      soapFaults:        0,
      descriptionsServed: 0,
      mappingsCreated:   0,
      mappingsRenewed:   0,
      mappingsDeleted:   0,
      requestsRejected:  0,
      thirdPartyBlocked: 0,
      pinholesCreated:   0
    }
  };


  function key_of(protocol, external_port) {
    return String(protocol).toLowerCase() + ':' + external_port;
  }


  /**
   * The description URL to advertise to one particular client.
   *
   * On a single-homed gateway this is the same string every time. On one with
   * several LAN interfaces it must not be: a control point fetches whatever
   * LOCATION it was given, and an address on a network it is not attached to
   * is simply unreachable — the device is discovered and then cannot be
   * described, which looks like a broken gateway rather than a wrong URL.
   */
  function location_for(address) {
    if (!context.locationFor) return context.location;
    var url = context.locationFor(address);
    return url || context.location;
  }


  function usn_for(target) {
    return target === context.udn ? context.udn : context.udn + '::' + target;
  }


  /* ============================== SSDP ============================== */

  function process_packet(buf, rinfo) {
    if (context.state === 'destroyed') return;

    var msg = ssdp.decode_ssdp(buf);
    if (!msg || msg.kind !== 'msearch') return;

    context.stats.searchesSeen++;

    var wanted = msg.headers['st'];
    if (!wanted) return;

    var matched = [];
    for (var i = 0; i < context.targets.length; i++) {
      if (wanted === ssdp.ST.ALL || ssdp.st_matches(wanted, context.targets[i])) {
        matched.push(context.targets[i]);
      }
    }
    if (!matched.length) return;

    // UDA 1.1 — the MX header is how long a device may wait before replying,
    // and it exists so that a network full of devices does not answer at the
    // same instant. Spreading the reply is the device's job, not the client's.
    var mx = parseInt(msg.headers['mx'], 10);
    if (isNaN(mx) || mx < 1) mx = 1;
    if (mx > 5) mx = 5;

    matched.forEach(function(target) {
      var delay = Math.floor(Math.random() * mx * 1000);
      safe_timeout(function() {
        if (context.state === 'destroyed') return;
        context.stats.searchesAnswered++;
        ev.emit('packet', ssdp.encode_msearch_response({
          location:   location_for(rinfo && rinfo.address),
          st:       target,
          usn:      usn_for(target),
          server:   context.server,
          maxAge:   context.maxAge,
          bootId:   context.bootId,
          configId: context.configId,
          // Where this device wants a unicast search aimed, when that is not
          // the standard port
          searchPort: context.searchPort
        }), rinfo);
      }, delay);
    });

    ev.emit('discovered', { from: rinfo.address, st: wanted, matched: matched.length });
  }


  function advertise(nts, extra) {
    extra = extra || {};
    for (var i = 0; i < context.targets.length; i++) {
      context.stats.advertisements++;
      ev.emit('packet', ssdp.encode_notify({
        nt:         context.targets[i],
        nts:        nts || 'ssdp:alive',
        usn:        usn_for(context.targets[i]),
        location:   context.location,
        server:     context.server,
        maxAge:     context.maxAge,
        bootId:     context.bootId,
        configId:   context.configId,
        searchPort: context.searchPort,
        nextBootId: extra.nextBootId
      }), { address: ssdp.MULTICAST_ADDR, port: ssdp.MULTICAST_PORT });
    }
  }


  /**
   * Announce that this device has changed without having gone away.
   *
   * UDA 1.1 defines ssdp:update for exactly the case where BOOTID must change
   * — a new network interface, a changed description — but the device is the
   * same one and its subscriptions are still valid. It carries the value
   * BOOTID is about to take, so a control point can follow the device across
   * the change instead of reading the new BOOTID as a restart and throwing
   * away everything it holds.
   *
   * The order matters: announce the next value first, then adopt it.
   */
  function update(options_in) {
    options_in = options_in || {};
    var next = options_in.bootId === undefined ? context.bootId + 1 : options_in.bootId;

    advertise('ssdp:update', { nextBootId: next });
    context.bootId = next;

    // A changed description is a changed CONFIGID, and a control point caches
    // descriptions against it
    if (options_in.configChanged) context.configId++;

    ev.emit('updated', { bootId: context.bootId, configId: context.configId });

    // The device is now on the new BOOTID, so it re-announces under it
    advertise('ssdp:alive');
    return { bootId: context.bootId, configId: context.configId };
  }


  function schedule_advertisements() {
    // Re-announce at half the cache lifetime, so an advertisement never
    // expires in a control point's cache before the next one arrives
    var interval = Math.max(60, Math.floor(context.maxAge / 2)) * 1000;
    context.announceTimer = safe_timeout(function again() {
      if (context.state === 'destroyed') return;
      advertise('ssdp:alive');
      context.announceTimer = safe_timeout(again, interval);
    }, interval);
  }


  /* ========================= Control object ========================= */

  /**
   * The control object and the waiting on asynchronous handlers live in
   * control.js, shared with the PCP/NAT-PMP engine and with the transport
   * above both. A policy written once has to mean the same thing whichever
   * protocol carried the request, which it cannot if each engine implements
   * the mechanism separately.
   */
  function control_for(proposed, ttl) { return make_control(proposed, ttl); }

  function await_control(control, cb) {
    when_control_done(control, context.controlTimeout, function(message) {
      ev.emit('warning', message);
    }, cb);
  }



  /* ========================= Mapping table ========================= */

  function is_free(protocol, port, client) {
    var existing = context.mappings[key_of(protocol, port)];
    return !existing || existing.internalIp === client;
  }


  function allocate_port(protocol, wanted, client) {
    if (wanted && is_free(protocol, wanted, client)) return wanted;
    var span = DYNAMIC_PORT_MAX - DYNAMIC_PORT_MIN + 1;
    var start = DYNAMIC_PORT_MIN + Math.floor(Math.random() * span);
    for (var i = 0; i < span; i++) {
      var port = DYNAMIC_PORT_MIN + ((start - DYNAMIC_PORT_MIN + i) % span);
      if (is_free(protocol, port, client)) return port;
    }
    return null;
  }


  // Same shape as the PMP side: a per-client tally, kept rather than counted
  var client_counts = Object.create(null);

  function count_for_client(client) { return client_counts[client] || 0; }

  function count_add(ip) { client_counts[ip] = (client_counts[ip] || 0) + 1; }
  function count_remove(ip) {
    var n = (client_counts[ip] || 1) - 1;
    if (n <= 0) delete client_counts[ip];
    else client_counts[ip] = n;
  }


  function arm_expiry(entry) {
    if (entry.timer) clear_safe_timeout(entry.timer);
    // A zero lease is permanent in IGD, so there is nothing to expire
    if (!entry.leaseDuration) return;
    entry.timer = safe_timeout(function() {
      remove(entry.protocol, entry.externalPort, 'expired');
    }, entry.leaseDuration * 1000);
  }


  function remove(protocol, external_port, reason) {
    var key = key_of(protocol, external_port);
    var entry = context.mappings[key];
    if (!entry) return null;
    if (entry.timer) clear_safe_timeout(entry.timer);
    delete context.mappings[key];
    count_remove(entry.internalIp);
    invalidate_order();
    context.stats.mappingsDeleted++;
    ev.emit(reason === 'expired' ? 'port-expired' : 'port-unmapped', public_mapping(entry), reason);
    return entry;
  }


  /**
   * The table in a stable order.
   *
   * GetGenericPortMappingEntry is addressed by index, so the order must not
   * shift between calls or a client walking the table will skip or repeat
   * entries. Sorting on every call would also make a full walk cost
   * O(n² log n), so the order is computed once and kept until the table
   * changes.
   */
  var sorted_cache = null;

  function sorted_mappings() {
    if (sorted_cache) return sorted_cache;
    sorted_cache = Object.keys(context.mappings).sort().map(function(k) {
      return context.mappings[k];
    });
    return sorted_cache;
  }

  function invalidate_order() { sorted_cache = null; }


  /* =========================== SOAP actions =========================== */

  function fault(cb, code, description) {
    context.stats.soapFaults++;
    cb(null, { statusCode: 500, headers: { 'Content-Type': 'text/xml; charset="utf-8"' },
               body: soap.encode_fault(code, description) });
  }


  function ok(cb, action, args, service_type) {
    cb(null, {
      statusCode: 200,
      headers: { 'Content-Type': 'text/xml; charset="utf-8"' },
      body: soap.encode_response(service_type || connection_type(), action, args || {})
    });
  }


  function connection_type() {
    return 'urn:schemas-upnp-org:service:WANIPConnection:' + context.igdVersion;
  }

  function firewall_type() {
    return 'urn:schemas-upnp-org:service:WANIPv6FirewallControl:1';
  }


  function do_add_mapping(args, remote, any_port, cb) {
    var protocol = String(args.NewProtocol || 'TCP').toLowerCase();
    if (protocol !== 'tcp' && protocol !== 'udp') {
      return fault(cb, 402, 'NewProtocol must be TCP or UDP');
    }

    var internal_ip = args.NewInternalClient || '';
    var internal_port = parseInt(args.NewInternalPort, 10);
    var external_port = parseInt(args.NewExternalPort, 10);
    var lease = parseInt(args.NewLeaseDuration, 10);
    if (isNaN(lease)) lease = 0;
    if (isNaN(internal_port) || internal_port < 1) return fault(cb, 402, 'NewInternalPort invalid');
    if (isNaN(external_port)) external_port = 0;

    // The check IGD:1 does not make. Without it, any program on the LAN can
    // publish any other device to the internet.
    if (!context.allowThirdPartyMappings && internal_ip && internal_ip !== remote.address) {
      context.stats.thirdPartyBlocked++;
      ev.emit('third-party-blocked', { from: remote.address, claimed: internal_ip });
      return fault(cb, 606, 'A mapping may only be created for the requesting host');
    }
    if (!internal_ip) internal_ip = remote.address;

    if (lease > context.maxLifetime) lease = context.maxLifetime;

    var existing = context.mappings[key_of(protocol, external_port)];
    if (existing && existing.internalIp !== internal_ip) {
      // The port is held by somebody else. AddAnyPortMapping is allowed to
      // move on and pick another; AddPortMapping must say so.
      if (!any_port) return fault(cb, 718);
    }

    if (!existing) {
      if (sorted_mappings().length >= context.maxMappings) {
        ev.emit('quota-exceeded', { scope: 'gateway', client: internal_ip });
        return fault(cb, context.igdVersion >= 2 ? 728 : 501);
      }
      if (count_for_client(internal_ip) >= context.maxPerClient) {
        ev.emit('quota-exceeded', { scope: 'client', client: internal_ip });
        return fault(cb, context.igdVersion >= 2 ? 728 : 501);
      }
    }

    var request = {
      via:          'upnp',
      protocol:     protocol,
      internalIp:   internal_ip,
      internalPort: internal_port,
      externalPort: external_port,
      leaseDuration: lease,
      description:  args.NewPortMappingDescription || '',
      remoteHost:   args.NewRemoteHost || '',
      remote:       remote
    };

    var control = control_for(external_port, context.maxLifetime);
    if (context.policy === 'allow-all') control.allow();

    ev.emit('port-request', request, control);

    await_control(control, function() {
      if (control._rejected || !control._allowed) {
        context.stats.requestsRejected++;
        ev.emit('port-rejected', request);
        return fault(cb, typeof control._rejected === 'number' ? control._rejected : 606);
      }

      var granted = any_port
        ? allocate_port(protocol, control.externalPort, internal_ip)
        : (is_free(protocol, control.externalPort, internal_ip) ? control.externalPort : null);

      if (granted === null) return fault(cb, 718);

      if (control.maxTtl && lease > control.maxTtl) lease = control.maxTtl;

      var key = key_of(protocol, granted);
      var entry = context.mappings[key];
      var now = Date.now();

      if (entry) {
        entry.internalPort  = internal_port;
        entry.leaseDuration = lease;
        entry.description   = request.description;
        entry.renewedAt     = now;
        arm_expiry(entry);
        context.stats.mappingsRenewed++;
        ev.emit('port-renewed', public_mapping(entry));
      } else {
        entry = {
          protocol:      protocol,
          externalPort:  granted,
          internalIp:    internal_ip,
          internalPort:  internal_port,
          leaseDuration: lease,
          description:   request.description,
          remoteHost:    request.remoteHost,
          createdAt:     now,
          renewedAt:     now
        };
        context.mappings[key] = entry;
        count_add(entry.internalIp);
        invalidate_order();
        arm_expiry(entry);
        context.stats.mappingsCreated++;
        ev.emit('port-mapped', public_mapping(entry));
      }

      // AddAnyPortMapping reports which port it actually reserved; plain
      // AddPortMapping returns nothing at all
      ok(cb, any_port ? 'AddAnyPortMapping' : 'AddPortMapping',
         any_port ? { NewReservedPort: granted } : {});
    });
  }


  function do_delete_mapping(args, remote, cb) {
    var protocol = String(args.NewProtocol || 'TCP').toLowerCase();
    var port = parseInt(args.NewExternalPort, 10);
    var entry = context.mappings[key_of(protocol, port)];

    if (!entry) return fault(cb, 714);

    if (!context.allowThirdPartyMappings && entry.internalIp !== remote.address) {
      context.stats.thirdPartyBlocked++;
      ev.emit('third-party-blocked', { from: remote.address, claimed: entry.internalIp });
      return fault(cb, 606, 'A mapping may only be deleted by the host that owns it');
    }

    remove(protocol, port, 'client-request');
    ok(cb, 'DeletePortMapping', {});
  }


  function do_delete_range(args, remote, cb) {
    if (context.igdVersion < 2) return fault(cb, 401);

    var protocol = String(args.NewProtocol || 'TCP').toLowerCase();
    var start = parseInt(args.NewStartPort, 10);
    var end   = parseInt(args.NewEndPort, 10);
    if (isNaN(start) || isNaN(end) || start > end) return fault(cb, 402);

    var removed = 0;
    sorted_mappings().forEach(function(e) {
      if (e.protocol !== protocol) return;
      if (e.externalPort < start || e.externalPort > end) return;
      if (!context.allowThirdPartyMappings && e.internalIp !== remote.address) return;
      remove(e.protocol, e.externalPort, 'client-request');
      removed++;
    });

    if (!removed) return fault(cb, 730, 'PortMappingNotFound');
    ok(cb, 'DeletePortMappingRange', {});
  }


  function do_get_generic(args, cb) {
    var index = parseInt(args.NewPortMappingIndex, 10);
    var list = sorted_mappings();
    // 713 is the documented end-of-array marker, and a client walking the
    // table from zero relies on it to know when to stop
    if (isNaN(index) || index < 0 || index >= list.length) return fault(cb, 713);
    ok(cb, 'GetGenericPortMappingEntry', mapping_args(list[index]));
  }


  function do_get_specific(args, cb) {
    var protocol = String(args.NewProtocol || 'TCP').toLowerCase();
    var port = parseInt(args.NewExternalPort, 10);
    var entry = context.mappings[key_of(protocol, port)];
    if (!entry) return fault(cb, 714);
    ok(cb, 'GetSpecificPortMappingEntry', {
      NewInternalPort:           entry.internalPort,
      NewInternalClient:         entry.internalIp,
      NewEnabled:                1,
      NewPortMappingDescription: entry.description,
      NewLeaseDuration:          entry.leaseDuration
    });
  }


  function do_get_list(args, remote, cb) {
    if (context.igdVersion < 2) return fault(cb, 401);

    var protocol = String(args.NewProtocol || 'TCP').toLowerCase();
    var start = parseInt(args.NewStartPort, 10) || 0;
    var end   = parseInt(args.NewEndPort, 10) || 65535;
    var manage = args.NewManage === '1' || args.NewManage === 'true';

    var list = sorted_mappings().filter(function(e) {
      if (e.protocol !== protocol) return false;
      if (e.externalPort < start || e.externalPort > end) return false;
      // Without NewManage a client sees only what it owns
      if (!manage && e.internalIp !== remote.address) return false;
      return true;
    });

    ok(cb, 'GetListOfPortMappings', { NewPortListing: soap.encode_port_listing(list) });
  }


  function mapping_args(e) {
    return {
      NewRemoteHost:             e.remoteHost || '',
      NewExternalPort:           e.externalPort,
      NewProtocol:               e.protocol.toUpperCase(),
      NewInternalPort:           e.internalPort,
      NewInternalClient:         e.internalIp,
      NewEnabled:                1,
      NewPortMappingDescription: e.description || '',
      NewLeaseDuration:          e.leaseDuration || 0
    };
  }


  /* ========================== IPv6 pinholes ========================== */

  function do_add_pinhole(args, remote, cb) {
    var internal = args.InternalClient || remote.address;

    if (!context.allowThirdPartyMappings && args.InternalClient &&
        args.InternalClient !== remote.address) {
      context.stats.thirdPartyBlocked++;
      return fault(cb, 606, 'A pinhole may only be created for the requesting host');
    }

    var request = {
      via:          'upnp-pinhole',
      internalIp:   internal,
      internalPort: parseInt(args.InternalPort, 10) || 0,
      remoteHost:   args.RemoteHost || '',
      remotePort:   parseInt(args.RemotePort, 10) || 0,
      protocol:     soap.protocol_name(args.Protocol),
      leaseTime:    parseInt(args.LeaseTime, 10) || 0,
      remote:       remote
    };

    var control = control_for(null, context.maxLifetime);
    if (context.policy === 'allow-all') control.allow();

    ev.emit('pinhole-request', request, control);

    await_control(control, function() {
      if (control._rejected || !control._allowed) {
        context.stats.requestsRejected++;
        return fault(cb, typeof control._rejected === 'number' ? control._rejected : 606);
      }

      var id = context.nextPinholeId++;
      // UniqueID is a ui2, so it wraps rather than growing without bound
      if (context.nextPinholeId > 65535) context.nextPinholeId = 1;

      var entry = {
        uniqueId:     id,
        internalIp:   request.internalIp,
        internalPort: request.internalPort,
        remoteHost:   request.remoteHost,
        remotePort:   request.remotePort,
        protocol:     request.protocol,
        leaseTime:    request.leaseTime,
        packets:      0,
        createdAt:    Date.now()
      };

      if (entry.leaseTime) {
        entry.timer = safe_timeout(function() {
          delete context.pinholes[id];
          ev.emit('pinhole-expired', entry);
        }, entry.leaseTime * 1000);
      }

      context.pinholes[id] = entry;
      context.stats.pinholesCreated++;
      ev.emit('pinhole-opened', entry);

      ok(cb, 'AddPinhole', { UniqueID: id }, firewall_type());
    });
  }


  function do_pinhole_action(action, args, remote, cb) {
    var id = parseInt(args.UniqueID, 10);
    var entry = context.pinholes[id];

    if (action !== 'GetFirewallStatus' && !entry) return fault(cb, 704);

    if (action === 'DeletePinhole') {
      if (entry.timer) clear_safe_timeout(entry.timer);
      delete context.pinholes[id];
      ev.emit('pinhole-closed', entry);
      return ok(cb, 'DeletePinhole', {}, firewall_type());
    }

    if (action === 'UpdatePinhole') {
      var lease = parseInt(args.NewLeaseTime, 10) || 0;
      entry.leaseTime = lease;
      if (entry.timer) clear_safe_timeout(entry.timer);
      if (lease) {
        entry.timer = safe_timeout(function() {
          delete context.pinholes[id];
          ev.emit('pinhole-expired', entry);
        }, lease * 1000);
      }
      return ok(cb, 'UpdatePinhole', {}, firewall_type());
    }

    if (action === 'GetPinholePackets') {
      return ok(cb, 'GetPinholePackets', { PinholePackets: entry.packets }, firewall_type());
    }

    if (action === 'CheckPinholeWorking') {
      // 709 NoPacketSent is the documented answer for a pinhole that exists
      // but has carried nothing yet — not a failure
      if (!entry.packets) return fault(cb, 709);
      return ok(cb, 'CheckPinholeWorking', { IsWorking: 1 }, firewall_type());
    }

    fault(cb, 401);
  }


  /* ============================== HTTP ============================== */

  /**
   * Handle one HTTP request. The transport supplies { method, url, headers,
   * body, remote } and sends back { statusCode, headers, body }.
   */
  function handle_http(req, cb) {
    // Always answer on a later tick, even when the answer is already known.
    //
    // A control point walking the mapping table calls this once per entry from
    // inside the previous callback. If some paths answer synchronously and
    // others do not, that loop is sometimes a loop and sometimes unbounded
    // recursion — and a table of a few hundred entries then overflows the
    // stack. One consistent contract removes the whole class of problem, and
    // an extra tick per control request costs nothing at this rate.
    var answer = cb;
    cb = function() {
      var args = arguments;
      setImmediate(function() { answer.apply(null, args); });
    };

    if (context.state === 'destroyed') {
      return cb(null, { statusCode: 503, headers: {}, body: '' });
    }

    var path = String(req.url || '/').split('?')[0];
    var remote = req.remote || { address: null };

    if (req.method === 'GET' || req.method === 'HEAD') {
      if (path === description_path()) {
        context.stats.descriptionsServed++;
        return cb(null, {
          statusCode: 200,
          headers: { 'Content-Type': 'text/xml; charset="utf-8"' },
          // Control URLs in the document are relative, so they resolve against
          // whichever address this client used to fetch it — which is what
          // makes one document correct on every interface
          body: describe()
        });
      }
      // Every service publishes its own description, which is how a control
      // point learns what this gateway actually implements rather than
      // inferring it from the version number
      if (/^\/scpd\//.test(path)) {
        return cb(null, {
          statusCode: 200,
          headers: { 'Content-Type': 'text/xml; charset="utf-8"' },
          body: describe_service(path)
        });
      }
      return cb(null, { statusCode: 404, headers: {}, body: '' });
    }

    if (req.method === 'SUBSCRIBE')   return handle_subscribe(req, remote, cb);
    if (req.method === 'UNSUBSCRIBE') return handle_unsubscribe(req, cb);

    if (req.method !== 'POST') return cb(null, { statusCode: 405, headers: {}, body: '' });

    context.stats.soapRequests++;

    var header = req.headers && (req.headers['SOAPAction'] || req.headers['soapaction']);
    var addressed = soap.parse_soap_action(header);

    var parsed;
    try { parsed = soap.decode_request(req.body); }
    catch (e) {
      ev.emit('warning', 'Malformed SOAP request: ' + e.message);
      return fault(cb, 401, 'Malformed request');
    }

    var action = parsed.action;
    var args = parsed.args;
    dbg('session', 'SOAP', action, 'from', remote.address);

    // Firewall actions live on their own control URL and their own service
    if (path === context.firewallControlUrl ||
        (addressed && addressed.serviceType === firewall_type())) {
      if (action === 'GetFirewallStatus') {
        return ok(cb, 'GetFirewallStatus',
                  { FirewallEnabled: 1, InboundPinholeAllowed: 1 }, firewall_type());
      }
      if (action === 'AddPinhole') return do_add_pinhole(args, remote, cb);
      if (action === 'GetOutboundPinholeTimeout') {
        return ok(cb, 'GetOutboundPinholeTimeout',
                  { OutboundPinholeTimeout: 180 }, firewall_type());
      }
      return do_pinhole_action(action, args, remote, cb);
    }

    switch (action) {
      case 'AddPortMapping':               return do_add_mapping(args, remote, false, cb);
      case 'AddAnyPortMapping':
        if (context.igdVersion < 2) return fault(cb, 401);
        return do_add_mapping(args, remote, true, cb);
      case 'DeletePortMapping':            return do_delete_mapping(args, remote, cb);
      case 'DeletePortMappingRange':       return do_delete_range(args, remote, cb);
      case 'GetGenericPortMappingEntry':   return do_get_generic(args, cb);
      case 'GetSpecificPortMappingEntry':  return do_get_specific(args, cb);
      case 'GetListOfPortMappings':        return do_get_list(args, remote, cb);

      case 'GetExternalIPAddress':
        if (!context.externalIp) return fault(cb, 501, 'No external address yet');
        return ok(cb, 'GetExternalIPAddress', { NewExternalIPAddress: context.externalIp });

      case 'GetConnectionTypeInfo':
        return ok(cb, 'GetConnectionTypeInfo', {
          NewConnectionType:          context.connectionType,
          NewPossibleConnectionTypes: 'Unconfigured,IP_Routed,IP_Bridged'
        });

      case 'GetPortMappingNumberOfEntries':
        return ok(cb, 'GetPortMappingNumberOfEntries', {
          NewPortMappingNumberOfEntries: sorted_mappings().length
        });

      case 'GetCommonLinkProperties':
        return ok(cb, 'GetCommonLinkProperties', {
          NewWANAccessType:              context.wanAccessType,
          NewLayer1UpstreamMaxBitRate:   context.upstreamBitRate,
          NewLayer1DownstreamMaxBitRate: context.downstreamBitRate,
          NewPhysicalLinkStatus:         context.linkStatus
        }, soap.COMMON_INTERFACE_SERVICE);

      case 'GetTotalBytesSent':
        return ok(cb, 'GetTotalBytesSent',
                  { NewTotalBytesSent: context.counters.bytesSent },
                  soap.COMMON_INTERFACE_SERVICE);
      case 'GetTotalBytesReceived':
        return ok(cb, 'GetTotalBytesReceived',
                  { NewTotalBytesReceived: context.counters.bytesReceived },
                  soap.COMMON_INTERFACE_SERVICE);
      case 'GetTotalPacketsSent':
        return ok(cb, 'GetTotalPacketsSent',
                  { NewTotalPacketsSent: context.counters.packetsSent },
                  soap.COMMON_INTERFACE_SERVICE);
      case 'GetTotalPacketsReceived':
        return ok(cb, 'GetTotalPacketsReceived',
                  { NewTotalPacketsReceived: context.counters.packetsReceived },
                  soap.COMMON_INTERFACE_SERVICE);

      case 'GetStatusInfo':
        return ok(cb, 'GetStatusInfo', {
          NewConnectionStatus:    context.connectionStatus,
          NewLastConnectionError: 'ERROR_NONE',
          NewUptime:              Math.floor((Date.now() - context.uptimeStart) / 1000)
        });

      default:
        // 401 InvalidAction is the architecture's answer for an action the
        // service does not implement
        return fault(cb, 401);
    }
  }


  /**
   * A service description listing the actions this gateway implements.
   *
   * Generated from the same switch that handles them, so the two cannot drift:
   * an action advertised here is one the gateway will answer.
   */
  function describe_service(path) {
    var is_firewall = /IPv6FC/i.test(path);
    var is_common   = /CommonIFC/i.test(path);

    var actions = is_firewall
      ? ['GetFirewallStatus', 'GetOutboundPinholeTimeout', 'AddPinhole',
         'UpdatePinhole', 'DeletePinhole', 'GetPinholePackets', 'CheckPinholeWorking']
      : is_common
        ? ['GetCommonLinkProperties', 'GetTotalBytesSent', 'GetTotalBytesReceived',
           'GetTotalPacketsSent', 'GetTotalPacketsReceived']
        : ['AddPortMapping', 'DeletePortMapping', 'GetExternalIPAddress',
           'GetStatusInfo', 'GetConnectionTypeInfo', 'GetGenericPortMappingEntry',
           'GetSpecificPortMappingEntry', 'GetPortMappingNumberOfEntries']
          .concat(context.igdVersion >= 2
            ? ['AddAnyPortMapping', 'DeletePortMappingRange', 'GetListOfPortMappings']
            : []);

    var xml = '<?xml version="1.0"?><scpd xmlns="urn:schemas-upnp-org:service-1-0">' +
      '<specVersion><major>1</major><minor>0</minor></specVersion><actionList>';
    for (var i = 0; i < actions.length; i++) {
      xml += '<action><name>' + actions[i] + '</name><argumentList/></action>';
    }
    xml += '</actionList><serviceStateTable>' +
      // Only evented variables can ever reach a subscriber
      '<stateVariable sendEvents="yes"><name>ExternalIPAddress</name>' +
        '<dataType>string</dataType></stateVariable>' +
      '<stateVariable sendEvents="yes"><name>PortMappingNumberOfEntries</name>' +
        '<dataType>ui2</dataType></stateVariable>' +
      '<stateVariable sendEvents="yes"><name>ConnectionStatus</name>' +
        '<dataType>string</dataType></stateVariable>' +
      '</serviceStateTable></scpd>';
    return xml;
  }


  /**
   * GENA subscription. A CALLBACK plus NT is a new subscription; a bare SID is
   * a renewal, and mixing them is an error the architecture defines, so the
   * two cases are separated here rather than merged.
   */
  function handle_subscribe(req, remote, cb) {
    var headers = req.headers || {};
    var sid      = headers.sid || headers.SID;
    var callback = headers.callback || headers.CALLBACK;
    var nt       = headers.nt || headers.NT;
    var timeout  = soap.parse_timeout(headers.timeout || headers.TIMEOUT) || 1800;

    if (sid && (callback || nt)) {
      return cb(null, { statusCode: 400, headers: {}, body: '' });
    }

    if (sid) {
      var existing = context.subscribers[sid];
      if (!existing) return cb(null, { statusCode: 412, headers: {}, body: '' });
      existing.expiresAt = Date.now() + timeout * 1000;
      return cb(null, {
        statusCode: 200,
        headers: { 'SID': sid, 'TIMEOUT': 'Second-' + timeout },
        body: ''
      });
    }

    if (!callback || nt !== 'upnp:event') {
      return cb(null, { statusCode: 412, headers: {}, body: '' });
    }

    var url = /<([^>]+)>/.exec(callback);
    if (!url) return cb(null, { statusCode: 412, headers: {}, body: '' });

    context.subscriberSeq++;
    var new_sid = 'uuid:sub-' + context.udn.replace('uuid:', '').slice(0, 8) +
                  '-' + context.subscriberSeq;

    context.subscribers[new_sid] = {
      sid:       new_sid,
      callback:  url[1],
      seq:       0,
      expiresAt: Date.now() + timeout * 1000,
      from:      remote.address
    };

    ev.emit('subscribed', { sid: new_sid, callback: url[1], from: remote.address });

    cb(null, {
      statusCode: 200,
      headers: { 'SID': new_sid, 'TIMEOUT': 'Second-' + timeout },
      body: ''
    });
  }


  function handle_unsubscribe(req, cb) {
    var sid = (req.headers || {}).sid || (req.headers || {}).SID;
    if (!sid || !context.subscribers[sid]) {
      return cb(null, { statusCode: 412, headers: {}, body: '' });
    }
    delete context.subscribers[sid];
    ev.emit('unsubscribed', { sid: sid });
    cb(null, { statusCode: 200, headers: {}, body: '' });
  }


  /**
   * Announce a changed state variable to every live subscriber.
   *
   * The transport does the posting; this builds what to post and to where,
   * and keeps the per-subscription sequence number the architecture requires
   * so a subscriber can notice a missed notification.
   */
  function notify(properties) {
    var body = soap.encode_property_set(properties);
    var out = [];
    var now = Date.now();

    Object.keys(context.subscribers).forEach(function(sid) {
      var sub = context.subscribers[sid];
      if (sub.expiresAt < now) { delete context.subscribers[sid]; return; }

      out.push({
        url:  sub.callback,
        body: body,
        headers: {
          'Content-Type': 'text/xml; charset="utf-8"',
          'NT':           'upnp:event',
          'NTS':          'upnp:propchange',
          'SID':          sid,
          'SEQ':          String(sub.seq++)
        }
      });
    });

    if (out.length) ev.emit('notify', out);
    return out;
  }


  function description_path() {
    var base = typeof context.location === 'function'
      ? context.location(null) : context.location;
    var m = /^https?:\/\/[^/]+(\/.*)$/.exec(base || '');
    return m ? m[1].split('?')[0] : '/';
  }


  function describe() {
    return ssdp.encode_device_description({
      udn:          context.udn,
      igdVersion:   context.igdVersion,
      friendlyName: context.friendlyName,
      manufacturer: context.manufacturer,
      modelName:    context.modelName,
      controlUrl:   context.controlUrl,
      firewallControlUrl: context.firewallControlUrl,
      configId:     context.configId
    });
  }


  /* ============================ Accessors ============================ */

  function public_mapping(e) {
    return {
      protocol:      e.protocol,
      externalPort:  e.externalPort,
      internalIp:    e.internalIp,
      internalPort:  e.internalPort,
      leaseDuration: e.leaseDuration,
      permanent:     !e.leaseDuration,
      description:   e.description || '',
      remoteHost:    e.remoteHost || null,
      via:           'upnp',
      createdAt:     new Date(e.createdAt),
      renewedAt:     e.renewedAt ? new Date(e.renewedAt) : null
    };
  }


  function getMappings() { return sorted_mappings().map(public_mapping); }
  function getPinholes() {
    return Object.keys(context.pinholes).map(function(k) { return context.pinholes[k]; });
  }

  function revoke(protocol, external_port) {
    var e = remove(protocol, external_port, 'revoked');
    return e ? public_mapping(e) : null;
  }

  function setExternalIp(ip) {
    if (ip === context.externalIp) return;
    context.externalIp = ip;
    ev.emit('external-ip', ip);
    // The evented half of what NAT-PMP does by multicast
    notify({ ExternalIPAddress: ip });
  }

  function setConnectionStatus(status) {
    context.connectionStatus = status;
    ev.emit('connection-status', status);
  }

  function setCounters(values) {
    Object.assign(context.counters, values || {});
  }

  function getStats() { return Object.assign({}, context.stats); }

  function getConfig() {
    return {
      udn:        context.udn,
      location:   context.location,
      igdVersion: context.igdVersion,
      externalIp: context.externalIp,
      policy:     context.policy,
      allowThirdPartyMappings: context.allowThirdPartyMappings,
      controlUrl: context.controlUrl,
      firewallControlUrl: context.firewallControlUrl
    };
  }


  /* ============================ Lifecycle ============================ */

  function listening() {
    if (context.state === 'destroyed') return;
    context.state = 'listening';
    ev.emit('listening');
    // UDA 1.1 — a device announces itself when it joins the network, rather
    // than waiting to be searched for
    advertise('ssdp:alive');
    schedule_advertisements();
  }


  function destroy() {
    if (context.state === 'destroyed') return;

    // Withdraw before going away, so control points drop us immediately
    // instead of waiting out their cache
    if (context.state === 'listening') advertise('ssdp:byebye');

    context.state = 'destroyed';
    if (context.announceTimer) clear_safe_timeout(context.announceTimer);

    Object.keys(context.mappings).forEach(function(k) {
      var e = context.mappings[k];
      if (e.timer) clear_safe_timeout(e.timer);
    });
    Object.keys(context.pinholes).forEach(function(k) {
      var e = context.pinholes[k];
      if (e.timer) clear_safe_timeout(e.timer);
    });
    context.mappings = Object.create(null);
    context.pinholes = Object.create(null);

    ev.emit('destroyed');
    ev.removeAllListeners();
  }


  /* ================================ API ================================ */

  var CONTROLLED = { 'port-request': true, 'pinhole-request': true };

  var api = {
    context: context,

    on: function(name, fn) { ev.on(name, CONTROLLED[name] ? wrap_control_listener(fn) : fn); },
    once: function(name, fn) { ev.once(name, CONTROLLED[name] ? wrap_control_listener(fn) : fn); },
    off: function(name, fn) { remove_control_listener(ev, name, fn); },

    process_packet: process_packet,
    handle_http: handle_http,
    listening: listening,

    advertise: advertise,
    update: update,
    describe: describe,
    descriptionPath: description_path,

    getMappings: getMappings,
    getPinholes: getPinholes,
    revoke: revoke,
    setExternalIp: setExternalIp,
    setConnectionStatus: setConnectionStatus,
    setCounters: setCounters,
    notify: notify,
    getSubscribers: function() {
      return Object.keys(context.subscribers).map(function(k) {
        return Object.assign({}, context.subscribers[k]);
      });
    },
    getStats: getStats,
    getConfig: getConfig,

    destroy: destroy
  };

  for (var k in api) if (Object.prototype.hasOwnProperty.call(api, k)) this[k] = api[k];

  Object.defineProperty(this, 'state', {
    get: function() { return context.state; },
    enumerable: true
  });

  return this;
}


export default UPnPServerSession;
export { UPnPServerSession };
