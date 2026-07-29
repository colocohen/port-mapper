/**
 * upnp_session.js — UPnP-IGD client protocol engine.
 *
 * Transport-agnostic, same pattern as PMPSession: SSDP datagrams leave as
 * 'packet' (buf, dest) events and arrive through process_packet(). The one
 * difference is that UPnP also needs HTTP, which is request/response rather
 * than fire-and-forget, so the caller injects an `http` function the way the
 * DHCP server takes an injected conflict `probe`. That keeps the whole engine
 * testable without sockets.
 *
 *   new UPnPSession({
 *     localIp: '192.168.1.42',
 *     gateway: '192.168.1.1',
 *     http: function (req, cb) { ... cb(null, { statusCode, headers, body }) }
 *   })
 *
 * Two behaviours here exist because of documented weaknesses in IGD, not
 * because of anything a router did to us in testing:
 *
 *   On-path preference. RFC 6886 §9.8 records that UPnP clients accept any
 *   device on the LAN claiming IGD capability, whether or not traffic
 *   actually flows through it — which produced years of reports of mappings
 *   that "worked" while never carrying a single inbound packet, because an
 *   old spare router was answering. So a device whose LOCATION address is the
 *   default gateway is preferred, and anything else is flagged off-path.
 *
 *   Lease fallback. RFC 6886 §9.5 notes that in practice almost every client
 *   requests an infinite lease, that gateways which mishandle finite leases
 *   were therefore never exercised, and that some fail or crash when asked
 *   for one. We ask for a finite lease because unrenewed mappings should be
 *   collected, but a gateway answering 725 OnlyPermanentLeasesSupported gets
 *   one automatic retry with a permanent lease rather than an error.
 *
 * References:
 *   UPnP Device Architecture 1.1 §1 (discovery), §3 (control)
 *   IGD:1 / IGD:2 WANIPConnection, WANPPPConnection
 */

import { EventEmitter } from 'node:events';
import * as ssdp from './ssdp.js';
import * as soap from './soap.js';
import * as lifecycle from './lifecycle.js';
import * as quirks from './quirks.js';
import { same_subnet } from './interfaces.js';
import { safe_timeout, clear_safe_timeout } from './timers.js';
import { dbg } from './debug.js';
import { PortMapValidationError, PortMapProtocolError, PortMapStateError, NoGatewayError } from './errors.js';


function validate_options(opts) {
  if (!opts.localIp) {
    throw new PortMapValidationError(
      'localIp (our address on the LAN) required — it is the NewInternalClient of every mapping',
      'localIp');
  }
  if (typeof opts.http !== 'function') {
    throw new PortMapValidationError(
      'http(request, callback) required — the session performs no I/O itself', 'http');
  }
  if (opts.lifetime !== undefined &&
      (typeof opts.lifetime !== 'number' || opts.lifetime < 0)) {
    throw new PortMapValidationError('lifetime must be a non-negative number of seconds', 'lifetime');
  }
}


// How many external ports to try when the gateway reports a conflict. Kept
// small deliberately: RFC 6886 §9.4 points out that a client which guesses
// incrementally against a gateway using pre-assigned port ranges can need
// tens of thousands of attempts. On IGD:2 AddAnyPortMapping removes the guess
// entirely; on IGD:1 we give up quickly and let the gateway choose instead.
const MAX_CONFLICT_RETRIES = 3;

// SSDP is unreliable UDP, so the search is repeated. UDA 1.1 recommends
// retransmitting rather than assuming one datagram arrives.
const SEARCH_ATTEMPTS = 3;
const SEARCH_INTERVAL_MS = 500;


function UPnPSession(options) {
  if (!(this instanceof UPnPSession)) return new UPnPSession(options);
  options = options || {};
  validate_options(options);

  var ev = new EventEmitter();
  ev.setMaxListeners(0);

  var context = {
    state: 'new',            // new | searching | ready | destroyed

    family:   options.family === 'ipv6' ? 'ipv6' : 'ipv4',
    localIp:  options.localIp,
    gateway:  options.gateway || null,
    http:     options.http,

    // Written into every mapping and used by cleanup() to recognise its own.
    // Callers should set this to something naming their application: two
    // different programs both leaving 'port-mapper' behind cannot tell their
    // strays apart.
    description: options.description || 'port-mapper',
    lifetime: options.lifetime === undefined ? lifecycle.LIFETIME.DEFAULT : options.lifetime,

    searchTargets: options.searchTargets || [ssdp.ST.IGD2, ssdp.ST.IGD1],
    // Multicast discovery cannot cross a router, so a gateway one hop away —
    // an upstream router in a double-NAT setup, for instance — is invisible to
    // an ordinary M-SEARCH. UDA 1.1 also defines a unicast search, addressed
    // straight at a host and answered immediately (no MX delay). Set
    // searchUnicast to that host to use it.
    searchUnicast: options.searchUnicast || null,
    // A device may announce a different port for unicast searches; setting it
    // explicitly is for the case where it is known in advance
    searchPort: options.searchPort || null,
    // MX is how long a device may wait before answering, and the architecture
    // caps it at 5. A search window shorter than MX would sometimes close
    // while a compliant gateway is still deliberately holding its reply — a
    // race that shows up as "found it sometimes", so the window is widened to
    // cover MX rather than trusting the caller to get it right.
    searchMx: Math.min(5, Math.max(1, options.searchMx === undefined ? 2 : options.searchMx)),
    searchTimeout: options.searchTimeout || 3000,
    // Accept a gateway that is not the default route. Off by default: see the
    // on-path note above.
    allowOffPath: options.allowOffPath === true,

    // The netmask of our own interface, used to check that a LOCATION points
    // somewhere on this network
    netmask: options.netmask || null,

    quirks: [],
    quirkEffects: {},

    // Discovery results, keyed by device UUID so a gateway advertising several
    // roles is not counted three times
    candidates: Object.create(null),
    device: null,            // the chosen parsed description
    chosenLocation: null,
    service: null,           // its connection service
    firewall: null,          // WANIPv6FirewallControl, when the device has one
    common: null,            // WANCommonInterfaceConfig, when the device has one
    igdVersion: null,

    // Gateways that have told us they cannot do finite leases
    permanentLeasesOnly: false,

    mappings: Object.create(null),
    pinholes: Object.create(null),
    subscriptions: Object.create(null),
    externalIp: null,

    searchTimer: null,
    searchAttempt: 0,
    searchCb: null,

    stats: {
      searchesSent:     0,
      responsesSeen:    0,
      offPathIgnored:   0,
      offNetworkIgnored: 0,
      descriptionsRead: 0,
      soapCalls:        0,
      soapFaults:       0,
      enumerationEnds:  0,
      conflicts:        0,
      leaseDowngrades:  0,
      mappingsCreated:  0,
      renewals:         0,
      pinholesCreated:  0,
      staleRemoved:     0,
      eventsReceived:   0,
      eventsMissed:     0,
      connectionRetries: 0
    }
  };


  function mapping_key(protocol, external_port) {
    return protocol + ':' + external_port;
  }


  /* ============================ Discovery ============================ */

  /**
   * Send one M-SEARCH per configured target. Responses arrive asynchronously
   * through process_packet and accumulate until the search window closes.
   */
  function send_search() {
    var unicast = context.searchUnicast;

    for (var i = 0; i < context.searchTargets.length; i++) {
      var buf = ssdp.encode_msearch({
        family:    context.family,
        st:        context.searchTargets[i],
        mx:        context.searchMx,
        unicast:   !!unicast,
        host:      unicast || ssdp.MULTICAST_ADDR,
        userAgent: 'Node/UPnP/1.1 port-mapper/1.0'
      });
      context.stats.searchesSent++;
      ev.emit('packet', buf, {
        address: unicast || ssdp.multicast_for(context.family),
        port:    unicast ? (context.searchPort || ssdp.MULTICAST_PORT) : ssdp.MULTICAST_PORT
      });
    }
  }


  function effective_search_timeout() {
    // A unicast search is answered immediately and carries no MX at all
    if (context.searchUnicast) return context.searchTimeout;
    return Math.max(context.searchTimeout, context.searchMx * 1000 + 300);
  }


  function discover(cb) {
    if (context.state === 'destroyed') {
      return cb(new PortMapStateError('Session destroyed', context.state));
    }
    if (context.state === 'searching') {
      return cb(new PortMapStateError('Discovery already in progress', context.state));
    }

    context.state = 'searching';
    context.searchCb = cb;
    context.searchAttempt = 0;
    context.candidates = Object.create(null);

    function attempt() {
      if (context.state !== 'searching') return;
      context.searchAttempt++;
      send_search();

      if (context.searchAttempt < SEARCH_ATTEMPTS) {
        context.searchTimer = safe_timeout(attempt, SEARCH_INTERVAL_MS);
      } else {
        context.searchTimer = safe_timeout(finish_search, effective_search_timeout());
      }
    }

    attempt();

    return {
      cancel: function(reason) {
        if (context.state !== 'searching') return false;
        context.state = 'new';
        clear_search_timer();
        var err = new PortMapStateError(reason || 'Discovery cancelled', 'cancelled');
        err.cancelled = true;
        end_search(err);
        return true;
      }
    };
  }


  /**
   * Everything discovery has heard from, whether or not it was chosen.
   *
   * A network can hold several devices claiming IGD capability — a spare
   * router still plugged in, a second WAN device, a virtual appliance — and
   * only one of them is on the path this host's traffic actually takes. The
   * chosen one is reported through 'ready'; this is the rest, so a caller can
   * see what was passed over and why.
   */
  function getCandidates() {
    return Object.keys(context.candidates).map(function(uuid) {
      var c = context.candidates[uuid];
      return {
        uuid:     c.uuid,
        location: c.location,
        address:  c.address,
        server:   c.server,
        st:       c.st,
        bootId:   c.bootId === undefined ? null : c.bootId,
        searchPort: c.searchPort || null,
        onPath:   c.onPath,
        chosen:   !!(context.device && context.chosenLocation === c.location)
      };
    });
  }


  function finish_search() {
    if (context.state !== 'searching') return;
    clear_search_timer();

    var uuids = Object.keys(context.candidates);
    if (uuids.length === 0) {
      context.state = 'new';
      return end_search(new NoGatewayError(
        'No UPnP Internet Gateway Device answered on the local network',
        context.searchTargets.slice()));
    }

    // Prefer the device that actually sits on our default route
    var ordered = uuids.map(function(u) { return context.candidates[u]; });
    ordered.sort(function(a, b) { return (b.onPath ? 1 : 0) - (a.onPath ? 1 : 0); });

    var chosen = ordered[0];
    if (!chosen.onPath && !context.allowOffPath) {
      context.state = 'new';
      var off = new NoGatewayError(
        'Found ' + ordered.length + ' IGD device(s), but none of them is the default ' +
        'gateway ' + context.gateway + '. A router that is not forwarding this host\'s ' +
        'traffic cannot make a working mapping (RFC 6886 §9.8). Pass allowOffPath:true ' +
        'to use it anyway.',
        ordered.map(function(c) { return c.location; }));
      context.stats.offPathIgnored += ordered.length;
      return end_search(off);
    }

    fetch_description(chosen);
  }


  function fetch_description(candidate) {
    dbg('discovery', 'fetching description from', candidate.location);

    context.http({ url: candidate.location, method: 'GET', headers: {} }, function(err, res) {
      if (context.state === 'destroyed') return;

      if (err) return end_search(err);
      if (res.statusCode !== 200) {
        return end_search(new PortMapProtocolError(
          'Device description fetch returned HTTP ' + res.statusCode,
          res.statusCode, 'upnp'));
      }

      var device;
      try {
        device = ssdp.parse_device_description(res.body, candidate.location);
      } catch (e) {
        return end_search(new PortMapProtocolError(
          'Could not read the device description: ' + e.message, null, 'upnp'));
      }

      context.stats.descriptionsRead++;

      if (!device.connection) {
        return end_search(new PortMapProtocolError(
          'Device "' + (device.friendlyName || 'unknown') + '" exposes no ' +
          'WANIPConnection or WANPPPConnection service, so it cannot map ports',
          null, 'upnp'));
      }

      context.device         = device;
      context.chosenLocation = candidate.location;

      // What this particular gateway is known to do differently. Matched on
      // what it says about itself, which is all we have.
      context.quirks = quirks.match({
        server:       candidate.server,
        manufacturer: device.manufacturer,
        modelName:    device.modelName,
        friendlyName: device.friendlyName
      });
      context.quirkEffects = quirks.effects_of(context.quirks);
      if (context.quirks.length) {
        dbg('discovery', 'quirks:', context.quirks.map(function(q) { return q.id; }).join(', '));
        ev.emit('quirks', context.quirks.map(function(q) {
          return { id: q.id, note: q.note, source: q.source };
        }));
      }
      context.service        = device.connection;
      context.firewall   = device.firewall || null;
      context.common     = find_service(device, soap.COMMON_INTERFACE_SERVICE);
      context.igdVersion = device.igdVersion;
      context.state      = 'ready';

      var info = {
        location:     candidate.location,
        onPath:       candidate.onPath,
        friendlyName: device.friendlyName,
        manufacturer: device.manufacturer,
        modelName:    device.modelName,
        igdVersion:   device.igdVersion,
        serviceType:  device.connection.type,
        controlUrl:   device.connection.controlUrl,
        // IGD:2 lets the gateway pick a free external port instead of making
        // the client guess (RFC 6886 §9.4)
        supportsAddAny: device.igdVersion >= 2,
        supportsPinholes: !!device.firewall,
        quirks: context.quirks.map(function(q) { return q.id; })
      };

      ev.emit('ready', info);
      end_search(null, info);
    });
  }


  function end_search(err, info) {
    var cb = context.searchCb;
    context.searchCb = null;
    clear_search_timer();
    if (cb) cb(err, info);
  }


  function clear_search_timer() {
    if (context.searchTimer) { clear_safe_timeout(context.searchTimer); context.searchTimer = null; }
  }


  /* ========================= Inbound SSDP ========================= */

  function process_packet(buf, rinfo) {
    if (context.state === 'destroyed') return;

    var msg = ssdp.decode_ssdp(buf);
    if (!msg) return;

    // Someone else's search, or our own multicast echoed back
    if (msg.kind === 'msearch') return;

    // A device leaving the network invalidates everything we know about it
    if (msg.kind === 'notify' && msg.nts === 'ssdp:byebye') {
      return on_byebye(msg);
    }

    check_boot_id(msg);

    // ssdp:update announces a new BOOTID without the device having gone away —
    // it changed something about itself, so the description should be re-read
    if (msg.kind === 'notify' && msg.nts === 'ssdp:update') {
      var updated_uuid = ssdp.usn_uuid(msg.usn);
      var updated = updated_uuid ? context.candidates[updated_uuid] : null;
      // Remember what it said it would become, so the alive that follows is
      // recognised as the same device rather than as a restart
      if (updated && msg.nextBootId !== null) updated.nextBootId = msg.nextBootId;
      ev.emit('gateway-updated', {
        uuid: updated_uuid, bootId: msg.bootId, nextBootId: msg.nextBootId
      });
      return;
    }

    if (!msg.location) return;

    var target = msg.st || msg.nt;
    var wanted = false;
    for (var i = 0; i < context.searchTargets.length; i++) {
      if (ssdp.st_matches(context.searchTargets[i], target)) { wanted = true; break; }
    }
    if (!wanted) return;

    context.stats.responsesSeen++;

    var host = ssdp.url_host(msg.location);
    var uuid = ssdp.usn_uuid(msg.usn) || msg.location;

    // The LOCATION is a URL this client is about to fetch, chosen by whoever
    // sent the datagram — and SSDP has no authentication at all, so anything
    // on the segment can answer. A LOCATION pointing off this network is
    // either a misconfiguration or an attempt to make us fetch from somewhere
    // else, and neither is a device worth talking to.
    if (host && context.netmask && context.localIp &&
        context.localIp.indexOf(':') === -1 && host.host.indexOf(':') === -1) {
      if (!same_subnet(host.host, context.localIp, context.netmask)) {
        context.stats.offNetworkIgnored++;
        ev.emit('warning',
          'Ignoring an SSDP response whose LOCATION is ' + host.host +
          ', which is not on this network (' + context.localIp + '/' +
          context.netmask + ').');
        dbg('discovery', 'rejecting off-network LOCATION', msg.location);
        return;
      }
    }

    // A gateway advertises the same device under several search targets, so
    // the first sighting wins and later ones only sharpen it.
    if (!context.candidates[uuid]) {
      context.candidates[uuid] = {
        uuid:     uuid,
        location: msg.location,
        server:   msg.server,
        st:       target,
        address:  host ? host.host : (rinfo && rinfo.address) || null,
        // Where to aim a unicast search at this device, when it is not 1900
        searchPort: msg.searchPort || null,
        bootId:   msg.bootId === null ? undefined : msg.bootId,
        onPath:   false
      };
    }

    var candidate = context.candidates[uuid];
    candidate.onPath = context.searchUnicast
      ? candidate.address === context.searchUnicast   // we aimed at this host
      : (context.gateway ? candidate.address === context.gateway : true);

    ev.emit('device', {
      location: candidate.location,
      address:  candidate.address,
      server:   candidate.server,
      onPath:   candidate.onPath
    });

    if (!candidate.onPath) {
      dbg('discovery', 'off-path IGD at', candidate.address, '— gateway is', context.gateway);
    }
  }


  /**
   * UDA 1.1 — BOOTID.UPNP.ORG changes whenever the device restarts. Every
   * subscription it held is void at that point, and so is anything a client
   * believed about it. This is the UPnP counterpart of the PCP epoch, and it
   * arrives on any advertisement rather than only on a reply.
   */
  function check_boot_id(msg) {
    if (msg.bootId === null || msg.bootId === undefined) return;
    var uuid = ssdp.usn_uuid(msg.usn);
    if (!uuid) return;

    var candidate = context.candidates[uuid];

    // A BOOTID that was announced in advance is the device telling us it is
    // about to change, not that it restarted. Following it keeps the
    // subscriptions, which is the whole reason ssdp:update exists.
    if (candidate && candidate.nextBootId !== undefined &&
        candidate.nextBootId === msg.bootId) {
      candidate.bootId = msg.bootId;
      delete candidate.nextBootId;
      dbg('discovery', 'followed an announced bootId change to', msg.bootId);
      return;
    }

    if (candidate && candidate.bootId !== undefined && candidate.bootId !== msg.bootId) {
      dbg('discovery', 'bootId changed', candidate.bootId, '→', msg.bootId);
      ev.emit('gateway-restarted', {
        uuid: uuid, from: candidate.bootId, to: msg.bootId,
        note: 'The gateway restarted: its subscriptions are void and its ' +
              'mappings may be gone.'
      });
      // Everything the gateway held is suspect now, including our own state
      context.subscriptions = Object.create(null);
    }
    if (candidate) candidate.bootId = msg.bootId;
  }


  function on_byebye(msg) {
    var uuid = ssdp.usn_uuid(msg.usn);
    if (!uuid) return;

    if (context.candidates[uuid]) delete context.candidates[uuid];

    if (context.device && context.device.udn &&
        context.device.udn.indexOf(uuid) !== -1) {
      dbg('discovery', 'our gateway announced byebye');
      ev.emit('gateway-gone', { uuid: uuid });
    }
  }


  /* ============================ SOAP calls ============================ */

  function call(action, args, cb) {
    if (context.state !== 'ready') {
      cb(new PortMapStateError('Not ready — call discover() first', context.state));
      return { cancel: function() { return false; } };
    }

    var req = soap.encode_request(context.service.type, action, args);
    context.stats.soapCalls++;
    dbg('soap', action, JSON.stringify(args));

    var cancelled = false;
    var retried = false;
    var handle = {
      cancel: function(reason) {
        if (cancelled) return false;
        cancelled = true;
        var err = new PortMapStateError(reason || 'Cancelled', 'cancelled');
        err.cancelled = true;
        cb(err);
        return true;
      }
    };

    function attempt() {
    context.http({
      url:     context.service.controlUrl,
      method:  'POST',
      headers: req.headers,
      body:    req.body
    }, function(err, res) {
      if (context.state === 'destroyed' || cancelled) return;

      // A gateway that closes the connection without answering is not
      // refusing — it is failing. Cheap firmware does this under load, and on
      // requests it dislikes, and a single retry recovers most of them. More
      // than one would just be waiting on a device that has made up its mind.
      if (err && /hang up|ECONNRESET|EPIPE/i.test(err.message || '') && !retried) {
        retried = true;
        context.stats.connectionRetries++;
        dbg('soap', action, 'connection dropped, retrying once');
        return setTimeout(function() { attempt(); }, 250);
      }

      if (err) return cb(err);

      var decoded;
      try {
        decoded = soap.decode_response(res.body, context.igdVersion);
      } catch (e) {
        return cb(new PortMapProtocolError(
          'Unreadable SOAP response to ' + action + ': ' + e.message, null, 'upnp'));
      }

      if (decoded.fault) {
        // 713 ends an enumeration rather than reporting a failure, so it must
        // not inflate the fault counter — walking the mapping table always
        // finishes with one.
        if (decoded.retry === 'end') context.stats.enumerationEnds++;
        else context.stats.soapFaults++;
        var fault = new PortMapProtocolError(
          action + ' failed: ' + (decoded.description || decoded.name),
          decoded.code, 'upnp');
        fault.retry     = decoded.retry;
        fault.ambiguous = decoded.ambiguous;
        fault.note      = decoded.note;
        return cb(fault, null, decoded);
      }

      // A 500 with no parseable fault is still a failure
      if (res.statusCode >= 400) {
        return cb(new PortMapProtocolError(
          action + ' returned HTTP ' + res.statusCode, res.statusCode, 'upnp'));
      }

      cb(null, decoded.args);
    });
    }

    attempt();
    return handle;
  }


  function find_service(device, type) {
    for (var i = 0; i < device.services.length; i++) {
      if (device.services[i].type === type) return device.services[i];
    }
    return null;
  }


  /**
   * Route a call to a service other than the connection one. Both the firewall
   * and the statistics services live on the same device but answer at their
   * own control URL and under their own serviceType.
   */
  function call_service(service, label, action, args, cb) {
    if (context.state !== 'ready') {
      return cb(new PortMapStateError('Not ready — call discover() first', context.state));
    }
    if (!service) {
      return cb(new PortMapProtocolError(
        'This gateway exposes no ' + label + ' service', null, 'upnp'));
    }
    var saved = context.service;
    context.service = service;
    call(action, args, function() {
      context.service = saved;
      cb.apply(null, arguments);
    });
  }


  /**
   * The firewall service is a different service on the same device, with its
   * own control URL and serviceType, so it cannot go through call().
   */
  function call_firewall(action, args, cb) {
    if (!context.firewall && context.state === 'ready') {
      return cb(new PortMapProtocolError(
        'This gateway exposes no WANIPv6FirewallControl service, so it cannot ' +
        'open IPv6 pinholes (that service is IGD:2 only)', null, 'upnp'));
    }
    call_service(context.firewall, 'WANIPv6FirewallControl', action, args, cb);
  }


  /* ============================== Actions ============================== */

  function getExternalIp(cb) {
    call(soap.ACTION.GET_EXTERNAL_IP, {}, function(err, args) {
      if (err) return cb(err);
      context.externalIp = args.NewExternalIPAddress || null;
      cb(null, { externalIp: context.externalIp });
    });
  }


  /**
   * Whether the WAN side is actually up. Worth checking before mapping: a
   * gateway that is disconnected will happily accept a mapping that cannot
   * possibly carry traffic.
   */
  function getStatus(cb) {
    call(soap.ACTION.GET_STATUS_INFO, {}, function(err, args) {
      if (err) return cb(err);
      cb(null, soap.parse_status_info(args));
    });
  }


  function map(opts, cb) {
    opts = opts || {};
    cb = cb || function() {};

    var protocol = (opts.protocol || 'tcp').toLowerCase();
    if (protocol !== 'tcp' && protocol !== 'udp') {
      return cb(new PortMapValidationError('protocol must be "tcp" or "udp"', 'protocol'));
    }
    if (!opts.internalPort) {
      return cb(new PortMapValidationError('internalPort required', 'internalPort'));
    }

    // 'any' hands the choice to the gateway from the start. RFC 6886 §9.4
    // makes the case: the gateway knows which ports are free and the client
    // does not, and against a gateway that pre-allocates port ranges a client
    // guessing upwards from 80 can need tens of thousands of attempts.
    var wanted = opts.onConflict === 'any' ? 0
               : (opts.externalPort === undefined ? opts.internalPort : opts.externalPort);

    var request = {
      protocol:     protocol,
      internalPort: opts.internalPort,
      externalPort: wanted,
      lifetime:     opts.lifetime === undefined ? context.lifetime : opts.lifetime,
      description:  opts.description || context.description,
      isRenewal:    !!opts.isRenewal,
      // "this port or nothing": no conflict retries, and AddPortMapping rather
      // than AddAnyPortMapping, since the latter exists precisely to substitute
      exact:        opts.exact === true || opts.onConflict === 'fail',
      onConflict:   opts.onConflict || 'increment',
      attempt:      0
    };

    attempt_map(request, cb);
  }


  function attempt_map(request, cb) {
    // IGD:2 can allocate a free external port itself, which removes the
    // guessing loop entirely (RFC 6886 §9.4) — but only if the gateway really
    // implements it. The advertised version is a claim, not a promise, so the
    // service description overrides it when we have read one.
    var use_add_any = context.igdVersion >= 2;
    if (context.service && context.service._scpd) {
      use_add_any = !!context.service._scpd.actions[soap.ACTION.ADD_ANY_PORT_MAPPING];
    }
    // AddAnyPortMapping is defined to substitute a free port, which is the
    // opposite of what an exact request wants
    if (request.exact) use_add_any = false;
    var action = use_add_any ? soap.ACTION.ADD_ANY_PORT_MAPPING : soap.ACTION.ADD_PORT_MAPPING;

    var lease = context.permanentLeasesOnly ? 0 : request.lifetime;
    // A gateway that silently raises or caps a lease would otherwise have us
    // renewing on a schedule derived from a number it never agreed to
    lease = quirks.clamp_lease(lease, context.quirkEffects);

    var args = {
      NewRemoteHost:             '',
      NewExternalPort:           request.externalPort,
      NewProtocol:               request.protocol.toUpperCase(),
      NewInternalPort:           request.internalPort,
      NewInternalClient:         context.localIp,
      NewEnabled:                true,
      NewPortMappingDescription: request.description,
      NewLeaseDuration:          lease
    };

    call(action, args, function(err, result) {
      if (!err) {
        // AddAnyPortMapping reports which port it actually reserved
        var granted = use_add_any && result && result.NewReservedPort
          ? parseInt(result.NewReservedPort, 10)
          : request.externalPort;
        return on_mapped(request, granted, lease, cb);
      }

      // 725: this gateway cannot do finite leases. Documented as common
      // enough that clients avoid non-zero leases entirely (RFC 6886 §9.5).
      // Downgrade once and remember, rather than failing.
      if (err.code === 725 && !context.permanentLeasesOnly) {
        context.permanentLeasesOnly = true;
        context.stats.leaseDowngrades++;
        ev.emit('warning',
          'Gateway only supports permanent leases — mappings will not expire on their ' +
          'own and must be deleted explicitly.');
        return attempt_map(request, cb);
      }

      if (err.retry === 'conflict') {
        if (request.exact) {
          // The caller said this port or nothing, so the conflict is the answer
          err.message = 'External port ' + request.externalPort +
                        ' is not available, and it was requested exactly';
          return cb(err);
        }
        return on_conflict(request, err, cb);
      }

      cb(err);
    });
  }


  function on_conflict(request, err, cb) {
    context.stats.conflicts++;

    // On IGD:1 a 718 may not be a conflict at all — RFC 6970 §4 maps a PCP
    // "not authorized" onto the same code. That is a reason to try fewer
    // ports, not to stop trying: on an ordinary IGD:1 gateway 718 really does
    // mean the port is taken, and giving up immediately would disable
    // conflict recovery on exactly the gateways that need it, since IGD:2
    // avoids the guessing game altogether with AddAnyPortMapping.
    var limit = err.ambiguous ? 1 : MAX_CONFLICT_RETRIES;
    if (err.ambiguous && request.attempt === 0) ev.emit('warning', err.note);

    if (request.attempt >= limit) {
      // Stop guessing and let the gateway pick, which is what it should have
      // been asked to do in the first place.
      if (request.externalPort !== 0) {
        request.externalPort = 0;
        request.attempt++;
        ev.emit('warning', 'External port contested — asking the gateway to choose one');
        return attempt_map(request, cb);
      }
      if (err.ambiguous && err.note) {
        err.message += ' — ' + err.note;
      }
      return cb(err);
    }

    request.attempt++;
    request.externalPort = request.externalPort + 1;
    ev.emit('conflict', { externalPort: request.externalPort, attempt: request.attempt });
    attempt_map(request, cb);
  }


  function on_mapped(request, external_port, lease, cb) {
    var now = Date.now();
    var key = mapping_key(request.protocol, external_port);

    var existing = context.mappings[key];
    var mapping = existing || {
      key:          key,
      protocol:     request.protocol,
      internalPort: request.internalPort,
      description:  request.description,
      exact:        request.exact,
      createdAt:    now,
      timer:        lifecycle.make_renewal_timer()
    };

    mapping.externalPort = external_port;
    mapping.externalIp   = context.externalIp;
    mapping.lifetime     = lease;
    mapping.state        = 'ACTIVE';
    mapping.renewedAt    = now;
    // A zero lease is permanent, so there is nothing to expire
    mapping.expiresAt    = lease ? now + lease * 1000 : null;

    context.mappings[key] = mapping;

    if (lease) {
      mapping.timer.arm(lease, function() { renew(mapping); });
    }

    if (request.isRenewal) {
      context.stats.renewals++;
      ev.emit('renewed', public_mapping(mapping));
    } else {
      context.stats.mappingsCreated++;
      ev.emit('mapped', public_mapping(mapping));
    }

    cb(null, public_mapping(mapping));
  }


  function renew(mapping) {
    if (context.state === 'destroyed') return;
    if (!context.mappings[mapping.key]) return;

    mapping.state = 'RENEWING';

    // On MiniUPnPd a repeated AddPortMapping reports success and leaves the
    // original expiry untouched, so a client that renews this way watches its
    // mapping expire exactly on schedule while every renewal looked fine.
    // Deleting first is the only way to actually extend it.
    if (context.quirkEffects.renewByRecreate) {
      return call(soap.ACTION.DELETE_PORT_MAPPING, {
        NewRemoteHost:   '',
        NewExternalPort: mapping.externalPort,
        NewProtocol:     mapping.protocol.toUpperCase()
      }, function() { do_renew(mapping); });
    }

    do_renew(mapping);
  }


  function do_renew(mapping) {
    map({
      protocol:     mapping.protocol,
      internalPort: mapping.internalPort,
      externalPort: mapping.externalPort,
      description:  mapping.description,
      isRenewal:    true,
      // A port asked for exactly must not drift to another one on renewal
      exact:        mapping.exact
    }, function(err) {
      if (!err) return;
      mapping.state = 'LOST';
      ev.emit('lost', public_mapping(mapping), err.message);
    });
  }


  function unmap(opts, cb) {
    if (typeof opts === 'number') opts = { externalPort: opts };
    opts = opts || {};
    cb = cb || function() {};

    var protocol = (opts.protocol || 'tcp').toLowerCase();
    var port = opts.externalPort;
    if (!port) return cb(new PortMapValidationError('externalPort required', 'externalPort'));

    var key = mapping_key(protocol, port);
    var mapping = context.mappings[key];
    if (mapping && mapping.timer) mapping.timer.cancel();

    call(soap.ACTION.DELETE_PORT_MAPPING, {
      NewRemoteHost:   '',
      NewExternalPort: port,
      NewProtocol:     protocol.toUpperCase()
    }, function(err) {
      // Deleting something that is already gone is a success as far as the
      // caller is concerned
      if (err && err.code !== 714) return cb(err);

      if (mapping) {
        delete context.mappings[key];
        mapping.state = 'CLOSED';
        ev.emit('unmapped', public_mapping(mapping));
      }
      cb(null, mapping ? public_mapping(mapping) : null);
    });
  }


  /* ================= Service description and eventing ================= */

  /**
   * Read a service's own description and remember what it implements.
   *
   * Called once per service, lazily. The result answers a question the device
   * description cannot: a gateway that says it is IGD:2 has not promised to
   * implement AddAnyPortMapping, and asking anyway costs a round trip and an
   * error. Knowing beforehand also lets a caller present real capabilities
   * rather than a version number.
   */
  function loadServiceDescription(service, cb) {
    service = service || context.service;
    if (!service) return cb(new PortMapProtocolError('No service to describe', null, 'upnp'));
    if (service._scpd) return cb(null, service._scpd);
    if (!service.scpdUrl) {
      return cb(new PortMapProtocolError(
        'This service publishes no SCPDURL, so its actions cannot be listed', null, 'upnp'));
    }

    context.http({ url: service.scpdUrl, method: 'GET', headers: {} }, function(err, res) {
      if (err) return cb(err);
      if (res.statusCode !== 200) {
        return cb(new PortMapProtocolError(
          'Service description fetch returned HTTP ' + res.statusCode, res.statusCode, 'upnp'));
      }
      var parsed;
      try { parsed = soap.parse_scpd(res.body); }
      catch (e) {
        return cb(new PortMapProtocolError(
          'Could not read the service description: ' + e.message, null, 'upnp'));
      }
      service._scpd = parsed;
      context.stats.descriptionsRead++;
      ev.emit('service-described', { type: service.type,
                                     actions: Object.keys(parsed.actions).length });
      cb(null, parsed);
    });
  }


  /** Does the connection service implement this action? */
  function supportsAction(action, cb) {
    loadServiceDescription(context.service, function(err, scpd) {
      // A gateway that will not describe itself is not evidence of absence,
      // so an unknown answer is null rather than false
      if (err) return cb(null, null);
      cb(null, !!scpd.actions[action]);
    });
  }


  /**
   * Subscribe to a service's evented state variables.
   *
   *   subscribe({ callbackUrl: 'http://192.168.1.42:8899/' }, cb)
   *
   * The gateway then POSTs a NOTIFY to that URL whenever something changes,
   * which for WANIPConnection includes ExternalIPAddress and
   * PortMappingNumberOfEntries. That is the closest UPnP gets to the
   * announcement NAT-PMP multicasts, and it is how a client learns its
   * external address changed without polling for it.
   *
   * The subscription expires, so it has to be renewed — the returned timeout
   * says when.
   */
  function subscribe(opts, cb) {
    opts = opts || {};
    cb = cb || function() {};

    if (context.state !== 'ready') {
      return cb(new PortMapStateError('Not ready — call discover() first', context.state));
    }
    if (!opts.callbackUrl) {
      return cb(new PortMapValidationError(
        'callbackUrl required — the gateway posts notifications to it', 'callbackUrl'));
    }

    var service = opts.service || context.service;
    if (!service.eventSubUrl) {
      return cb(new PortMapProtocolError(
        'This service publishes no eventSubURL, so it cannot be subscribed to',
        null, 'upnp'));
    }

    context.http({
      url:     service.eventSubUrl,
      method:  'SUBSCRIBE',
      headers: {
        // The angle brackets are part of the syntax, not decoration
        'CALLBACK': '<' + opts.callbackUrl + '>',
        'NT':       'upnp:event',
        'TIMEOUT':  'Second-' + (opts.timeout || 1800)
      }
    }, function(err, res) {
      if (err) return cb(err);
      if (res.statusCode !== 200) {
        return cb(new PortMapProtocolError(
          'SUBSCRIBE returned HTTP ' + res.statusCode, res.statusCode, 'upnp'));
      }

      var sid = res.headers && (res.headers.sid || res.headers.SID);
      if (!sid) {
        return cb(new PortMapProtocolError(
          'The gateway accepted the subscription but returned no SID', null, 'upnp'));
      }

      var timeout = soap.parse_timeout(res.headers.timeout || res.headers.TIMEOUT);
      var record = { sid: sid, timeout: timeout, service: service.type,
                     eventSubUrl: service.eventSubUrl };
      context.subscriptions[sid] = record;
      ev.emit('subscribed', record);
      cb(null, record);
    });
  }


  /** Extend a subscription before it lapses. Sends the SID and nothing else. */
  function renewSubscription(sid, opts, cb) {
    if (typeof opts === 'function') { cb = opts; opts = {}; }
    opts = opts || {};
    cb = cb || function() {};

    var record = context.subscriptions[sid];
    if (!record) return cb(new PortMapValidationError('Unknown subscription ' + sid, 'sid'));

    context.http({
      url:     record.eventSubUrl,
      method:  'SUBSCRIBE',
      // A renewal carries SID alone: sending NT or CALLBACK as well makes it a
      // new subscription request, which the gateway answers with 400
      headers: { 'SID': sid, 'TIMEOUT': 'Second-' + (opts.timeout || 1800) }
    }, function(err, res) {
      if (err) return cb(err);
      if (res.statusCode !== 200) {
        delete context.subscriptions[sid];
        return cb(new PortMapProtocolError(
          'Subscription renewal returned HTTP ' + res.statusCode, res.statusCode, 'upnp'));
      }
      record.timeout = soap.parse_timeout(res.headers.timeout || res.headers.TIMEOUT);
      cb(null, record);
    });
  }


  function unsubscribe(sid, cb) {
    cb = cb || function() {};
    var record = context.subscriptions[sid];
    if (!record) return cb(null);

    context.http({
      url: record.eventSubUrl, method: 'UNSUBSCRIBE', headers: { 'SID': sid }
    }, function(err) {
      delete context.subscriptions[sid];
      ev.emit('unsubscribed', record);
      cb(err || null);
    });
  }


  /**
   * Feed an incoming NOTIFY here. The transport receives it, since the gateway
   * posts to a URL the caller chose.
   */
  function handle_notify(headers, body) {
    var sid = headers && (headers.sid || headers.SID);

    // The sequence number is per subscription and increments by one. A gap
    // means a notification was lost, and since each one carries only the
    // variables that changed, the local picture is now missing something —
    // the only correct response is to re-read the state rather than carry on
    // believing a partial view.
    var seq = headers && (headers.seq || headers.SEQ);
    if (sid && seq !== undefined) {
      var record = context.subscriptions[sid];
      var n = parseInt(seq, 10);
      if (record && !isNaN(n)) {
        // Sequence 0 is the initial event, which restates everything
        if (n !== 0 && record.lastSeq !== undefined && n !== record.lastSeq + 1) {
          context.stats.eventsMissed += Math.max(0, n - record.lastSeq - 1);
          ev.emit('events-missed', {
            sid: sid, expected: record.lastSeq + 1, received: n,
            note: 'A notification was lost, so some state change was not seen.'
          });
        }
        record.lastSeq = n;
      }
    }

    var properties;
    try { properties = soap.parse_property_set(body); }
    catch (e) {
      ev.emit('warning', 'Unreadable event notification: ' + e.message);
      return null;
    }

    context.stats.eventsReceived++;

    if (properties.ExternalIPAddress && properties.ExternalIPAddress !== context.externalIp) {
      var previous = context.externalIp;
      context.externalIp = properties.ExternalIPAddress;
      // The mappings still exist, but every address a caller recorded is now
      // wrong — the same situation a NAT-PMP announcement signals
      ev.emit('external-ip-changed', { from: previous, to: context.externalIp });
    }

    ev.emit('event', { sid: sid, properties: properties });
    return properties;
  }


  function getSubscriptions() {
    return Object.keys(context.subscriptions).map(function(k) {
      return Object.assign({}, context.subscriptions[k]);
    });
  }


  /* ====================== Gateway information ====================== */

  /**
   * Whether the device is routing at all. A gateway in IP_Bridged mode will
   * accept a mapping and do nothing with it, because it is not the thing
   * performing translation.
   */
  function getConnectionType(cb) {
    call(soap.ACTION.GET_CONNECTION_TYPE, {}, function(err, args) {
      if (err) return cb(err);
      cb(null, soap.parse_connection_type(args));
    });
  }


  /** How many mappings the gateway holds. Not implemented by every device. */
  function getMappingCount(cb) {
    call(soap.ACTION.GET_MAPPING_COUNT, {}, function(err, args) {
      if (err) return cb(err);
      var n = parseInt(args.NewPortMappingNumberOfEntries, 10);
      cb(null, isNaN(n) ? null : n);
    });
  }


  /** Link type, speed and physical status, from WANCommonInterfaceConfig. */
  function getLinkProperties(cb) {
    call_service(context.common, 'WANCommonInterfaceConfig',
                 soap.ACTION.GET_COMMON_LINK_PROPERTIES, {}, function(err, args) {
      if (err) return cb(err);
      cb(null, soap.parse_link_properties(args));
    });
  }


  /**
   * Traffic counters. All four are ui4 and wrap at roughly 4 GB, so they are a
   * liveness signal rather than an accounting record; a gateway that is not
   * implementing one of them answers 401 and it comes back null.
   */
  function getTrafficCounters(cb) {
    var out = { bytesSent: null, bytesReceived: null,
                packetsSent: null, packetsReceived: null };

    var jobs = [
      ['bytesSent',       soap.ACTION.GET_TOTAL_BYTES_SENT,       'NewTotalBytesSent'],
      ['bytesReceived',   soap.ACTION.GET_TOTAL_BYTES_RECEIVED,   'NewTotalBytesReceived'],
      ['packetsSent',     soap.ACTION.GET_TOTAL_PACKETS_SENT,     'NewTotalPacketsSent'],
      ['packetsReceived', soap.ACTION.GET_TOTAL_PACKETS_RECEIVED, 'NewTotalPacketsReceived']
    ];

    function step(i) {
      if (i >= jobs.length) return cb(null, out);
      var job = jobs[i];
      call_service(context.common, 'WANCommonInterfaceConfig', job[1], {}, function(err, args) {
        if (!err && args) {
          var n = parseInt(args[job[2]], 10);
          if (!isNaN(n)) out[job[0]] = n;
        }
        setImmediate(function() { step(i + 1); });
      });
    }

    if (!context.common) {
      return cb(new PortMapProtocolError(
        'This gateway exposes no WANCommonInterfaceConfig service', null, 'upnp'));
    }
    step(0);
  }


  /**
   * Check that a mapping is still in place, without changing anything.
   *
   * A successful renewal is not proof. Some gateways reclaim a mapping that
   * has carried no traffic and answer the next AddPortMapping cheerfully,
   * because from their side it is a new mapping; and on MiniUPnPd a repeated
   * AddPortMapping reports success while leaving the original expiry alone.
   * In both cases the client believes it holds something it does not.
   *
   * GetSpecificPortMappingEntry asks rather than asserts, which is the only
   * way to tell the two apart. 714 NoSuchEntryInArray is the answer that
   * matters: the mapping is gone.
   */
  function verify(opts, cb) {
    opts = opts || {};
    cb = cb || function() {};

    var protocol = (opts.protocol || 'tcp').toLowerCase();
    var port = opts.externalPort;
    if (!port) return cb(new PortMapValidationError('externalPort required', 'externalPort'));

    call(soap.ACTION.GET_SPECIFIC_MAPPING, {
      NewRemoteHost:   opts.remoteHost || '',
      NewExternalPort: port,
      NewProtocol:     protocol.toUpperCase()
    }, function(err, args) {
      if (err) {
        if (err.code === 714) {
          return cb(null, { present: false, reason: 'the gateway has no such entry' });
        }
        // A gateway that will not answer is not evidence either way
        return cb(null, { present: null, reason: err.message });
      }

      var internal_ip = args.NewInternalClient || null;
      var mine = !opts.internalIp || internal_ip === opts.internalIp;

      cb(null, {
        present:      mine,
        internalIp:   internal_ip,
        internalPort: parseInt(args.NewInternalPort, 10) || null,
        leaseDuration: parseInt(args.NewLeaseDuration, 10),
        description:  args.NewPortMappingDescription || '',
        // The port exists but now belongs to somebody else, which is not the
        // same as it being gone and needs a different response
        stolen:       !mine,
        reason:       mine ? null : 'the port now maps to ' + internal_ip
      });
    });
  }


  /* ========================= IPv6 pinholes ========================= */

  /**
   * Whether pinholes can be opened at all. Both flags must be true: a firewall
   * that is switched off has nothing to pierce, and one that forbids inbound
   * pinholes will refuse every AddPinhole with 703.
   */
  function getFirewallStatus(cb) {
    call_firewall(soap.ACTION.GET_FIREWALL_STATUS, {}, function(err, args) {
      if (err) return cb(err);
      cb(null, soap.parse_firewall_status(args));
    });
  }


  /**
   * Open an inbound IPv6 pinhole.
   *
   *   addPinhole({ internalIp, internalPort, protocol, remoteHost, remotePort, lifetime })
   *
   * Unlike a NAT mapping this performs no translation: the internal address is
   * already globally routable, and the firewall is simply told to let traffic
   * through. RemoteHost and RemotePort may be left out to accept any source,
   * which the service spells as the empty string and port 0.
   *
   * Returns { uniqueId, ... }; uniqueId is what update and delete address.
   */
  function addPinhole(opts, cb) {
    opts = opts || {};
    cb = cb || function() {};

    var internal = opts.internalIp || context.localIp;
    if (!opts.internalPort && opts.internalPort !== 0) {
      return cb(new PortMapValidationError('internalPort required', 'internalPort'));
    }

    var args = {
      RemoteHost:     opts.remoteHost || '',
      RemotePort:     opts.remotePort || 0,
      InternalClient: internal,
      InternalPort:   opts.internalPort,
      Protocol:       soap.protocol_number(opts.protocol === undefined ? 'any' : opts.protocol),
      LeaseTime:      opts.lifetime === undefined ? context.lifetime : opts.lifetime
    };

    call_firewall(soap.ACTION.ADD_PINHOLE, args, function(err, result) {
      if (err) return cb(err);

      var pinhole = soap.parse_pinhole(result, args);
      context.pinholes[pinhole.uniqueId] = pinhole;
      context.stats.pinholesCreated++;
      ev.emit('pinhole', pinhole);
      cb(null, pinhole);
    });
  }


  /**
   * Extend an existing pinhole's lease. The service also extends it
   * implicitly when AddPinhole repeats an identical five-tuple with a
   * different lease time, but addressing it by id is unambiguous.
   */
  function updatePinhole(unique_id, lease_time, cb) {
    cb = cb || function() {};
    call_firewall(soap.ACTION.UPDATE_PINHOLE, {
      UniqueID:     unique_id,
      NewLeaseTime: lease_time
    }, function(err) {
      if (err) return cb(err);
      var p = context.pinholes[unique_id];
      if (p) p.leaseTime = lease_time;
      cb(null, p || null);
    });
  }


  function deletePinhole(unique_id, cb) {
    cb = cb || function() {};
    call_firewall(soap.ACTION.DELETE_PINHOLE, { UniqueID: unique_id }, function(err) {
      // Deleting something already gone is a success from the caller's view
      if (err && err.code !== 704) return cb(err);
      var p = context.pinholes[unique_id];
      delete context.pinholes[unique_id];
      if (p) ev.emit('pinhole-closed', p);
      cb(null, p || null);
    });
  }


  /** How many packets have traversed a pinhole — useful to prove it works. */
  function getPinholePackets(unique_id, cb) {
    call_firewall(soap.ACTION.GET_PINHOLE_PACKETS, { UniqueID: unique_id }, function(err, args) {
      if (err) return cb(err);
      var n = parseInt(args.PinholePackets, 10);
      cb(null, { uniqueId: unique_id, packets: isNaN(n) ? null : n });
    });
  }


  /**
   * Whether the pinhole is still in place and has carried traffic. A 709
   * NoPacketSent answer means the pinhole exists but nothing has used it yet,
   * which is not a failure.
   */
  function checkPinholeWorking(unique_id, cb) {
    call_firewall(soap.ACTION.CHECK_PINHOLE_WORKING, { UniqueID: unique_id }, function(err, args) {
      if (err) {
        if (err.code === 709) return cb(null, { uniqueId: unique_id, working: false, reason: 'no packets yet' });
        return cb(err);
      }
      cb(null, {
        uniqueId: unique_id,
        working:  args.IsWorking === '1' || args.IsWorking === 'true'
      });
    });
  }


  /**
   * How long an automatic outbound pinhole would last for this five-tuple.
   * Lets a caller decide whether an explicit inbound pinhole is needed at all,
   * since most gateways open one automatically when outbound traffic starts.
   */
  function getOutboundPinholeTimeout(opts, cb) {
    opts = opts || {};
    call_firewall(soap.ACTION.GET_OUTBOUND_PINHOLE_TIMEOUT, {
      RemoteHost:     opts.remoteHost || '',
      RemotePort:     opts.remotePort || 0,
      InternalClient: opts.internalIp || context.localIp,
      InternalPort:   opts.internalPort || 0,
      Protocol:       soap.protocol_number(opts.protocol === undefined ? 'any' : opts.protocol)
    }, function(err, args) {
      if (err) return cb(err);
      var n = parseInt(args.OutboundPinholeTimeout, 10);
      cb(null, { timeout: isNaN(n) ? null : n });
    });
  }


  function getPinholes() {
    var out = [];
    var keys = Object.keys(context.pinholes);
    for (var i = 0; i < keys.length; i++) out.push(context.pinholes[keys[i]]);
    return out;
  }


  /* ===================== IGD:2 bulk mapping actions ===================== */

  /**
   * Read the mapping table in one call instead of walking it index by index.
   * IGD:2 only; the result is an XML document nested inside the SOAP
   * response, so it arrives escaped and is parsed a second time.
   */
  function getListOfPortMappings(opts, cb) {
    if (typeof opts === 'function') { cb = opts; opts = {}; }
    opts = opts || {};

    if (context.igdVersion < 2) {
      return cb(new PortMapProtocolError(
        'GetListOfPortMappings is IGD:2 only — use getRouterMappings(), which ' +
        'walks the table one entry at a time and works on IGD:1', null, 'upnp'));
    }

    call(soap.ACTION.GET_LIST_OF_MAPPINGS, {
      NewStartPort:     opts.startPort === undefined ? 0 : opts.startPort,
      NewEndPort:       opts.endPort === undefined ? 65535 : opts.endPort,
      NewProtocol:      (opts.protocol || 'tcp').toUpperCase(),
      // false: only our own mappings; true: everything, which usually needs
      // an authorised control point
      NewManage:        opts.manage ? 1 : 0,
      NewNumberOfPorts: opts.limit === undefined ? 0 : opts.limit
    }, function(err, args) {
      if (err) return cb(err);
      var list;
      try { list = soap.parse_port_listing(args.NewPortListing); }
      catch (e) { return cb(new PortMapProtocolError(e.message, null, 'upnp')); }
      cb(null, list);
    });
  }


  /** Delete every mapping in a port range. IGD:2 only. */
  function deletePortMappingRange(opts, cb) {
    opts = opts || {};
    cb = cb || function() {};

    if (context.igdVersion < 2) {
      return cb(new PortMapProtocolError(
        'DeletePortMappingRange is IGD:2 only', null, 'upnp'));
    }
    if (!opts.startPort || !opts.endPort) {
      return cb(new PortMapValidationError('startPort and endPort required', 'startPort'));
    }

    call(soap.ACTION.DELETE_MAPPING_RANGE, {
      NewStartPort: opts.startPort,
      NewEndPort:   opts.endPort,
      NewProtocol:  (opts.protocol || 'tcp').toUpperCase(),
      NewManage:    opts.manage ? 1 : 0
    }, function(err) {
      if (err && err.code !== 714) return cb(err);
      cb(null);
    });
  }


  /**
   * Delete mappings left behind by earlier runs of this application.
   *
   * Deleting someone else's mapping is worse than leaving a stale one, so
   * every filter here is a reason NOT to delete, and a candidate has to clear
   * all of them:
   *
   *   1. the description must match exactly. Set `description` to something
   *      identifying the application — the default is the library name, which
   *      is too broad to be safe if two different programs both use it.
   *   2. the internal address must be ours. Another host's mapping is never
   *      ours to remove, whatever it is called.
   *   3. it must not be one this session is currently maintaining.
   *   4. it must not still be live. A mapping with a running lease belongs to
   *      something that is still renewing it — quite possibly a second copy of
   *      this same application on this same machine — so only permanent
   *      entries, which cannot expire on their own, are considered abandoned.
   *
   * Rule 4 is the one that makes this safe to call at startup. Without it,
   * launching an app twice would have the second copy delete the first
   * copy's mapping.
   *
   * `dryRun: true` returns what would be deleted without touching anything.
   */
  function cleanup(opts, cb) {
    if (typeof opts === 'function') { cb = opts; opts = {}; }
    opts = opts || {};
    cb = cb || function() {};

    var wanted = opts.description === undefined ? context.description : opts.description;
    var mine = context.localIp;

    if (!wanted && opts.anyDescription !== true) {
      return cb(new PortMapValidationError(
        'cleanup() needs a description to match on, or anyDescription:true to ' +
        'delete every mapping this host owns', 'description'));
    }

    getRouterMappings(function(err, list) {
      if (err) return cb(err);

      var skipped = [];
      var stale = list.filter(function(e) {
        if (wanted && e.description !== wanted) return false;
        if (opts.anyHost !== true && e.internalIp !== mine) return false;
        if (context.mappings[mapping_key(e.protocol, e.externalPort)]) return false;

        // A live lease means something is still renewing this
        if (e.leaseDuration && opts.includeLeased !== true) {
          skipped.push(e);
          return false;
        }
        return true;
      });

      if (opts.dryRun) return cb(null, stale, skipped);

      var removed = [];
      function step(i) {
        if (i >= stale.length) return cb(null, removed, skipped);
        var e = stale[i];
        call(soap.ACTION.DELETE_PORT_MAPPING, {
          NewRemoteHost:   e.remoteHost || '',
          NewExternalPort: e.externalPort,
          NewProtocol:     e.protocol.toUpperCase()
        }, function(err2) {
          if (!err2 || err2.code === 714) {
            removed.push(e);
            context.stats.staleRemoved++;
            ev.emit('stale-removed', e);
          }
          setImmediate(function() { step(i + 1); });
        });
      }
      step(0);
    });
  }


  /**
   * Walk the gateway's whole mapping table. IGD:1 has no list action, so the
   * entries are read one index at a time until the gateway answers 713
   * SpecifiedArrayIndexInvalid, which is the documented end-of-array marker
   * rather than a failure.
   */
  function getRouterMappings(cb) {
    var out = [];
    var index = 0;
    var limit = 1000;    // a gateway that never returns 713 must not hang us

    function step() {
      if (index >= limit) return cb(null, out);

      call(soap.ACTION.GET_GENERIC_MAPPING, { NewPortMappingIndex: index }, function(err, args) {
        if (err) {
          if (err.code === 713 || err.code === 714) return cb(null, out);
          return cb(err, out);
        }
        var entry = soap.parse_mapping_entry(args);
        if (entry) out.push(entry);
        index++;
        // Deferred rather than called directly: this walks once per entry, and
        // a transport that answers synchronously would turn the walk into
        // recursion as deep as the table is long
        setImmediate(step);
      });
    }

    step();
  }


  /* ============================ Accessors ============================ */

  function public_mapping(m) {
    return {
      protocol:     m.protocol,
      internalPort: m.internalPort,
      externalPort: m.externalPort,
      internalIp:   context.localIp,
      externalIp:   m.externalIp,
      lifetime:     m.lifetime,
      permanent:    m.lifetime === 0,
      via:          'upnp',
      state:        m.state,
      description:  m.description,
      createdAt:    new Date(m.createdAt),
      renewedAt:    m.renewedAt ? new Date(m.renewedAt) : null,
      expiresAt:    m.expiresAt ? new Date(m.expiresAt) : null
    };
  }


  function getMappings() {
    var out = [];
    var keys = Object.keys(context.mappings);
    for (var i = 0; i < keys.length; i++) out.push(public_mapping(context.mappings[keys[i]]));
    return out;
  }


  function getDevice() {
    if (!context.device) return null;
    return {
      friendlyName: context.device.friendlyName,
      manufacturer: context.device.manufacturer,
      modelName:    context.device.modelName,
      udn:          context.device.udn,
      igdVersion:   context.igdVersion,
      serviceType:  context.service.type,
      controlUrl:   context.service.controlUrl,
      firewallControlUrl: context.firewall ? context.firewall.controlUrl : null,
      supportsPinholes:   !!context.firewall,
      supportsStatistics: !!context.common,
      permanentLeasesOnly: context.permanentLeasesOnly
    };
  }


  function getStats() { return Object.assign({}, context.stats); }

  function getConfig() {
    return {
      localIp:   context.localIp,
      gateway:   context.gateway,
      lifetime:  context.lifetime,
      externalIp: context.externalIp,
      igdVersion: context.igdVersion
    };
  }


  /* ============================ Lifecycle ============================ */

  function destroy() {
    if (context.state === 'destroyed') return;
    context.state = 'destroyed';

    clear_search_timer();
    var keys = Object.keys(context.mappings);
    for (var i = 0; i < keys.length; i++) {
      if (context.mappings[keys[i]].timer) context.mappings[keys[i]].timer.cancel();
    }

    ev.emit('destroyed');
    ev.removeAllListeners();
  }


  /* ================================ API ================================ */

  var api = {
    context: context,

    on:   function(name, fn) { ev.on(name, fn); },
    off:  function(name, fn) { ev.off(name, fn); },
    once: function(name, fn) { ev.once(name, fn); },

    process_packet: process_packet,
    discover: discover,
    getCandidates: getCandidates,

    map: map,
    unmap: unmap,
    getExternalIp: getExternalIp,
    getStatus: getStatus,
    getMappings: getMappings,
    getRouterMappings: getRouterMappings,
    getListOfPortMappings: getListOfPortMappings,
    deletePortMappingRange: deletePortMappingRange,
    cleanup: cleanup,

    loadServiceDescription: loadServiceDescription,
    supportsAction: supportsAction,
    subscribe: subscribe,
    renewSubscription: renewSubscription,
    unsubscribe: unsubscribe,
    handle_notify: handle_notify,
    getSubscriptions: getSubscriptions,

    getQuirks: function() {
      return context.quirks.map(function(q) {
        return { id: q.id, note: q.note, source: q.source, effects: q.effects };
      });
    },
    getQuirkEffects: function() { return Object.assign({}, context.quirkEffects); },

    verify: verify,

    getConnectionType: getConnectionType,
    getMappingCount: getMappingCount,
    getLinkProperties: getLinkProperties,
    getTrafficCounters: getTrafficCounters,

    getFirewallStatus: getFirewallStatus,
    addPinhole: addPinhole,
    updatePinhole: updatePinhole,
    deletePinhole: deletePinhole,
    getPinholePackets: getPinholePackets,
    checkPinholeWorking: checkPinholeWorking,
    getOutboundPinholeTimeout: getOutboundPinholeTimeout,
    getPinholes: getPinholes,
    getDevice: getDevice,
    getStats: getStats,
    getConfig: getConfig,

    call: call,
    destroy: destroy
  };

  for (var k in api) if (Object.prototype.hasOwnProperty.call(api, k)) this[k] = api[k];

  Object.defineProperty(this, 'state', {
    get: function() { return context.state; },
    enumerable: true
  });

  return this;
}


export default UPnPSession;
export { UPnPSession, MAX_CONFLICT_RETRIES };
