/**
 * pmp_server_session.js — PCP + NAT-PMP gateway protocol engine.
 *
 * The other half of pmp_session.js: this is what a router runs. Transport
 * agnostic in the same way — it emits 'packet' (buf, dest) and is fed inbound
 * datagrams through process_packet(buf, rinfo). No sockets, and it never
 * touches the kernel; turning an approved request into an actual forwarding
 * rule is the enforcement layer's job.
 *
 * Both dialects are served from one engine because RFC 6886 §1.1 says a
 * gateway should do exactly that: when a packet arrives, if the version is 2
 * it is handled as PCP and answered in PCP format, and if it is 0 the
 * existing NAT-PMP path handles it and answers in NAT-PMP format.
 *
 * Requests are approved through the same control object the DHCP server uses,
 * and the default policy is to refuse everything. A gateway that grants
 * whatever it is asked lets any program on the LAN — including a web page,
 * through DNS rebinding — expose any device to the internet.
 *
 * References:
 *   RFC 6886 §3.3 — the source address MUST be the internal address; the
 *                   companion TCP/UDP port MUST be reserved for that client
 *   RFC 6886 §3.4 — lifetime 0 deletes; deleting what does not exist succeeds
 *   RFC 6886 §3.5 — result codes and the two odd error response shapes
 *   RFC 6886 §3.6 — Seconds Since Start of Epoch resets on state loss
 *   RFC 6887 §8.1 — a client address that disagrees with the packet source
 *                   means a NAT is on the path: ADDRESS_MISMATCH
 */

import { EventEmitter } from 'node:events';
import * as wire from './wire.js';
import { safe_timeout, clear_safe_timeout } from './timers.js';
import { make_control, when_control_done, wrap_control_listener, remove_control_listener } from './control.js';
import { PortMapValidationError } from './errors.js';


function validate_options(opts) {
  if (opts.externalIp !== undefined && opts.externalIp !== null) {
    try { wire.encode_ip4(opts.externalIp); }
    catch (e) { throw new PortMapValidationError('externalIp invalid: ' + e.message, 'externalIp'); }
  }
  if (opts.maxLifetime !== undefined &&
      (typeof opts.maxLifetime !== 'number' || opts.maxLifetime < 0)) {
    throw new PortMapValidationError('maxLifetime must be a non-negative number', 'maxLifetime');
  }
  if (opts.policy !== undefined && opts.policy !== 'deny-all' && opts.policy !== 'allow-all') {
    throw new PortMapValidationError(
      'policy must be "deny-all" (default) or "allow-all"', 'policy');
  }
}


// Ports the gateway hands out when the requested one is unavailable, or when
// the client asks it to choose. Deliberately high and outside the registered
// range.
const DYNAMIC_PORT_MIN = 49152;
const DYNAMIC_PORT_MAX = 65535;


function PMPServerSession(options) {
  if (!(this instanceof PMPServerSession)) return new PMPServerSession(options);
  options = options || {};
  validate_options(options);

  var ev = new EventEmitter();
  ev.setMaxListeners(0);

  var context = {
    state: 'new',                // new | listening | destroyed

    externalIp:  options.externalIp || null,
    maxLifetime: options.maxLifetime === undefined ? 86400 : options.maxLifetime,
    minLifetime: options.minLifetime === undefined ? 120 : options.minLifetime,
    maxMappings: options.maxMappings === undefined ? 100 : options.maxMappings,
    maxPerClient: options.maxPerClient === undefined ? 20 : options.maxPerClient,

    // Refuse by default. Nothing is granted without a 'port-request' listener
    // calling control.allow(), or an explicit 'allow-all' policy.
    policy: options.policy || 'deny-all',

    // How long a handler may take before the session answers without it
    controlTimeout: options.controlTimeout || 5000,

    // §3.6 — seconds since the mapping table was initialised. Resetting this
    // is how clients are told every mapping is gone.
    epochStart: Date.now(),

    // 'tcp:8080' → mapping, keyed by external port
    mappings: Object.create(null),

    // Two indexes over the same entries. Without them every request scans the
    // whole table twice — once to find what this client already holds and once
    // to count its mappings — which makes creating n mappings cost O(n²). A
    // gateway with a few hundred is fine either way; one with thousands is not.
    byInternal: Object.create(null),   // 'ip|tcp|8080' → entry
    byClient:   Object.create(null),   // ip → count
    // Object.keys().length is itself O(n), so counting the table on every
    // request would have reintroduced exactly the cost the indexes removed
    count:      0,

    stats: {
      packetsReceived:   0,
      malformedPackets:  0,
      pcpRequests:       0,
      natpmpRequests:    0,
      responsesIgnored:  0,
      mappingsCreated:   0,
      mappingsRenewed:   0,
      mappingsDeleted:   0,
      requestsRejected:  0,
      addressMismatches: 0,
      poolExhausted:     0
    }
  };


  function epoch() {
    return Math.floor((Date.now() - context.epochStart) / 1000);
  }


  function key_of(protocol, external_port) {
    return protocol + ':' + external_port;
  }

  function internal_key(client, protocol, internal_port) {
    return client + '|' + protocol + '|' + internal_port;
  }

  function index_add(entry) {
    context.byInternal[internal_key(entry.internalIp, entry.protocol, entry.internalPort)] = entry;
    context.byClient[entry.internalIp] = (context.byClient[entry.internalIp] || 0) + 1;
    context.count++;
  }

  function index_remove(entry) {
    delete context.byInternal[internal_key(entry.internalIp, entry.protocol, entry.internalPort)];
    var n = (context.byClient[entry.internalIp] || 1) - 1;
    if (n <= 0) delete context.byClient[entry.internalIp];
    else context.byClient[entry.internalIp] = n;
    context.count--;
  }


  function emit_packet(buf, dest) {
    ev.emit('packet', buf, dest);
  }


  /* ========================= Control object ========================= */

  /**
   * The control object, the waiting on asynchronous handlers, and the arity
   * check that arranges it all live in control.js — the same three pieces are
   * needed by both gateway engines and by the transport above them, and they
   * have to behave identically or a policy written once would mean different
   * things depending on which protocol the request arrived by.
   */
  function control_for(proposed, ttl) { return make_control(proposed, ttl); }

  function await_control(control, cb) {
    when_control_done(control, context.controlTimeout, function(message) {
      ev.emit('warning', message);
    }, cb);
  }



  /* ======================== Port allocation ======================== */

  function is_free(protocol, port, client) {
    var existing = context.mappings[key_of(protocol, port)];
    if (!existing) {
      // RFC 6886 §3.3 — while a client holds TCP port 80, another client with
      // a different internal address must not be able to take UDP port 80.
      var companion = context.mappings[key_of(protocol === 'tcp' ? 'udp' : 'tcp', port)];
      if (companion && companion.internalIp !== client) return false;
      return true;
    }
    return existing.internalIp === client;
  }


  /**
   * RFC 6886 §3.3 — the client normally asks for the external port matching
   * its internal one; if that is unavailable the gateway MUST return some
   * available external port if it can, and an error only when none is left.
   */
  function allocate_port(protocol, wanted, client) {
    if (wanted && is_free(protocol, wanted, client)) return wanted;

    var span = DYNAMIC_PORT_MAX - DYNAMIC_PORT_MIN + 1;
    var start = DYNAMIC_PORT_MIN + (Math.floor(Math.random() * span));
    for (var i = 0; i < span; i++) {
      var port = DYNAMIC_PORT_MIN + ((start - DYNAMIC_PORT_MIN + i) % span);
      if (is_free(protocol, port, client)) return port;
    }
    return null;
  }


  function count_for_client(client) {
    return context.byClient[client] || 0;
  }


  /* ========================== Mapping table ========================== */

  function store(entry) {
    var key = key_of(entry.protocol, entry.externalPort);
    var existing = context.mappings[key];

    if (existing) {
      if (existing.timer) clear_safe_timeout(existing.timer);
      // The internal port is part of the index key, so a change has to move it
      if (existing.internalPort !== entry.internalPort) index_remove(existing);
      existing.internalPort = entry.internalPort;
      existing.lifetime     = entry.lifetime;
      existing.renewedAt    = Date.now();
      existing.expiresAt    = entry.lifetime ? Date.now() + entry.lifetime * 1000 : null;
      existing.nonce        = entry.nonce || existing.nonce;
      if (!context.byInternal[internal_key(existing.internalIp, existing.protocol,
                                           existing.internalPort)]) index_add(existing);
      arm_expiry(existing);
      context.stats.mappingsRenewed++;
      ev.emit('port-renewed', public_mapping(existing));
      return existing;
    }

    entry.createdAt = Date.now();
    entry.renewedAt = entry.createdAt;
    entry.expiresAt = entry.lifetime ? entry.createdAt + entry.lifetime * 1000 : null;
    context.mappings[key] = entry;
    index_add(entry);
    arm_expiry(entry);
    context.stats.mappingsCreated++;
    ev.emit('port-mapped', public_mapping(entry));
    return entry;
  }


  function arm_expiry(entry) {
    if (!entry.lifetime) return;
    entry.timer = safe_timeout(function() {
      remove(entry.protocol, entry.externalPort, 'expired');
    }, entry.lifetime * 1000);
  }


  function remove(protocol, external_port, reason) {
    var key = key_of(protocol, external_port);
    var entry = context.mappings[key];
    if (!entry) return null;

    if (entry.timer) clear_safe_timeout(entry.timer);
    delete context.mappings[key];
    index_remove(entry);
    context.stats.mappingsDeleted++;
    ev.emit(reason === 'expired' ? 'port-expired' : 'port-unmapped',
            public_mapping(entry), reason);
    return entry;
  }


  /**
   * RFC 6886 §3.4 — a client may clear all of its own mappings for one
   * protocol by sending a deletion with every port and the lifetime zero.
   */
  function remove_all_for(client, protocol) {
    var keys = Object.keys(context.mappings);
    var n = 0;
    for (var i = 0; i < keys.length; i++) {
      var entry = context.mappings[keys[i]];
      if (entry.internalIp !== client) continue;
      if (protocol && entry.protocol !== protocol) continue;
      remove(entry.protocol, entry.externalPort, 'client-request');
      n++;
    }
    return n;
  }


  function find_by_internal(client, protocol, internal_port) {
    return context.byInternal[internal_key(client, protocol, internal_port)] || null;
  }


  /* ========================== Request handling ========================== */

  function clamp_lifetime(requested) {
    if (!requested) return 0;
    if (requested > context.maxLifetime) return context.maxLifetime;
    if (requested < context.minLifetime) return context.minLifetime;
    return requested;
  }


  /**
   * The shared approval path for both dialects. `req` is already normalised;
   * `reply` is called with (resultCode, mapping) once a decision is made.
   */
  function decide(req, codes, reply) {
    // Deletion never needs approval: a client is only ever removing what it
    // owns, and RFC 6886 §3.4 requires deleting a nonexistent mapping to look
    // like a success so a lost acknowledgement can be retried safely.
    if (req.lifetime === 0) {
      if (!req.internalPort && !req.externalPort) {
        remove_all_for(req.internalIp, req.protocol);
        return reply(codes.SUCCESS, null);
      }
      var owned = find_by_internal(req.internalIp, req.protocol, req.internalPort);
      if (owned) remove(owned.protocol, owned.externalPort, 'client-request');
      return reply(codes.SUCCESS, null);
    }

    // Idempotency: §3.3 requires a repeat request for an internal port the
    // client already holds to succeed with the port it was already given,
    // so that a lost acknowledgement can be retransmitted safely.
    var existing = find_by_internal(req.internalIp, req.protocol, req.internalPort);
    var proposed = existing ? existing.externalPort : req.externalPort;

    if (!existing) {
      if (context.count >= context.maxMappings) {
        context.stats.poolExhausted++;
        ev.emit('quota-exceeded', { scope: 'gateway', client: req.internalIp });
        return reply(codes.NO_RESOURCES, null);
      }
      if (count_for_client(req.internalIp) >= context.maxPerClient) {
        ev.emit('quota-exceeded', { scope: 'client', client: req.internalIp });
        return reply(codes.QUOTA, null);
      }
    }

    var control = control_for(proposed, context.maxLifetime);
    if (context.policy === 'allow-all') control.allow();

    ev.emit('port-request', req, control);

    await_control(control, function() {
      if (control._ignored) {
        context.stats.requestsRejected++;
        return reply(null, null);            // send nothing at all
      }
      if (control._rejected || !control._allowed) {
        context.stats.requestsRejected++;
        ev.emit('port-rejected', req);
        var code = typeof control._rejected === 'number' ? control._rejected : codes.NOT_AUTHORIZED;
        return reply(code, null);
      }

      var lifetime = clamp_lifetime(Math.min(req.lifetime, control.maxTtl || req.lifetime));
      var port = allocate_port(req.protocol, control.externalPort, req.internalIp);
      if (port === null) {
        context.stats.poolExhausted++;
        return reply(codes.NO_RESOURCES, null);
      }

      // The client moved to a different external port; drop the stale entry
      if (existing && existing.externalPort !== port) {
        remove(existing.protocol, existing.externalPort, 'reallocated');
      }

      var entry = store({
        protocol:     req.protocol,
        externalPort: port,
        internalIp:   req.internalIp,
        internalPort: req.internalPort,
        lifetime:     lifetime,
        nonce:        req.nonce || null,
        via:          req.via
      });

      reply(codes.SUCCESS, entry);
    });
  }


  /* ============================ NAT-PMP ============================ */

  var NATPMP_CODES = {
    SUCCESS:        wire.NATPMP_RESULT.SUCCESS,
    NOT_AUTHORIZED: wire.NATPMP_RESULT.NOT_AUTHORIZED,
    NO_RESOURCES:   wire.NATPMP_RESULT.OUT_OF_RESOURCES,
    QUOTA:          wire.NATPMP_RESULT.OUT_OF_RESOURCES
  };


  function handle_natpmp(buf, rinfo) {
    context.stats.natpmpRequests++;

    var msg;
    try { msg = wire.decode_natpmp_request(buf); }
    catch (e) {
      context.stats.malformedPackets++;
      ev.emit('warning', 'Malformed NAT-PMP request: ' + e.message);
      return;
    }

    // §3.5 — a response arriving at the server is not ours to answer
    if (msg.kind === 'response') { context.stats.responsesIgnored++; return; }

    if (msg.kind === 'unsupported-version') {
      return emit_packet(wire.encode_natpmp_unsupported_version(epoch()), rinfo);
    }

    if (msg.kind === 'unsupported-opcode') {
      return emit_packet(wire.encode_natpmp_unsupported_opcode(buf, epoch()), rinfo);
    }

    if (msg.kind === 'address') {
      return emit_packet(wire.encode_natpmp_address_response({
        resultCode: context.externalIp ? 0 : wire.NATPMP_RESULT.NETWORK_FAILURE,
        epoch:      epoch(),
        externalIp: context.externalIp
      }), rinfo);
    }

    // §3.3 — the source address of the packet MUST be used as the internal
    // address. The protocol deliberately gives the client no way to map on
    // another device's behalf.
    var req = {
      via:          'natpmp',
      protocol:     msg.protocol,
      internalIp:   rinfo.address,
      internalPort: msg.internalPort,
      externalPort: msg.externalPort,
      lifetime:     msg.lifetime,
      remote:       rinfo
    };

    decide(req, NATPMP_CODES, function(code, entry) {
      if (code === null) return;               // control.ignore()
      emit_packet(wire.encode_natpmp_map_response({
        protocol:     req.protocol,
        resultCode:   code,
        epoch:        epoch(),
        // §3.5 — the internal port is echoed even on failure, because it is
        // how the client identifies which request failed
        internalPort: req.internalPort,
        externalPort: entry ? entry.externalPort : 0,
        lifetime:     entry ? entry.lifetime : 0
      }), rinfo);
    });
  }


  /* ============================== PCP ============================== */

  var PCP_CODES = {
    SUCCESS:        wire.PCP_RESULT.SUCCESS,
    NOT_AUTHORIZED: wire.PCP_RESULT.NOT_AUTHORIZED,
    NO_RESOURCES:   wire.PCP_RESULT.NO_RESOURCES,
    QUOTA:          wire.PCP_RESULT.USER_EX_QUOTA
  };


  function handle_pcp(buf, rinfo) {
    context.stats.pcpRequests++;

    var msg;
    try { msg = wire.decode_pcp_request(buf); }
    catch (e) {
      context.stats.malformedPackets++;
      ev.emit('warning', 'Malformed PCP request: ' + e.message);
      return;
    }

    if (msg.kind === 'response') { context.stats.responsesIgnored++; return; }

    if (msg.kind === 'unsupported-version') {
      return emit_packet(wire.encode_pcp_response({
        opcode:     msg.opcode,
        resultCode: wire.PCP_RESULT.UNSUPP_VERSION,
        lifetime:   0,
        epoch:      epoch()
      }), rinfo);
    }

    if (msg.kind === 'announce') {
      return emit_packet(wire.encode_pcp_response({
        opcode:     wire.PCP_OP.ANNOUNCE,
        resultCode: wire.PCP_RESULT.SUCCESS,
        lifetime:   0,
        epoch:      epoch()
      }), rinfo);
    }

    if (msg.kind === 'unsupported-opcode') {
      return emit_packet(wire.encode_pcp_response({
        opcode:     msg.opcode,
        resultCode: wire.PCP_RESULT.UNSUPP_OPCODE,
        lifetime:   0,
        epoch:      epoch()
      }), rinfo);
    }

    // RFC 6887 §8.1 — the client wrote its own address into the request. If it
    // disagrees with where the packet actually came from, a NAT sits between
    // us, and any mapping made here would be for the wrong host.
    if (msg.clientIp !== rinfo.address) {
      context.stats.addressMismatches++;
      ev.emit('address-mismatch', { claimed: msg.clientIp, actual: rinfo.address });
      return emit_packet(wire.encode_pcp_response({
        opcode:     wire.PCP_OP.MAP,
        resultCode: wire.PCP_RESULT.ADDRESS_MISMATCH,
        lifetime:   0,
        epoch:      epoch(),
        nonce:      msg.nonce,
        protocol:   msg.protocol,
        internalPort: msg.internalPort
      }), rinfo);
    }

    var req = {
      via:          'pcp',
      protocol:     msg.protocol === 'all' ? 'tcp' : msg.protocol,
      internalIp:   rinfo.address,
      internalPort: msg.internalPort,
      externalPort: msg.externalPort,
      lifetime:     msg.lifetime,
      nonce:        msg.nonce,
      remote:       rinfo
    };

    decide(req, PCP_CODES, function(code, entry) {
      if (code === null) return;
      emit_packet(wire.encode_pcp_response({
        opcode:       wire.PCP_OP.MAP,
        resultCode:   code,
        lifetime:     entry ? entry.lifetime : 0,
        epoch:        epoch(),
        nonce:        msg.nonce,
        protocol:     req.protocol,
        internalPort: req.internalPort,
        externalPort: entry ? entry.externalPort : 0,
        externalIp:   context.externalIp || '::'
      }), rinfo);
    });
  }


  /* ========================= Inbound packets ========================= */

  function process_packet(buf, rinfo) {
    if (context.state === 'destroyed') return;
    context.stats.packetsReceived++;

    var proto = wire.detect_protocol(buf);
    if (!proto) {
      context.stats.malformedPackets++;
      // §1.1 — an unrecognised version is answered as NAT-PMP would answer it,
      // since that is the older and more widely understood of the two
      return emit_packet(wire.encode_natpmp_unsupported_version(epoch()), rinfo);
    }

    if (proto === 'pcp') return handle_pcp(buf, rinfo);
    handle_natpmp(buf, rinfo);
  }


  /* ========================== Announcements ========================== */

  /**
   * RFC 6886 §3.2.1 — on boot, on acquiring or changing the external address,
   * or on any other event that may mean mapping state was lost, the gateway
   * multicasts a gratuitous address response. To survive packet loss it sends
   * ten of them, the first two 250 ms apart and each interval doubling; the
   * epoch field is updated on every transmission so clients do not read the
   * series as a fresh restart.
   *
   * Both dialects are announced. A client tracks the epoch separately for
   * each, because the two protocols define different validity tests, so a
   * PCP client would never see a NAT-PMP announcement — it would keep its
   * mappings for another half-lifetime without knowing they were gone. RFC
   * 6887 §14.1.3 defines the unsolicited ANNOUNCE for exactly this.
   */
  function announce() {
    var attempt = 0;
    var timer = null;

    function send() {
      if (context.state === 'destroyed') return;
      var now = epoch();

      emit_packet(wire.encode_natpmp_address_response({
        resultCode: 0,
        epoch:      now,
        externalIp: context.externalIp
      }), { address: wire.NATPMP_MULTICAST, port: wire.CLIENT_PORT });

      emit_packet(wire.encode_pcp_response({
        opcode:     wire.PCP_OP.ANNOUNCE,
        resultCode: wire.PCP_RESULT.SUCCESS,
        lifetime:   0,
        epoch:      now
      }), { address: wire.NATPMP_MULTICAST, port: wire.CLIENT_PORT });

      attempt++;
      if (attempt >= 10) return;
      timer = safe_timeout(send, 250 * Math.pow(2, attempt - 1));
    }

    send();
    return { cancel: function() { if (timer) clear_safe_timeout(timer); attempt = 10; } };
  }


  /**
   * Declare that every mapping is gone — a reboot, a configuration change, or
   * anything else that cleared the table. Resets the epoch, which is the
   * signal clients watch for, and re-announces.
   */
  function resetEpoch() {
    var keys = Object.keys(context.mappings);
    for (var i = 0; i < keys.length; i++) {
      var entry = context.mappings[keys[i]];
      if (entry.timer) clear_safe_timeout(entry.timer);
    }
    context.mappings = Object.create(null);
    context.byInternal = Object.create(null);
    context.byClient = Object.create(null);
    context.count = 0;
    context.epochStart = Date.now();
    ev.emit('epoch-reset');
    announce();
  }


  function setExternalIp(ip) {
    if (ip === context.externalIp) return;
    context.externalIp = ip;
    ev.emit('external-ip', ip);
    // §3.2.1 — a changed external address is one of the events that must be
    // announced, because every client's recorded address is now wrong
    announce();
  }


  /* ============================ Accessors ============================ */

  function public_mapping(m) {
    return {
      protocol:     m.protocol,
      externalPort: m.externalPort,
      internalIp:   m.internalIp,
      internalPort: m.internalPort,
      lifetime:     m.lifetime,
      via:          m.via,
      nonceHex:     m.nonce ? wire.nonce_to_hex(m.nonce) : null,
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


  function revoke(protocol, external_port) {
    var entry = remove(protocol, external_port, 'revoked');
    return entry ? public_mapping(entry) : null;
  }


  function getStats() { return Object.assign({}, context.stats); }

  function getConfig() {
    return {
      externalIp:  context.externalIp,
      policy:      context.policy,
      maxLifetime: context.maxLifetime,
      minLifetime: context.minLifetime,
      maxMappings: context.maxMappings,
      maxPerClient: context.maxPerClient,
      epoch:       epoch()
    };
  }


  /* ============================ Lifecycle ============================ */

  function listening() {
    if (context.state === 'destroyed') return;
    context.state = 'listening';
    context.epochStart = Date.now();
    ev.emit('listening');
    // §3.2.1 — announce on boot
    announce();
  }


  function destroy() {
    if (context.state === 'destroyed') return;
    context.state = 'destroyed';

    var keys = Object.keys(context.mappings);
    for (var i = 0; i < keys.length; i++) {
      var entry = context.mappings[keys[i]];
      if (entry.timer) clear_safe_timeout(entry.timer);
    }
    context.mappings = Object.create(null);
    context.byInternal = Object.create(null);
    context.byClient = Object.create(null);
    context.count = 0;

    ev.emit('destroyed');
    ev.removeAllListeners();
  }


  /* ================================ API ================================ */

  var api = {
    context: context,

    on: function(name, fn) {
      ev.on(name, name === 'port-request' ? wrap_control_listener(fn) : fn);
    },
    once: function(name, fn) {
      ev.once(name, name === 'port-request' ? wrap_control_listener(fn) : fn);
    },
    off: function(name, fn) { remove_control_listener(ev, name, fn); },

    process_packet: process_packet,
    listening: listening,

    announce: announce,
    resetEpoch: resetEpoch,
    setExternalIp: setExternalIp,

    getMappings: getMappings,
    revoke: revoke,
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


export default PMPServerSession;
export { PMPServerSession, DYNAMIC_PORT_MIN, DYNAMIC_PORT_MAX };
