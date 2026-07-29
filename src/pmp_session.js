/**
 * pmp_session.js — PCP + NAT-PMP client protocol engine.
 *
 * Transport-agnostic, same pattern as ServerSession/ClientSession: it emits
 * 'packet' (buf, dest) and is fed inbound datagrams via process_packet().
 * No sockets here.
 *
 * Both protocols live in one session on purpose. They share UDP port 5351,
 * the same gateway, the same retransmission schedule and the same serial
 * request queue; and RFC 6886 §1.1 requires the client to speak both at once:
 * always try PCP first, fall back to NAT-PMP only on an Unsupported Version
 * reply, and never remember the result — NAT firmware gets updated, so a
 * gateway that only speaks NAT-PMP today may speak PCP tomorrow. The fallback
 * therefore happens mid-transaction, which is why it cannot span two modules.
 *
 * References:
 *   RFC 6886 — NAT-PMP
 *   RFC 6887 — PCP
 *   RFC 6886 §3.1 — one request in flight at a time; gateways are small devices
 *   RFC 6886 §3.2 — discard responses whose source is not the gateway
 *   RFC 6886 §3.3 — renew with the port the gateway assigned, not the one asked for
 */

import { EventEmitter } from 'node:events';
import * as wire from './wire.js';
import * as lifecycle from './lifecycle.js';
import { safe_timeout, clear_safe_timeout } from './timers.js';
import { dbg } from './debug.js';
import {
  PortMapValidationError,
  PortMapProtocolError,
  PortMapTimeoutError,
  PortMapStateError
} from './errors.js';


function validate_options(opts) {
  if (!opts.gateway) {
    throw new PortMapValidationError('gateway (the router IP) required', 'gateway');
  }
  try { wire.encode_ip(opts.gateway); }
  catch (e) { throw new PortMapValidationError('gateway invalid: ' + e.message, 'gateway'); }

  if (!opts.clientIp) {
    throw new PortMapValidationError(
      'clientIp (our address on the LAN) required — PCP echoes it back to detect double NAT',
      'clientIp');
  }
  try { wire.encode_ip(opts.clientIp); }
  catch (e) { throw new PortMapValidationError('clientIp invalid: ' + e.message, 'clientIp'); }

  if (opts.protocols !== undefined) {
    if (!Array.isArray(opts.protocols) || opts.protocols.length === 0) {
      throw new PortMapValidationError('protocols must be a non-empty array', 'protocols');
    }
    for (var i = 0; i < opts.protocols.length; i++) {
      if (opts.protocols[i] !== 'pcp' && opts.protocols[i] !== 'natpmp') {
        throw new PortMapValidationError(
          'protocols may only contain "pcp" and "natpmp" — UPnP has its own session',
          'protocols');
      }
    }
  }

  if (opts.lifetime !== undefined) {
    if (typeof opts.lifetime !== 'number' || opts.lifetime < 0) {
      throw new PortMapValidationError('lifetime must be a non-negative number of seconds', 'lifetime');
    }
  }
}


/* ========================= Dialect dispatch ========================= */

/**
 * The only real differences between the two protocols, in one table.
 *
 * `matches` is the interesting one. PCP correlates a response to its request
 * by the 96-bit mapping nonce. NAT-PMP has no transaction identifier at all —
 * RFC 6886 §3.5 states the messages are deliberately idempotent and
 * self-describing, so correlation is by (opcode, internal port) instead.
 */
var DIALECT = {
  pcp: {
    name: 'pcp',

    encode_map: function(tx, ctx) {
      // RFC 6887 §13.2 — without the option a suggested port is a preference
      // the gateway may ignore; with it the request either gets that exact
      // port or fails. There is no third behaviour to fall back on, which is
      // why the caller has to say which one it wanted.
      var options = tx.exact ? [wire.pcp_option_prefer_failure()] : undefined;

      return wire.encode_pcp_map_request({
        nonce:        tx.nonce,
        protocol:     tx.protocol,
        internalPort: tx.internalPort,
        externalPort: tx.externalPort,
        lifetime:     tx.lifetime,
        clientIp:     ctx.clientIp,
        options:      options
      });
    },

    // PCP learns the external address as a side effect of MAP; there is no
    // standalone address opcode the way NAT-PMP has one.
    encode_address: null,

    // RFC 6887 §14.1 — ANNOUNCE with a zero lifetime is the cheapest possible
    // "are you there, and do you speak PCP?" question.
    encode_probe: function(tx, ctx) {
      return wire.encode_pcp_announce_request(ctx.clientIp);
    },

    decode: wire.decode_pcp_response,

    matches: function(tx, msg) {
      if (tx.kind === 'probe') return msg.opcode === wire.PCP_OP.ANNOUNCE;
      if (tx.kind !== 'map') return false;
      if (msg.opcode !== wire.PCP_OP.MAP) return false;
      if (!msg.nonce) return true;             // truncated error response
      return wire.nonce_equal(tx.nonce, msg.nonce);
    },

    is_unsupported_version: function(msg) {
      return msg.resultCode === wire.PCP_RESULT.UNSUPP_VERSION;
    },

    succeeded: function(msg) { return msg.resultCode === wire.PCP_RESULT.SUCCESS; },
    result_name: wire.pcp_result_name
  },

  natpmp: {
    name: 'natpmp',

    encode_map: function(tx) {
      return wire.encode_natpmp_map_request({
        protocol:     tx.protocol,
        internalPort: tx.internalPort,
        externalPort: tx.externalPort,
        lifetime:     tx.lifetime
      });
    },

    encode_address: function() {
      return wire.encode_natpmp_address_request();
    },

    // NAT-PMP has no announce opcode; asking for the external address is the
    // equivalent two-byte question.
    encode_probe: function() {
      return wire.encode_natpmp_address_request();
    },

    decode: wire.decode_natpmp_response,

    matches: function(tx, msg) {
      if (tx.kind === 'address' || tx.kind === 'probe') return msg.kind === 'address';
      if (msg.kind !== 'map') return false;
      // No transaction id exists — correlate on what the message describes
      if (msg.internalPort === undefined) return true;   // truncated error
      return msg.internalPort === tx.internalPort && msg.protocol === tx.protocol;
    },

    is_unsupported_version: function(msg) {
      return msg.resultCode === wire.NATPMP_RESULT.UNSUPPORTED_VERSION;
    },

    succeeded: function(msg) { return msg.resultCode === wire.NATPMP_RESULT.SUCCESS; },
    result_name: wire.natpmp_result_name
  }
};


function mapping_key(protocol, internal_port) {
  return protocol + ':' + internal_port;
}


/* ============================== Session ============================== */

function PMPSession(options) {
  if (!(this instanceof PMPSession)) return new PMPSession(options);
  options = options || {};
  validate_options(options);

  var ev = new EventEmitter();
  ev.setMaxListeners(0);

  var context = {
    state: 'new',                  // new | listening | destroyed

    gateway:  options.gateway,
    clientIp: options.clientIp,

    // RFC 6886 §1.1 — PCP first, NAT-PMP as the fallback dialect. This order
    // is re-applied to every request; it is never cached as "this gateway
    // only speaks X", because firmware gets updated.
    protocols: (options.protocols || ['pcp', 'natpmp']).slice(),

    lifetime:          options.lifetime === undefined ? lifecycle.LIFETIME.DEFAULT : options.lifetime,
    // RFC 6886 §3.7 spread; overridable so tests need not wait it out
    rebootDelayMs:     options.rebootRecreateDelay,
    retransmitAttempts: options.retransmitAttempts || lifecycle.RETRANSMIT.MAX_ATTEMPTS,

    // RFC 6886 §3.1 — small devices; never more than one request in flight
    queue:    [],
    inflight: null,
    tx_seq:   0,

    mappings: Object.create(null),   // 'tcp:8080' → mapping record
    externalIp: null,

    epoch: {
      pcp:    lifecycle.make_epoch_tracker('pcp'),
      natpmp: lifecycle.make_epoch_tracker('natpmp')
    },

    // RFC 6886 §1.1 requires trying PCP again on every request, so the same
    // fallback repeats forever. The event is announced once; the retries stay.
    announcedFallback: Object.create(null),

    stats: {
      requestsSent:      0,
      retransmissions:   0,
      responsesReceived: 0,
      discardedForeign:  0,
      malformedPackets:  0,
      dialectFallbacks:  0,
      mappingsCreated:   0,
      renewals:          0,
      rebootsDetected:   0,
      timeouts:          0
    }
  };


  /* ========================= Packet emission ========================= */

  function emit_packet(buf) {
    ev.emit('packet', buf, { address: context.gateway, port: wire.SERVER_PORT });
  }


  /* ======================= Transaction handling ======================= */

  function make_tx(spec) {
    context.tx_seq++;
    return {
      id:           context.tx_seq,
      kind:         spec.kind,                  // 'map' | 'address'
      protocol:     spec.protocol || null,
      internalPort: spec.internalPort || 0,
      externalPort: spec.externalPort || 0,
      lifetime:     spec.lifetime === undefined ? context.lifetime : spec.lifetime,
      nonce:        spec.nonce || lifecycle.make_nonce(),
      isRenewal:    !!spec.isRenewal,
      exact:        !!spec.exact,
      cb:           spec.cb || null,

      dialectIndex: 0,
      tried:        [],
      rt:           null,
      timer:        null,
      cancelled:    false,
      settled:      false
    };
  }


  function current_dialect(tx) {
    var name = context.protocols[tx.dialectIndex];
    return name ? DIALECT[name] : null;
  }


  function enqueue(tx) {
    context.queue.push(tx);
    pump();
  }


  function pump() {
    if (context.state === 'destroyed') return;
    if (context.inflight || context.queue.length === 0) return;

    context.inflight = context.queue.shift();
    start_dialect(context.inflight);
  }


  /**
   * Abandon a transaction before it has been answered.
   *
   * This matters more than it looks. The retransmission schedule runs to nine
   * attempts and the last wait alone is 64 seconds, so a request that nobody
   * answers holds its callback for over two minutes. An application that has
   * moved on — a window closed, a user cancelled — has no other way out.
   */
  function cancel(tx, reason) {
    // Already answered, already cancelled, or never started: there is nothing
    // to abandon, and saying otherwise would let a caller believe it stopped
    // something that had in fact completed
    if (!tx || tx.cancelled || tx.settled) return false;
    tx.cancelled = true;
    clear_timer(tx);

    var i = context.queue.indexOf(tx);
    if (i !== -1) context.queue.splice(i, 1);

    var err = new PortMapStateError(reason || 'Cancelled', 'cancelled');
    err.cancelled = true;
    finish(tx, err);
    return true;
  }


  function finish(tx, err, result) {
    clear_timer(tx);
    tx.settled = true;
    if (context.inflight === tx) context.inflight = null;
    if (tx.cb) {
      var cb = tx.cb;
      tx.cb = null;
      cb(err, result);
    }
    pump();
  }


  function clear_timer(tx) {
    if (tx.timer) { clear_safe_timeout(tx.timer); tx.timer = null; }
  }


  /**
   * Begin (or restart) a transaction under the dialect at tx.dialectIndex.
   */
  function start_dialect(tx) {
    var dialect = current_dialect(tx);

    // Skip dialects that cannot express this request at all — only NAT-PMP
    // has a standalone external-address opcode.
    while (dialect &&
           ((tx.kind === 'address' && !dialect.encode_address) ||
            (tx.kind === 'probe'   && !dialect.encode_probe))) {
      tx.dialectIndex++;
      dialect = current_dialect(tx);
    }

    if (!dialect) {
      return finish(tx, new PortMapProtocolError(
        'No configured protocol can perform this request', null, null));
    }

    tx.tried.push(dialect.name);
    tx.rt = lifecycle.make_retransmit({
      attempts: tx.lifetime === 0
        ? lifecycle.RETRANSMIT.DELETE_ATTEMPTS      // §3.1 — deletion is advisory
        : context.retransmitAttempts
    });

    send(tx);
  }


  function send(tx) {
    if (tx.cancelled) return;
    var dialect = current_dialect(tx);
    if (!dialect) return;

    var buf;
    try {
      if (tx.kind === 'probe')        buf = dialect.encode_probe(tx, context);
      else if (tx.kind === 'address')  buf = dialect.encode_address(tx, context);
      else                             buf = dialect.encode_map(tx, context);
    } catch (e) {
      return finish(tx, new PortMapValidationError('encode failed: ' + e.message));
    }

    var delay = tx.rt.next();
    if (delay === null) return on_exhausted(tx);

    if (tx.rt.attempt === 1) context.stats.requestsSent++;
    else context.stats.retransmissions++;

    dbg('session', dialect.name, tx.kind, 'attempt', tx.rt.attempt,
        tx.kind === 'map' ? tx.protocol + ':' + tx.internalPort : '');

    emit_packet(buf);

    clear_timer(tx);
    tx.timer = safe_timeout(function() { send(tx); }, delay);
  }


  /**
   * Every retransmission for this dialect has gone unanswered.
   */
  function on_exhausted(tx) {
    clear_timer(tx);

    if (switch_dialect(tx, 'no response')) return;

    context.stats.timeouts++;
    finish(tx, new PortMapTimeoutError(
      'No response from ' + context.gateway + ' after ' + tx.rt.attempts +
      ' attempts (' + tx.tried.join(', ') + ')', null));
  }


  /**
   * Move to the next dialect, if there is an untried one left.
   * Returns true when the transaction has been restarted.
   */
  function switch_dialect(tx, reason) {
    var from = current_dialect(tx);
    tx.dialectIndex++;
    var to = current_dialect(tx);
    if (!to) return false;

    context.stats.dialectFallbacks++;

    var announce_key = (from ? from.name : '?') + '>' + to.name + ':' + reason;
    if (!context.announcedFallback[announce_key]) {
      context.announcedFallback[announce_key] = true;
      ev.emit('degraded', { from: from ? from.name : null, to: to.name, reason: reason });
    }
    dbg('session', 'falling back', from ? from.name : '?', '→', to.name, '(' + reason + ')');

    start_dialect(tx);
    return true;
  }


  /* ========================= Inbound packets ========================= */

  function process_packet(buf, rinfo) {
    if (context.state === 'destroyed') return;

    // RFC 6886 §3.2 — the client MUST check the source address and silently
    // discard anything not from the gateway it asked. Guards against another
    // NAT box on the LAN answering, and against spoofed announcements.
    if (rinfo && rinfo.address && rinfo.address !== context.gateway) {
      context.stats.discardedForeign++;
      dbg('session', 'discarding packet from', rinfo.address, '— not the gateway');
      return;
    }

    var proto = wire.detect_protocol(buf);
    if (!proto) {
      context.stats.malformedPackets++;
      ev.emit('warning', 'Unrecognised packet version from ' + context.gateway);
      return;
    }

    var msg;
    try {
      msg = DIALECT[proto].decode(buf);
    } catch (e) {
      context.stats.malformedPackets++;
      ev.emit('warning', 'Malformed ' + proto + ' packet: ' + e.message);
      return;
    }

    context.stats.responsesReceived++;

    // Epoch first: a state loss invalidates every mapping we hold, whether or
    // not this particular packet answers an outstanding request. Unsolicited
    // announcements arrive here too.
    if (context.epoch[proto].observe(msg.epoch)) {
      on_gateway_reboot(proto);
    }

    var tx = context.inflight;
    if (!tx || tx.cancelled) return;       // announcement, or a late duplicate

    var dialect = current_dialect(tx);
    if (!dialect || dialect.name !== proto) {
      // A reply in the other dialect: only meaningful as an Unsupported
      // Version rejection of what we just sent.
      if (proto === 'natpmp' && msg.unsupportedVersion) {
        return on_unsupported_version(tx);
      }
      return;
    }

    if (!dialect.matches(tx, msg)) return;

    // RFC 6886 §1.1 — this reply is the fast fail-over signal. Switch dialect
    // and resend immediately rather than waiting out the retransmit timer.
    if (dialect.is_unsupported_version(msg)) {
      return on_unsupported_version(tx);
    }

    clear_timer(tx);

    if (!dialect.succeeded(msg)) {
      return on_error_response(tx, dialect, msg);
    }

    on_success(tx, dialect, msg);
  }


  function on_unsupported_version(tx) {
    clear_timer(tx);
    if (switch_dialect(tx, 'unsupported version')) return;

    finish(tx, new PortMapProtocolError(
      'Gateway rejected every protocol version we speak', 1, tx.tried.join(',')));
  }


  function on_error_response(tx, dialect, msg) {
    var retry = lifecycle.retry_class(dialect.name, msg.resultCode);

    var err = new PortMapProtocolError(
      dialect.name.toUpperCase() + ' request rejected: ' + msg.resultName,
      msg.resultCode, dialect.name);
    err.retry = retry;
    // RFC 6887 §7.4 — on an error response the lifetime says how long the
    // client should assume it would get the same answer again.
    err.retryAfter = (dialect.name === 'pcp' && msg.lifetime)
      ? msg.lifetime * 1000
      : (retry === 'long' ? lifecycle.LONG_ERROR_BACKOFF_MS : 0);

    dbg('session', dialect.name, 'error', msg.resultName, 'retry=' + retry);
    finish(tx, err);
  }


  function on_success(tx, dialect, msg) {
    if (tx.kind === 'probe') {
      if (msg.externalIp) context.externalIp = msg.externalIp;
      return finish(tx, null, {
        protocol:   dialect.name,
        externalIp: context.externalIp,
        epoch:      msg.epoch
      });
    }

    if (tx.kind === 'address') {
      context.externalIp = msg.externalIp || null;
      return finish(tx, null, { externalIp: context.externalIp });
    }

    if (msg.externalIp) context.externalIp = msg.externalIp;

    // Some gateways ignore PREFER_FAILURE and hand back another port anyway.
    // Reporting that as success would defeat the whole point of asking.
    if (tx.exact && tx.lifetime !== 0 && tx.externalPort &&
        msg.externalPort !== tx.externalPort) {
      var mismatch = new PortMapProtocolError(
        'Asked for external port ' + tx.externalPort + ' exactly, but the gateway ' +
        'assigned ' + msg.externalPort, wire.PCP_RESULT.CANNOT_PROVIDE_EXTERNAL, 'pcp');
      mismatch.retry = 'conflict';
      mismatch.assignedPort = msg.externalPort;
      return finish(tx, mismatch);
    }

    var key = mapping_key(tx.protocol, tx.internalPort);

    // Deletion: lifetime 0 in, lifetime 0 back.
    if (tx.lifetime === 0) {
      var removed = context.mappings[key];
      if (removed) {
        cancel_mapping_timer(removed);
        delete context.mappings[key];
        removed.state = 'CLOSED';
        ev.emit('unmapped', public_mapping(removed));
      }
      return finish(tx, null, removed ? public_mapping(removed) : null);
    }

    var now = Date.now();
    var existing = context.mappings[key];
    var mapping = existing || {
      key:          key,
      protocol:     tx.protocol,
      internalPort: tx.internalPort,
      nonce:        tx.nonce,
      exact:        tx.exact,
      createdAt:    now,
      timer:        lifecycle.make_renewal_timer()
    };

    mapping.externalPort = msg.externalPort;
    mapping.externalIp   = context.externalIp;
    mapping.lifetime     = msg.lifetime;
    mapping.via          = dialect.name;
    mapping.state        = 'ACTIVE';
    mapping.renewedAt    = now;
    mapping.expiresAt    = now + msg.lifetime * 1000;

    context.mappings[key] = mapping;

    arm_renewal(mapping);

    if (tx.isRenewal) {
      context.stats.renewals++;
      ev.emit('renewed', public_mapping(mapping));
    } else {
      context.stats.mappingsCreated++;
      ev.emit('mapped', public_mapping(mapping));
    }

    finish(tx, null, public_mapping(mapping));
  }


  /* =========================== Renewal =========================== */

  function arm_renewal(mapping) {
    if (!mapping.lifetime) return;
    mapping.timer.arm(mapping.lifetime, function() { renew(mapping); });
  }


  function cancel_mapping_timer(mapping) {
    if (mapping.timer) mapping.timer.cancel();
  }


  function renew(mapping) {
    if (context.state === 'destroyed') return;
    if (!context.mappings[mapping.key]) return;

    mapping.state = 'RENEWING';

    enqueue(make_tx({
      kind:         'map',
      protocol:     mapping.protocol,
      internalPort: mapping.internalPort,
      // RFC 6886 §3.3 — renew with the port the gateway actually gave us.
      // To a rebooted gateway this looks like a fresh request for a port it
      // was willing to hand out a moment ago, so mappings survive restarts.
      externalPort: mapping.externalPort,
      lifetime:     context.lifetime,
      nonce:        mapping.nonce,          // PCP ties the renewal to the mapping
      isRenewal:    true,
      // A mapping asked for exactly must not drift to another port on renewal
      exact:        mapping.exact,
      cb: function(err) {
        if (!err) return;
        mapping.state = 'LOST';
        ev.emit('lost', public_mapping(mapping), err.message);
      }
    }));
  }


  /* ======================== Gateway reboot ======================== */

  /**
   * RFC 6886 §3.7 / RFC 6887 §8.5 — the epoch says the gateway lost its
   * table. Every mapping is gone; recreate them after a random delay so the
   * whole LAN does not hit the gateway at once, and serially, since the
   * queue only runs one request at a time anyway.
   */
  function on_gateway_reboot(proto) {
    context.stats.rebootsDetected++;
    dbg('session', proto, 'epoch anomaly — gateway lost state');

    var keys = Object.keys(context.mappings);
    ev.emit('gateway-reboot', { protocol: proto, mappings: keys.length });

    for (var i = 0; i < keys.length; i++) {
      var mapping = context.mappings[keys[i]];
      mapping.state = 'LOST';
      ev.emit('lost', public_mapping(mapping), 'gateway restarted');
      schedule_recreate(mapping);
    }
  }


  function schedule_recreate(mapping) {
    var delay = context.rebootDelayMs === undefined
      ? lifecycle.reboot_recreate_delay()
      : context.rebootDelayMs;
    mapping.timer.armIn(delay, function() {
      if (context.state === 'destroyed') return;
      if (!context.mappings[mapping.key]) return;

      var previous_port = mapping.externalPort;
      enqueue(make_tx({
        kind:         'map',
        protocol:     mapping.protocol,
        internalPort: mapping.internalPort,
        externalPort: previous_port,
        lifetime:     context.lifetime,
        nonce:        mapping.nonce,
        isRenewal:    true,
        cb: function(err, result) {
          if (err) {
            ev.emit('warning', 'Could not recreate ' + mapping.key + ': ' + err.message);
            return;
          }
          if (result.externalPort !== previous_port) {
            ev.emit('remapped', result, previous_port);
          }
        }
      }));
    });
  }


  /* ============================ Public API ============================ */

  function public_mapping(m) {
    return {
      protocol:     m.protocol,
      internalPort: m.internalPort,
      externalPort: m.externalPort,
      internalIp:   context.clientIp,
      externalIp:   m.externalIp,
      lifetime:     m.lifetime,
      via:          m.via,
      state:        m.state,
      nonceHex:     wire.nonce_to_hex(m.nonce),
      createdAt:    new Date(m.createdAt),
      renewedAt:    m.renewedAt ? new Date(m.renewedAt) : null,
      expiresAt:    m.expiresAt ? new Date(m.expiresAt) : null
    };
  }


  function map(opts, cb) {
    if (context.state === 'destroyed') {
      var err = new PortMapStateError('Session destroyed', context.state);
      return cb ? cb(err) : ev.emit('error', err);
    }
    opts = opts || {};

    var protocol = opts.protocol || 'tcp';
    if (protocol !== 'tcp' && protocol !== 'udp') {
      var perr = new PortMapValidationError('protocol must be "tcp" or "udp"', 'protocol');
      return cb ? cb(perr) : ev.emit('error', perr);
    }
    if (!opts.internalPort) {
      var ierr = new PortMapValidationError('internalPort required', 'internalPort');
      return cb ? cb(ierr) : ev.emit('error', ierr);
    }

    // 'any' means the gateway chooses from the start, which RFC 6886 §9.4
    // argues is what a client should usually do: the gateway knows which
    // ports are free and the client does not
    var wanted = opts.onConflict === 'any' ? 0
               : (opts.externalPort === undefined ? opts.internalPort : opts.externalPort);

    var tx = make_tx({
      kind:         'map',
      protocol:     protocol,
      internalPort: opts.internalPort,
      // 0 asks the gateway to pick a high-numbered port of its choosing
      externalPort: wanted,
      lifetime:     opts.lifetime === undefined ? context.lifetime : opts.lifetime,
      exact:        opts.exact === true || opts.onConflict === 'fail',
      cb:           cb
    });
    enqueue(tx);
    return { cancel: function(reason) { return cancel(tx, reason); } };
  }


  function unmap(opts, cb) {
    if (typeof opts === 'number') opts = { internalPort: opts };
    opts = opts || {};

    var protocol = opts.protocol || 'tcp';
    var key = mapping_key(protocol, opts.internalPort);
    var mapping = context.mappings[key];
    if (mapping) cancel_mapping_timer(mapping);

    var tx = make_tx({
      kind:         'map',
      protocol:     protocol,
      internalPort: opts.internalPort,
      externalPort: 0,        // MUST be zero on delete (RFC 6886 §3.4)
      lifetime:     0,
      nonce:        mapping ? mapping.nonce : undefined,
      cb:           cb
    });
    enqueue(tx);
    return { cancel: function(reason) { return cancel(tx, reason); } };
  }


  /**
   * NAT-PMP opcode 0 is the only direct way to ask "what is my public IPv4?".
   * PCP has no equivalent: there the external address arrives as part of a
   * MAP response, so it is served from cache when PCP is all we have.
   */
  function getExternalIp(cb) {
    if (context.protocols.indexOf('natpmp') === -1) {
      return cb(null, { externalIp: context.externalIp, cached: true });
    }
    var tx = make_tx({ kind: 'address', cb: cb });
    enqueue(tx);
    return { cancel: function(reason) { return cancel(tx, reason); } };
  }


  /**
   * Ask the gateway whether it speaks either protocol at all, without
   * creating anything. PCP is asked first and NAT-PMP is the fallback, on the
   * same schedule as any other request, so the answer reflects exactly what a
   * real mapping would encounter.
   */
  function probe(cb) {
    if (context.state === 'destroyed') {
      var err = new PortMapStateError('Session destroyed', context.state);
      return cb ? cb(err) : ev.emit('error', err);
    }
    var tx = make_tx({ kind: 'probe', cb: cb });
    enqueue(tx);
    return { cancel: function(reason) { return cancel(tx, reason); } };
  }


  /** Abandon everything queued and in flight. */
  function cancelAll(reason) {
    var n = 0;
    var queued = context.queue.slice();
    for (var i = 0; i < queued.length; i++) if (cancel(queued[i], reason)) n++;
    if (context.inflight && cancel(context.inflight, reason)) n++;
    return n;
  }


  /**
   * Confirm a mapping is still held.
   *
   * Neither PCP nor NAT-PMP has a read operation: there is no way to ask a
   * gateway what it holds without asking it to hold something. RFC 6886 §3.3
   * makes a repeated request idempotent — a gateway that already has the
   * mapping returns the port it already assigned — so re-requesting does
   * verify it, but it also recreates it if it was gone, and the answer looks
   * the same either way.
   *
   * That is not a gap to work around. A mapping that had vanished is restored
   * by the same call that would have discovered it missing, which is the
   * outcome a caller wanted. What cannot be reported is *whether* it had
   * vanished, and `verified` says so rather than claiming certainty.
   */
  function verify(opts, cb) {
    opts = opts || {};
    cb = cb || function() {};

    var protocol = (opts.protocol || 'tcp').toLowerCase();
    var key = mapping_key(protocol, opts.internalPort);
    var known = context.mappings[key];

    map({
      protocol:     protocol,
      internalPort: opts.internalPort,
      externalPort: known ? known.externalPort : opts.externalPort,
      lifetime:     context.lifetime
    }, function(err, mapping) {
      if (err) return cb(null, { present: false, reason: err.message });
      cb(null, {
        present:      true,
        // The protocol cannot distinguish "was there" from "is there now"
        verified:     'reasserted',
        externalPort: mapping.externalPort,
        // A different port coming back means the old one was lost and this is
        // a new mapping, which the caller does need to know
        moved:        known ? mapping.externalPort !== known.externalPort : null
      });
    });
  }


  function getMappings() {
    var out = [];
    var keys = Object.keys(context.mappings);
    for (var i = 0; i < keys.length; i++) out.push(public_mapping(context.mappings[keys[i]]));
    return out;
  }


  function getMapping(protocol, internal_port) {
    var m = context.mappings[mapping_key(protocol, internal_port)];
    return m ? public_mapping(m) : null;
  }


  function getStats() { return Object.assign({}, context.stats); }

  function getConfig() {
    return {
      gateway:    context.gateway,
      clientIp:   context.clientIp,
      protocols:  context.protocols.slice(),
      lifetime:   context.lifetime,
      externalIp: context.externalIp
    };
  }


  /* ============================ Lifecycle ============================ */

  function listening() {
    if (context.state === 'destroyed') return;
    context.state = 'listening';
    ev.emit('listening');
    pump();
  }


  function destroy() {
    if (context.state === 'destroyed') return;
    context.state = 'destroyed';

    if (context.inflight) clear_timer(context.inflight);
    context.inflight = null;
    context.queue = [];

    var keys = Object.keys(context.mappings);
    for (var i = 0; i < keys.length; i++) cancel_mapping_timer(context.mappings[keys[i]]);

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
    listening: listening,

    map: map,
    unmap: unmap,
    cancelAll: cancelAll,
    getExternalIp: getExternalIp,
    probe: probe,
    verify: verify,
    getMappings: getMappings,
    getMapping: getMapping,
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


export default PMPSession;
export { PMPSession, DIALECT };
