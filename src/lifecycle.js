/**
 * lifecycle.js — Mapping lifecycle policy shared by the protocol sessions.
 *
 * Everything here is the behaviour that wire.js deliberately does not carry:
 * the clock, the random source, retransmission schedules, renewal timing and
 * the reboot-detection heuristics. Both pmp_session and upnp_session renew on
 * the same logic, so it lives outside either of them.
 *
 * References:
 *   RFC 6886 §3.1 — retransmission: 250 ms, doubling, nine attempts
 *   RFC 6886 §3.3 — renew halfway to expiry, like DHCP
 *   RFC 6886 §3.6 — Seconds Since Start of Epoch, 7/8 conservative estimate
 *   RFC 6886 §3.7 — random 0–5 s delay before recreating after a reboot
 *   RFC 6887 §8.5 — PCP epoch validation
 *   RFC 6887 §7.4 — error lifetimes: how long an error should be believed
 */

import { safe_timeout, clear_safe_timeout } from './timers.js';


/* ============================== Defaults ============================== */

// RFC 6886 §3.3 / RFC 6887 §15 — 7200 s is the recommended mapping lifetime
const LIFETIME = {
  MIN:     120,
  DEFAULT: 7200,
  MAX:     86400
};

// RFC 6886 §3.1 — first timeout 250 ms, doubling each attempt, nine attempts
// (the ninth waits 64 s). Deletion is advisory, so it gives up much sooner.
const RETRANSMIT = {
  INITIAL_MS:      250,
  MAX_ATTEMPTS:    9,
  DELETE_ATTEMPTS: 2
};

// RFC 6886 §3.7 — after detecting a reboot, wait a uniform random 0–5 s
// before the first re-request so the whole LAN does not stampede the gateway
const REBOOT_RECREATE_DELAY_MS = 5000;

// Renew at half the granted lifetime, jittered so many clients on the same
// network do not synchronise onto the same instant.
const RENEW_FRACTION = 0.5;
const RENEW_JITTER   = 0.1;

/**
 * RFC 6887 §7.4 — how long a failure should be believed before retrying.
 * 'none'  — the request itself is wrong; retrying unchanged is pointless
 * 'short' — transient; retry on the normal schedule
 * 'long'  — semi-permanent (policy, quota, no external address available)
 */
const PCP_RESULT_RETRY = {
  1: 'short',   // UNSUPP_VERSION — handled separately as a dialect fallback
  2: 'long',    // NOT_AUTHORIZED
  3: 'none',    // MALFORMED_REQUEST
  4: 'none',    // UNSUPP_OPCODE
  5: 'none',    // UNSUPP_OPTION
  6: 'none',    // MALFORMED_OPTION
  7: 'short',   // NETWORK_FAILURE
  8: 'short',   // NO_RESOURCES
  9: 'long',    // UNSUPP_PROTOCOL
  10: 'long',   // USER_EX_QUOTA
  11: 'long',   // CANNOT_PROVIDE_EXTERNAL
  12: 'none',   // ADDRESS_MISMATCH — double NAT; nothing to retry
  13: 'long'    // EXCESSIVE_REMOTE_PEERS
};

const LONG_ERROR_BACKOFF_MS = 30 * 60 * 1000;

const NATPMP_RESULT_RETRY = {
  1: 'short',   // UNSUPPORTED_VERSION — dialect fallback
  2: 'long',    // NOT_AUTHORIZED — administrator disabled it
  3: 'short',   // NETWORK_FAILURE — gateway has no upstream lease yet
  4: 'short',   // OUT_OF_RESOURCES
  5: 'none'     // UNSUPPORTED_OPCODE
};


function retry_class(dialect, code) {
  var table = dialect === 'pcp' ? PCP_RESULT_RETRY : NATPMP_RESULT_RETRY;
  return table[code] || 'none';
}


/* ================================ Nonce ================================ */

/**
 * RFC 6887 §11.1 — the 96-bit mapping nonce must be unpredictable: it is what
 * stops another host on the LAN from deleting or stealing the mapping.
 * The DHCP xid is generated in the session for the same reason.
 */
function make_nonce() {
  var out = new Uint8Array(12);
  if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.getRandomValues) {
    globalThis.crypto.getRandomValues(out);
  } else {
    for (var i = 0; i < 12; i++) out[i] = Math.floor(Math.random() * 256);
  }
  return out;
}


/* ========================== Retransmission ========================== */

/**
 * Doubling retransmission schedule. Returns a handle the session drives:
 *
 *   var rt = make_retransmit({ attempts: 9 })
 *   rt.next()    // 250, then 500, 1000, ... or null once exhausted
 *   rt.attempt   // 1-based count of sends so far
 */
function make_retransmit(options) {
  options = options || {};
  var initial  = options.initialMs || RETRANSMIT.INITIAL_MS;
  var attempts = options.attempts  || RETRANSMIT.MAX_ATTEMPTS;

  var state = {
    attempt: 0,
    next: function() {
      if (state.attempt >= attempts) return null;
      var delay = initial * Math.pow(2, state.attempt);
      state.attempt++;
      return delay;
    },
    reset: function() { state.attempt = 0; },
    get exhausted() { return state.attempt >= attempts; },
    get attempts() { return attempts; }
  };
  return state;
}


/* ============================ Renewal timing ============================ */

/**
 * Delay until the next renewal, in ms. Half the granted lifetime with ±10%
 * jitter, floored so a pathologically short lifetime cannot spin the client.
 */
function renewal_delay(lifetime_seconds) {
  var base = lifetime_seconds * RENEW_FRACTION * 1000;
  var jitter = base * RENEW_JITTER * (Math.random() * 2 - 1);
  var ms = base + jitter;
  return ms < 1000 ? 1000 : ms;
}


/** Uniform random 0–5 s, per RFC 6886 §3.7. */
function reboot_recreate_delay() {
  return Math.floor(Math.random() * REBOOT_RECREATE_DELAY_MS);
}


/* =========================== Epoch tracking =========================== */

/**
 * Tracks Seconds Since Start of Epoch for one gateway dialect and reports
 * when the gateway appears to have lost its mapping table.
 *
 * The two protocols specify genuinely different tests, so the dialect is
 * chosen at construction rather than guessed per call:
 *
 *   PCP (RFC 6887 §8.5)    two-sided drift check with a 1/16 tolerance;
 *                          going backwards by up to 1 s is packet reordering
 *   NAT-PMP (RFC 6886 §3.6) one-sided: compare against a conservative
 *                          estimate of prev + 7/8 of locally elapsed time
 */
function make_epoch_tracker(dialect) {
  var prev = null;    // { epoch, seenAt }

  function pcp_lost(epoch, now) {
    if (epoch + 1 < prev.epoch) return true;

    var client_delta = Math.floor((now - prev.seenAt) / 1000);
    var server_delta = epoch - prev.epoch;
    if (client_delta < 0) client_delta = 0;

    if (client_delta + 2 < server_delta - Math.floor(server_delta / 16)) return true;
    if (server_delta + 2 < client_delta - Math.floor(client_delta / 16)) return true;
    return false;
  }

  function natpmp_lost(epoch, now) {
    var elapsed = Math.floor((now - prev.seenAt) / 1000);
    if (elapsed < 0) elapsed = 0;
    var estimate = prev.epoch + Math.floor(elapsed * 7 / 8);
    return epoch < estimate - 2;
  }

  return {
    /**
     * Feed every epoch value received from this gateway.
     * Returns true exactly once per detected state loss.
     */
    observe: function(epoch, now) {
      now = now || Date.now();
      if (typeof epoch !== 'number') return false;

      if (prev === null) {
        prev = { epoch: epoch, seenAt: now };
        return false;
      }

      var lost = dialect === 'pcp' ? pcp_lost(epoch, now) : natpmp_lost(epoch, now);
      prev = { epoch: epoch, seenAt: now };
      return lost;
    },

    reset: function() { prev = null; },
    get last() { return prev ? { epoch: prev.epoch, seenAt: prev.seenAt } : null; }
  };
}


/* ============================ Renewal timer ============================ */

/**
 * One renewal timer per mapping. Overflow-safe, so a lifetime near 2^32
 * seconds does not fire immediately.
 */
function make_renewal_timer() {
  var handle = null;

  return {
    arm: function(lifetime_seconds, fn) {
      this.cancel();
      handle = safe_timeout(fn, renewal_delay(lifetime_seconds));
    },
    armIn: function(ms, fn) {
      this.cancel();
      handle = safe_timeout(fn, ms);
    },
    cancel: function() {
      if (handle) { clear_safe_timeout(handle); handle = null; }
    },
    get armed() { return handle !== null; }
  };
}


export {
  LIFETIME,
  RETRANSMIT,
  REBOOT_RECREATE_DELAY_MS,
  RENEW_FRACTION,
  LONG_ERROR_BACKOFF_MS,
  PCP_RESULT_RETRY,
  NATPMP_RESULT_RETRY,
  retry_class,
  make_nonce,
  make_retransmit,
  renewal_delay,
  reboot_recreate_delay,
  make_epoch_tracker,
  make_renewal_timer
};
