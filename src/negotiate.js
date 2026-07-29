/**
 * negotiate.js — decide which protocol this gateway actually speaks.
 *
 * The two engines are probed at the same time rather than in sequence. They
 * use different transports and different timeouts, and a gateway that ignores
 * one may answer the other instantly; running them one after the other would
 * add the first one's full retransmission schedule to every startup on a
 * UPnP-only router.
 *
 * Ranking, best first:
 *
 *   pcp      Standards-track successor to NAT-PMP. Two-packet exchanges, real
 *            lifetimes, a mapping nonce that stops other hosts on the LAN
 *            from deleting the mapping, and an Epoch Time that makes gateway
 *            restarts detectable rather than silent.
 *   natpmp   Same shape, IPv4 only, no nonce, but still cheap and reliable.
 *   upnp     Widest deployment by far, and the reason this library is usable
 *            on ordinary consumer hardware — but the weakest protocol of the
 *            three. RFC 6886 §9 catalogues why: retrieving one external IPv4
 *            address takes roughly 42 packets and thousands of bytes against
 *            NAT-PMP's two-packet exchange; there is no equivalent of the
 *            Epoch mechanism, so a rebooted gateway silently drops every
 *            mapping; and lease handling is unreliable enough in practice
 *            that stale entries accumulate.
 *
 * A protocol is only ranked if it answered. Preference never overrides
 * reality: a gateway that speaks only UPnP gets UPnP.
 *
 * RFC 6886 §1.1 is the reason nothing here is cached. Clients should not
 * record that a given gateway speaks only one protocol and default to it
 * afterwards, because NAT firmware gets updated, and a gateway that speaks
 * only NAT-PMP today may speak PCP tomorrow. Each negotiation starts fresh.
 */

import { safe_timeout, clear_safe_timeout } from './timers.js';
import { dbg } from './debug.js';
import { NoGatewayError } from './errors.js';


// Lower is better
const RANK = { pcp: 0, natpmp: 1, upnp: 2 };


/**
 * Probe both engines concurrently.
 *
 *   negotiate({ pmp, upnp, timeout }, function (err, result) { ... })
 *
 * result = {
 *   protocol,        'pcp' | 'natpmp' | 'upnp'
 *   session,         the engine that won — call map()/unmap() on it
 *   externalIp,      when the winning probe revealed one
 *   device,          UPnP device info, when UPnP answered
 *   results: {       what every engine reported, whether or not it won
 *     pcp:    { available, ... } | null,
 *     natpmp: { available, ... } | null,
 *     upnp:   { available, ... } | null
 *   }
 * }
 *
 * Either engine may be omitted, which is how a caller restricts the search.
 */
function negotiate(options, cb) {
  options = options || {};

  var pmp     = options.pmp || null;
  var upnp    = options.upnp || null;
  var timeout = options.timeout || 10000;

  if (!pmp && !upnp) {
    return cb(new NoGatewayError('No protocol engines given to negotiate', []));
  }

  var results = { pcp: null, natpmp: null, upnp: null };
  var pending = 0;
  var settled = false;
  var guard = null;

  function done(err, result) {
    if (settled) return;
    settled = true;
    if (guard) { clear_safe_timeout(guard); guard = null; }
    cb(err, result);
  }

  function record(name, entry) {
    results[name] = entry;
    dbg('discovery', name, entry.available ? 'available' : 'unavailable',
        entry.reason ? '(' + entry.reason + ')' : '');
    if (--pending === 0) choose();
  }

  function choose() {
    var winner = null;
    var names = Object.keys(results);

    for (var i = 0; i < names.length; i++) {
      var name = names[i];
      var entry = results[name];
      if (!entry || !entry.available) continue;
      if (winner === null || RANK[name] < RANK[winner]) winner = name;
    }

    if (winner === null) {
      var tried = names.filter(function(n) { return results[n]; });
      return done(new NoGatewayError(
        'No gateway on this network answered PCP, NAT-PMP or UPnP-IGD. ' +
        'Port mapping is unavailable; the router may have it disabled, or ' +
        'there may be no NAT in front of this host.',
        tried), build(null));
    }

    done(null, build(winner));
  }

  function build(winner) {
    var out = {
      protocol:   winner,
      session:    winner === 'upnp' ? upnp : pmp,
      externalIp: null,
      device:     null,
      results:    results
    };
    if (!winner) { out.session = null; return out; }

    var entry = results[winner];
    out.externalIp = entry.externalIp || null;

    // The UPnP description is worth keeping whichever protocol won: it names
    // the router, its IGD version and its capabilities, which is exactly what
    // a user needs when a mapping does not behave.
    if (results.upnp && results.upnp.available) out.device = results.upnp.device || null;
    return out;
  }

  /* ------------------------------ probes ------------------------------ */

  if (pmp) {
    pending++;
    pmp.probe(function(err, info) {
      if (settled) return;
      if (err) {
        // Neither dialect answered. Both are recorded as unavailable, since
        // the probe already tried PCP and fell back to NAT-PMP internally.
        results.pcp    = { available: false, reason: err.message };
        results.natpmp = { available: false, reason: err.message };
        dbg('discovery', 'pcp/natpmp unavailable:', err.message);
        if (--pending === 0) choose();
        return;
      }

      var spoke = info.protocol;                       // 'pcp' or 'natpmp'
      var other = spoke === 'pcp' ? 'natpmp' : 'pcp';

      results[spoke] = {
        available:  true,
        externalIp: info.externalIp || null,
        epoch:      info.epoch
      };
      // The other dialect was either rejected or never reached; do not claim
      // it is unavailable, only that it was not the one that answered.
      results[other] = { available: false, reason: 'gateway answered with ' + spoke };

      if (--pending === 0) choose();
    });
  }

  if (upnp) {
    pending++;
    upnp.discover(function(err, info) {
      if (settled) return;
      if (err) return record('upnp', { available: false, reason: err.message });
      record('upnp', { available: true, device: info, externalIp: null });
    });
  }

  guard = safe_timeout(function() {
    // Whatever has answered by now decides it; the rest are simply late.
    var names = Object.keys(results);
    for (var i = 0; i < names.length; i++) {
      if (!results[names[i]]) results[names[i]] = { available: false, reason: 'timed out' };
    }
    pending = 0;
    choose();
  }, timeout);

  return {
    cancel: function() {
      if (guard) { clear_safe_timeout(guard); guard = null; }
      settled = true;
    }
  };
}


export { negotiate, RANK };
export default negotiate;
