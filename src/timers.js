/**
 * timers.js — Overflow-safe timers.
 *
 * Node's setTimeout is limited to 2^31-1 ms (~24.8 days). PCP lifetimes are
 * an unsigned 32-bit count of seconds (RFC 6887 §7.1), so a long-lived
 * mapping would otherwise fire its expiry timer IMMEDIATELY (Node emits
 * TimeoutOverflowWarning and clamps the delay to 1 ms).
 *
 * safe_timeout() chains shorter timeouts until the full delay has elapsed.
 * It returns a handle object; cancel with clear_safe_timeout(handle).
 */

var MAX_TIMEOUT_MS = 2147483647; // 2^31 - 1


function safe_timeout(fn, ms) {
  var handle = { t: null, cleared: false };
  if (typeof ms !== 'number' || isNaN(ms) || ms < 0) ms = 0;

  var target = Date.now() + ms;

  function schedule() {
    if (handle.cleared) return;
    var remaining = target - Date.now();
    if (remaining <= MAX_TIMEOUT_MS) {
      handle.t = setTimeout(function() {
        if (!handle.cleared) fn();
      }, remaining < 0 ? 0 : remaining);
    } else {
      handle.t = setTimeout(schedule, MAX_TIMEOUT_MS);
    }
  }

  schedule();
  return handle;
}


function clear_safe_timeout(handle) {
  if (!handle) return;
  handle.cleared = true;
  if (handle.t) { clearTimeout(handle.t); handle.t = null; }
}


export { safe_timeout, clear_safe_timeout, MAX_TIMEOUT_MS };
