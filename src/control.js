/**
 * control.js — the decision object handed to a request listener.
 *
 * A gateway has to let the program above it decide whether a request is
 * allowed, and that decision is the same shape whether the request arrived as
 * PCP, as NAT-PMP or as a SOAP envelope. This is the object that carries it,
 * and it was written three times before it was written once.
 *
 * The pattern is the one the DHCP server uses for 'discover' and 'request':
 *
 *   igd.on('port-request', function (request, control) {
 *     if (request.externalPort < 1024) return control.reject()
 *     control.allow()
 *   })
 *
 * A listener that declares a third parameter is waited for, so a decision can
 * come from a database or an HTTP call:
 *
 *   igd.on('port-request', function (request, control, done) {
 *     db.isAllowed(request.internalIp, function (err, ok) {
 *       ok ? control.allow() : control.reject()
 *       done()
 *     })
 *   })
 *
 * The waiting is arranged by arity rather than by a flag because that is the
 * only signal available at registration time — and it is why the forwarders
 * that pass these events between layers must declare exactly two parameters.
 * A variadic forwarder looks synchronous to this check, and the engine would
 * answer before the real handler had decided.
 */

import { safe_timeout, clear_safe_timeout } from './timers.js';


/**
 * Build a control object.
 *
 * `proposed` is what the engine intends to do unless told otherwise — the
 * external port it would assign — so a handler that only wants to approve does
 * not have to restate it.
 */
function make_control(proposed, max_ttl) {
  var control = {
    externalPort: proposed,
    maxTtl:       max_ttl,

    _allowed:  false,
    _rejected: null,
    _ignored:  false,
    _pending:  0,
    _continue: null,

    allow:  function() { control._allowed = true; },
    reject: function(code) { control._rejected = code === undefined ? true : code; },
    // Answer nothing at all. Distinct from rejecting: a client that is refused
    // knows where it stands, while one that is ignored retransmits and gives
    // up, which is what a gateway wants for traffic it does not want to admit
    // hearing.
    ignore: function() { control._ignored = true; },

    _begin: function() { control._pending++; },
    _end: function() {
      control._pending--;
      if (control._pending <= 0 && control._continue) {
        var c = control._continue;
        control._continue = null;
        c();
      }
    }
  };
  return control;
}


/**
 * Run `cb` once every asynchronous handler has finished.
 *
 * Synchronous handlers leave nothing pending, so this runs immediately and
 * costs nothing in the common case. The guard exists because a handler that
 * takes a `done` and forgets to call it would otherwise stall the gateway for
 * every client, not just its own.
 */
function when_control_done(control, timeout, emit_warning, cb) {
  if (control._pending <= 0) return cb();

  var guard = safe_timeout(function() {
    if (!control._continue) return;
    if (emit_warning) {
      emit_warning('A request handler took a done callback but did not call it ' +
                   'within ' + timeout + 'ms — proceeding without it');
    }
    var c = control._continue;
    control._continue = null;
    c();
  }, timeout);

  control._continue = function() { clear_safe_timeout(guard); cb(); };
}


/**
 * Wrap a listener that declares a third `done` parameter so the engine knows
 * to wait for it. Listeners with two parameters are returned untouched.
 *
 * The original is kept on `_orig` so off() can find a wrapped listener by the
 * function the caller actually passed in.
 */
function wrap_control_listener(fn) {
  if (typeof fn !== 'function' || fn.length < 3) return fn;

  var wrapped = function(req, control) {
    if (!control || typeof control._begin !== 'function') {
      return fn(req, control, function() {});
    }
    control._begin();
    var called = false;
    fn(req, control, function done() {
      if (called) return;
      called = true;
      control._end();
    });
  };

  wrapped._orig = fn;
  return wrapped;
}


/**
 * Remove a listener that may have been wrapped on the way in.
 */
function remove_control_listener(emitter, name, fn) {
  var listeners = emitter.listeners(name);
  for (var i = 0; i < listeners.length; i++) {
    if (listeners[i] === fn || listeners[i]._orig === fn) {
      emitter.removeListener(name, listeners[i]);
      return true;
    }
  }
  return false;
}


/**
 * What a control object decided, reduced to one of four outcomes so the
 * engines do not each interpret the flags themselves.
 */
function outcome(control, policy) {
  if (control._ignored) return { action: 'ignore' };
  if (control._rejected) {
    return { action: 'reject',
             code: typeof control._rejected === 'number' ? control._rejected : null };
  }
  if (control._allowed || policy === 'allow-all') return { action: 'allow' };
  // Nothing said is a refusal. A gateway that grants what it was not asked to
  // grant is the failure mode this whole layer exists to prevent.
  return { action: 'reject', code: null };
}


export {
  make_control, when_control_done, wrap_control_listener,
  remove_control_listener, outcome
};
