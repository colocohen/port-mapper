/**
 * reachability.js — verifying what the outside world actually sees.
 *
 * A gateway reporting its external address is reporting what it believes.
 * Comparing that with what a server on the internet observes is the only way
 * to turn an inference into a fact — and the difference between the two is
 * exactly what a second layer of NAT looks like:
 *
 *   gateway says   192.168.0.7      the WAN side of the router
 *   STUN says      186.28.87.164    what the internet sees
 *   → they differ, so something else is translating upstream
 *
 * STUN is a separate protocol with its own RFC, so it is not reimplemented
 * here. `turn-server` is an optional dependency: without it a diagnosis is
 * still produced from the address classification alone, and with it the same
 * diagnosis is verified and gains the NAT type. The two levels are reported
 * as `method: 'inferred'` and `method: 'verified'` rather than silently
 * differing, so a caller always knows which one it is looking at.
 *
 * The NAT type matters for the advice, not just the diagnosis. When no mapping
 * is possible, what to do next depends on it: a cone NAT can still be
 * traversed by hole punching, a symmetric one cannot and needs a relay.
 */

import { dbg } from './debug.js';
import * as wire from './wire.js';


var cached_module;          // undefined = not tried, null = not installed


/**
 * Load the STUN implementation, once. A missing optional dependency is a
 * normal condition, not an error: it downgrades the diagnosis rather than
 * failing it.
 */
function load_stun(cb) {
  if (cached_module !== undefined) return cb(null, cached_module);

  import('turn-server').then(function(mod) {
    cached_module = mod && (mod.default && mod.default.getPublicIP ? mod.default : mod);
    dbg('diagnose', 'turn-server available — diagnosis will be verified');
    cb(null, cached_module);
  }).catch(function() {
    cached_module = null;
    dbg('diagnose', 'turn-server not installed — diagnosis will be inferred only');
    cb(null, null);
  });
}


/**
 * Ask a STUN server what address it sees us coming from.
 *
 * `stun` may be:
 *   omitted    use turn-server when it is installed
 *   false      never; the diagnosis stays inferred
 *   function   a custom provider, called as fn(cb) → cb(err, { address, port })
 */
function public_address(options, cb) {
  options = options || {};

  if (options.stun === false) return cb(null, null);

  if (typeof options.stun === 'function') {
    return options.stun(function(err, res) {
      if (err) return cb(null, null);
      cb(null, normalise(res, 'custom'));
    });
  }

  load_stun(function(_, mod) {
    if (!mod || typeof mod.getPublicIP !== 'function') return cb(null, null);

    var server = options.stunServer || 'stun:stun.l.google.com:19302';
    var settled = false;
    function once(err, res) {
      if (settled) return;
      settled = true;
      // A STUN failure is not a diagnosis failure — plenty of networks block
      // it while port mapping works perfectly
      cb(null, err ? null : normalise(res, 'stun'));
    }

    // The signature is not pinned here on purpose: this is a thin bridge to
    // another library, and accepting both shapes costs one branch and removes
    // a version coupling that would otherwise break on a minor release.
    try {
      if (mod.getPublicIP.length >= 2) mod.getPublicIP(server, once);
      else mod.getPublicIP(once);
    } catch (e) {
      once(e);
    }
  });
}


function normalise(res, source) {
  if (!res) return null;
  if (typeof res === 'string') return { address: res, port: null, source: source };
  return {
    address: res.address || res.ip || res.host || null,
    port:    res.port || null,
    source:  source
  };
}


/**
 * Classify the NAT this host sits behind (RFC 5780).
 *
 * Only meaningful when no mapping is available, and only when turn-server is
 * present. A symmetric NAT allocates a different external port per
 * destination, which is what defeats hole punching and forces a relay.
 */
function nat_type(options, cb) {
  options = options || {};
  if (options.stun === false) return cb(null, null);

  load_stun(function(_, mod) {
    if (!mod || typeof mod.detectNAT !== 'function') return cb(null, null);

    var settled = false;
    function once(err, res) {
      if (settled) return;
      settled = true;
      if (err || !res) return cb(null, null);
      cb(null, typeof res === 'string' ? { type: res } : res);
    }

    try {
      if (mod.detectNAT.length >= 2) mod.detectNAT(options.stunServer, once);
      else mod.detectNAT(once);
    } catch (e) { once(e); }
  });
}


/**
 * What a caller should do when a mapping cannot be made, given the NAT type.
 * This is the part that turns a diagnosis into a next step.
 */
function traversal_advice(nat) {
  if (!nat || !nat.type) {
    return 'Port forwarding is unavailable. Peer-to-peer may still work through ' +
           'hole punching; a relay always will.';
  }

  var type = String(nat.type).toLowerCase();

  if (type.indexOf('symmetric') !== -1) {
    return 'This is a symmetric NAT: it allocates a different external port for ' +
           'every destination, so hole punching cannot work. A relay (TURN) is the ' +
           'only option left for peer-to-peer.';
  }
  if (type.indexOf('open') !== -1 || type.indexOf('none') !== -1) {
    return 'There is no NAT in front of this host, so nothing needs mapping — ' +
           'a firewall is what is blocking the port, if anything is.';
  }
  if (type.indexOf('blocked') !== -1) {
    return 'UDP appears to be blocked outbound, so neither STUN nor hole punching ' +
           'will work. A relay over TCP or TLS is the remaining option.';
  }
  return 'This is a cone NAT, so hole punching should work for peer-to-peer even ' +
         'without a port mapping. A relay is the fallback.';
}


/**
 * Combine what the gateway claims with what the internet observes.
 *
 * Returns { method, publicAddress, agrees, natType, advice } — `agrees` is the
 * whole point: a gateway whose external address is not the one the world sees
 * is behind something else, whatever it says about itself.
 */
function verify(gateway_external_ip, options, cb) {
  if (typeof options === 'function') { cb = options; options = {}; }
  options = options || {};

  public_address(options, function(_, seen) {
    if (!seen || !seen.address) {
      return cb(null, {
        method:        'inferred',
        publicAddress: null,
        agrees:        null,
        natType:       null,
        advice:        null
      });
    }

    var agrees = gateway_external_ip ? seen.address === gateway_external_ip : null;

    // The NAT type is only worth the extra round trips when the answer will
    // change what a caller does, which is when there is no usable mapping
    if (agrees === true && wire.classify_external_address(seen.address) === 'public') {
      return cb(null, {
        method:        'verified',
        publicAddress: seen.address,
        agrees:        true,
        natType:       null,
        advice:        null
      });
    }

    nat_type(options, function(__, nat) {
      cb(null, {
        method:        'verified',
        publicAddress: seen.address,
        agrees:        agrees,
        natType:       nat ? nat.type : null,
        natDetail:     nat || null,
        advice:        traversal_advice(nat)
      });
    });
  });
}


/** Is the optional dependency present? Reported rather than assumed. */
function available(cb) {
  load_stun(function(_, mod) {
    cb(null, {
      available:   !!mod,
      getPublicIP: !!(mod && typeof mod.getPublicIP === 'function'),
      detectNAT:   !!(mod && typeof mod.detectNAT === 'function'),
      reason:      mod ? null :
        'turn-server is not installed — install it for a verified diagnosis ' +
        'and NAT type detection: npm install turn-server'
    });
  });
}


/** Testing seam: forget whether the module was found. */
function _reset() { cached_module = undefined; }


export { verify, public_address, nat_type, traversal_advice, available, _reset };
