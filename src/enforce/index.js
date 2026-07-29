/**
 * enforce/index.js — the enforcement contract.
 *
 * A gateway session decides whether a mapping is allowed. Making it actually
 * happen is a separate job, and a very different one: the protocol half is
 * pure JavaScript that runs anywhere, while enforcement touches the operating
 * system, usually needs root, and is where a mistake becomes a security
 * problem rather than a compatibility bug.
 *
 * So enforcement is a pluggable adapter with one small interface:
 *
 *   {
 *     name,
 *     capabilities,                  // what it can and cannot do
 *     check(cb),                     // cb(null, { available, reason })
 *     init(config, cb),              // set up tables, chains, sockets
 *     add(mapping, cb),              // cb(null, { handle })
 *     remove(mapping, cb),
 *     list(cb),                      // cb(null, mappings) — what is in place now
 *     destroy(cb)
 *   }
 *
 * The capabilities are not documentation. They are the reason a caller can
 * demand a property and be refused rather than silently degraded:
 *
 *   createServer({ enforce: 'auto', require: { preservesSourceIp: true } })
 *
 * That matters because the userspace relay — the only adapter that runs
 * without root, on any platform — cannot preserve the source address. An
 * application that logs, rate-limits or geo-restricts by client IP would see
 * every connection arriving from the router itself. Being told is better than
 * finding out.
 */

import { PortMapValidationError } from '../errors.js';
import { relay, noop } from './relay.js';
import { nftables } from './nftables.js';
import { iptables } from './iptables.js';
import { pf } from './pf.js';
import { conformance } from './conformance.js';
import { dbg } from '../debug.js';


/**
 * The full set of capability keys, with the conservative default for each.
 * An adapter states what it can do; anything it omits is assumed absent.
 */
const CAPABILITY_DEFAULTS = {
  platforms:         [],        // process.platform values this works on
  requiresRoot:      true,
  requiresPort:      false,     // does it have to bind the external port itself?
  preservesSourceIp: false,     // does the internal host see the real client?
  forwardsSourceIp:  false,     // is it carried in band instead, e.g. PROXY protocol?
  protocols:         [],        // 'tcp' | 'udp'
  families:          [],        // 'ipv4' | 'ipv6'
  hairpin:           false,     // does traffic from inside the LAN work too?
  throughput:        'unknown', // 'wire-speed' | 'medium' | 'none'
  persistent:        false      // does it survive this process exiting?
};


function capabilities_of(adapter) {
  return Object.assign({}, CAPABILITY_DEFAULTS, (adapter && adapter.capabilities) || {});
}


/**
 * Preference order when nothing is specified. Kernel adapters first, because
 * they are faster and keep the client's address; the relay last, because it
 * always works.
 */
const PREFERENCE = ['nftables', 'iptables', 'pf', 'relay', 'noop'];


function rank_of(name) {
  var i = PREFERENCE.indexOf(name);
  return i === -1 ? PREFERENCE.length : i;
}


/**
 * Does this adapter satisfy every demanded capability?
 * Array capabilities are satisfied when they contain everything demanded.
 */
function satisfies(adapter, required) {
  if (!required) return { ok: true };

  var caps = capabilities_of(adapter);
  var names = Object.keys(required);

  for (var i = 0; i < names.length; i++) {
    var name = names[i];
    var want = required[name];
    var have = caps[name];

    if (Array.isArray(want)) {
      for (var j = 0; j < want.length; j++) {
        if (!Array.isArray(have) || have.indexOf(want[j]) === -1) {
          return { ok: false, reason: name + ' does not include ' + want[j] };
        }
      }
      continue;
    }

    if (have !== want) {
      return { ok: false, reason: name + ' is ' + have + ', not ' + want };
    }
  }

  return { ok: true };
}


/**
 * Pick an adapter from a list.
 *
 *   select([nftables(), relay()], { require: { preservesSourceIp: true } }, cb)
 *
 * Every candidate is asked whether it is usable here, in parallel, and the
 * best available one that meets the requirements wins. The result always
 * carries the full report, so a caller can say why something was not chosen.
 *
 * cb(err, { adapter, capabilities, rejected: [{ name, reason }] })
 */
function select(adapters, options, cb) {
  if (typeof options === 'function') { cb = options; options = {}; }
  options = options || {};

  if (!Array.isArray(adapters) || adapters.length === 0) {
    return cb(new PortMapValidationError('no enforcement adapters given', 'enforce'));
  }

  var required = options.require || null;
  var results = [];
  var pending = adapters.length;

  adapters.forEach(function(adapter, index) {
    var name = adapter.name || ('adapter' + index);

    var fit = satisfies(adapter, required);
    if (!fit.ok) {
      results[index] = { adapter: adapter, name: name, available: false, reason: fit.reason };
      if (--pending === 0) finish();
      return;
    }

    var platforms = capabilities_of(adapter).platforms;
    if (platforms.length && platforms.indexOf(process.platform) === -1) {
      results[index] = { adapter: adapter, name: name, available: false,
                         reason: 'not available on ' + process.platform };
      if (--pending === 0) finish();
      return;
    }

    if (typeof adapter.check !== 'function') {
      results[index] = { adapter: adapter, name: name, available: true };
      if (--pending === 0) finish();
      return;
    }

    adapter.check(function(err, res) {
      results[index] = err
        ? { adapter: adapter, name: name, available: false, reason: err.message }
        : { adapter: adapter, name: name, available: !!(res && res.available),
            reason: res && res.reason };
      if (--pending === 0) finish();
    });
  });

  function finish() {
    var usable = results.filter(function(r) { return r.available; });
    var rejected = results.filter(function(r) { return !r.available; })
                          .map(function(r) { return { name: r.name, reason: r.reason }; });

    if (!usable.length) {
      var err = new PortMapValidationError(
        'No enforcement adapter is usable here: ' +
        rejected.map(function(r) { return r.name + ' (' + r.reason + ')'; }).join(', '),
        'enforce');
      err.rejected = rejected;
      return cb(err, { adapter: null, capabilities: null, rejected: rejected });
    }

    usable.sort(function(a, b) { return rank_of(a.name) - rank_of(b.name); });
    var chosen = usable[0].adapter;

    dbg('enforce', 'selected', usable[0].name,
        rejected.length ? '(rejected: ' + rejected.map(function(r) { return r.name; }).join(', ') + ')' : '');

    cb(null, {
      adapter:      chosen,
      name:         usable[0].name,
      capabilities: capabilities_of(chosen),
      rejected:     rejected,
      warnings:     warnings_for(chosen)
    });
  }
}


/**
 * Things a caller should be told about the adapter that won, phrased as
 * consequences rather than as flags.
 */
function warnings_for(adapter) {
  var caps = capabilities_of(adapter);
  var out = [];

  if (!caps.preservesSourceIp && caps.forwardsSourceIp) {
    out.push('Source addresses are not preserved at the IP layer, but are sent ' +
             'in band with the PROXY protocol: the internal service must be ' +
             'configured to read that header, or it will treat it as garbage.');
  } else if (!caps.preservesSourceIp) {
    out.push('Source addresses are not preserved: internal hosts will see every ' +
             'connection as coming from this gateway, so their logs, access rules ' +
             'and rate limits will not see the real client. Enable the PROXY ' +
             'protocol if the internal service understands it.');
  }
  if (!caps.hairpin) {
    out.push('Hairpin traffic is not handled: a host inside the LAN connecting to ' +
             'the external address will not reach the mapped service.');
  }
  if (!caps.persistent) {
    out.push('Rules disappear when this process exits.');
  }
  if (caps.requiresPort) {
    out.push('The external port must be free on this machine, since the adapter ' +
             'binds it directly.');
  }

  return out;
}


/**
 * Every adapter this library ships, in preference order. Anything not usable
 * here is filtered out by select(), so this is the right list to hand it.
 */
function all(options) {
  options = options || {};
  return [
    nftables(options.nftables || {}),
    iptables(options.iptables || {}),
    pf(options.pf || {}),
    relay(options.relay || {})
  ];
}


export {
  CAPABILITY_DEFAULTS, PREFERENCE, capabilities_of, satisfies, select, warnings_for,
  all, nftables, iptables, pf, relay, noop, conformance
};
