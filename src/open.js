/**
 * open.js — the one-line entry point.
 *
 * Most callers want a port reachable and do not care how, so this runs both
 * address families and reports whichever worked:
 *
 *   import { open } from 'port-mapper'
 *
 *   open(8080, function (err, mapping) {
 *     if (err) return console.error(err.message)
 *     console.log('Reachable at ' + mapping.address)
 *     // ... later
 *     mapping.close(function () {})
 *   })
 *
 * Both families are attempted by default because a developer opening a port
 * wants it open, not a decision about IP versions. Failure of one is not
 * failure: IPv6 mapping needs an IGD:2 gateway with WANIPv6FirewallControl or
 * a PCP one, and most consumer hardware has neither — while IPv4 increasingly
 * runs into carrier-grade NAT that IPv6 walks straight past. Either one
 * succeeding is a success, and `failures` says what the other hit.
 *
 * The flags follow the shape used elsewhere in this stack — `{ ipv4, ipv6 }`
 * rather than a family string — so turning one off reads the same way here as
 * it does in mdns-local.
 */

import { createMapper } from './mapper.js';
import { PortMapValidationError } from './errors.js';


/** Format a host and port the way a URL would carry it. */
function format_address(host, port) {
  if (!host) return null;
  return (host.indexOf(':') !== -1 ? '[' + host + ']' : host) + ':' + port;
}


function open(port, options, cb) {
  if (typeof options === 'function') { cb = options; options = {}; }
  options = options || {};
  cb = cb || function() {};

  if (typeof port !== 'number' || port < 1 || port > 65535) {
    return cb(new PortMapValidationError('port must be a number between 1 and 65535', 'port'));
  }

  var want4 = options.ipv4 !== false;
  var want6 = options.ipv6 !== false;
  if (!want4 && !want6) {
    return cb(new PortMapValidationError(
      'at least one of ipv4 or ipv6 must be enabled', 'ipv4'));
  }

  var results = { ipv4: null, ipv6: null };
  var mappers = { ipv4: null, ipv6: null };
  var failures = [];
  var pending = 0;
  var finished = false;


  function attempt(family, next) {
    var mapper;
    try {
      mapper = createMapper(Object.assign({}, options, { family: family }));
    } catch (e) {
      // No interface in that family, usually — a fact about the host rather
      // than an error worth stopping for
      failures.push({ family: family, error: e });
      return next();
    }

    mappers[family] = mapper;

    mapper.start(function(err) {
      if (err) {
        failures.push({ family: family, error: err });
        return mapper.stop(function() { mappers[family] = null; next(); });
      }

      mapper.map({
        internalPort: port,
        externalPort: options.externalPort === undefined ? port : options.externalPort,
        protocol:     options.protocol || 'tcp',
        lifetime:     options.lifetime,
        remoteHost:   options.remoteHost,
        remotePort:   options.remotePort,
        // "this port or nothing" versus "this port, or whatever is free"
        exact:        options.exact,
        onConflict:   options.onConflict
      }, function(err2, mapping) {
        if (err2) {
          failures.push({ family: family, error: err2 });
          return mapper.stop(function() { mappers[family] = null; next(); });
        }
        results[family] = mapping;
        next();
      });
    });
  }


  function finish() {
    if (finished) return;
    finished = true;

    if (!results.ipv4 && !results.ipv6) {
      // Report the failure that is most likely to be the real obstacle: a
      // caller with no IPv6 does not want to read about IPv6
      var primary = failures.filter(function(f) { return f.family === 'ipv4'; })[0] ||
                    failures[0];
      var err = primary ? primary.error : new PortMapValidationError('no mapping was made');
      err.failures = failures;
      return cb(err);
    }

    cb(null, build());
  }


  function build() {
    var v4 = results.ipv4;
    var v6 = results.ipv6;

    var addresses = [];
    if (v4) addresses.push(format_address(v4.externalIp, v4.externalPort));
    if (v6) addresses.push(format_address(v6.externalIp || v6.internalIp,
                                          v6.externalPort || v6.internalPort));

    // The primary result stays IPv4 when there is one, so the familiar
    // `externalIp` and `externalPort` keep meaning what they always did
    var primary = v4 || v6;

    var mapping = Object.assign({}, primary, {
      // One address that is always usable, whichever family succeeded. Without
      // it, code that reads externalIp directly prints "null:null" on a host
      // where only IPv6 worked — through no fault of its own.
      address:   addresses[0],
      addresses: addresses,
      families:  [].concat(v4 ? ['ipv4'] : [], v6 ? ['ipv6'] : []),
      ipv4:      v4 || null,
      ipv6:      v6 || null,
      failures:  failures,
      mapper:    mappers.ipv4 || mappers.ipv6,
      mappers:   mappers
    });

    mapping.close = function(done) {
      done = done || function() {};
      var open_mappers = [mappers.ipv4, mappers.ipv6].filter(Boolean);
      if (!open_mappers.length) return setImmediate(done);
      var left = open_mappers.length;
      open_mappers.forEach(function(m) {
        m.close(function() { if (--left === 0) done(); });
      });
    };

    /**
     * Diagnose each family separately.
     *
     * One number would hide the case that is becoming common: unreachable over
     * IPv4 because of carrier-grade NAT, and perfectly reachable over IPv6. A
     * caller shown a single `reachable: false` would give up for no reason.
     */
    mapping.diagnose = function(done) {
      done = done || function() {};
      var report = { reachable: false, ipv4: null, ipv6: null };
      var families = Object.keys(mappers).filter(function(f) { return mappers[f]; });
      var left = families.length;
      if (!left) return setImmediate(function() { done(null, report); });

      families.forEach(function(f) {
        mappers[f].diagnose(function(_, d) {
          report[f] = d;
          if (d && d.reachable) report.reachable = true;
          if (--left === 0) {
            // The detail of whichever family is actually usable, or of IPv4
            // when neither is, since that is the one most callers will act on
            var lead = (report.ipv4 && report.ipv4.reachable) ? report.ipv4
                     : (report.ipv6 && report.ipv6.reachable) ? report.ipv6
                     : report.ipv4 || report.ipv6;
            report.reason     = lead ? lead.reason : null;
            report.detail     = lead ? lead.detail : null;
            report.suggestion = lead ? lead.suggestion : null;
            done(null, report);
          }
        });
      });
    };

    return mapping;
  }


  // Both families are tried at once: they touch different sockets and
  // different gateways, and running them in sequence would add the whole of
  // one negotiation to every start on a host that only has the other.
  if (want4) pending++;
  if (want6) pending++;

  function next() { if (--pending === 0) finish(); }

  if (want4) attempt('ipv4', next);
  if (want6) attempt('ipv6', next);

  return {
    cancel: function(reason) {
      var cancelled = false;
      [mappers.ipv4, mappers.ipv6].forEach(function(m) {
        if (m && m.cancelAll && m.cancelAll(reason) > 0) cancelled = true;
      });
      return cancelled;
    }
  };
}


export { open, format_address };
export default open;
