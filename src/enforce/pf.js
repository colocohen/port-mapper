/**
 * enforce/pf.js — kernel NAT through pf.
 *
 * The packet filter on FreeBSD, OpenBSD, NetBSD and macOS. It works quite
 * differently from the Linux tools, and the difference drives the design of
 * this file:
 *
 *   pf has no incremental rule commands. There is no "add this one rule" —
 *   an anchor is loaded from a complete ruleset, replacing whatever was there.
 *   So every add and remove rewrites the whole anchor from the set of mappings
 *   held here, and this adapter's own table is authoritative rather than
 *   advisory. That also means the rules do not survive this process unless
 *   they are reloaded, which is why `persistent` is false here and true for
 *   the Linux adapters.
 *
 *   The anchor keeps our rules apart from the operator's, the way a private
 *   table does under nftables, but it has to be declared in the main
 *   /etc/pf.conf before it can be loaded into — `anchor "port-mapper"`.
 *   check() looks for it and says so, because a missing anchor declaration is
 *   the failure most likely to look like a silent no-op.
 *
 * macOS is a caveat rather than a target. Apple manages parts of pf itself and
 * rules added from outside can be discarded, so this adapter is dependable on
 * the BSDs and best-effort on macOS.
 */

import { run as system_run, probe_tool } from './exec.js';
import { dbg } from '../debug.js';
import { PortMapNetworkError, PortMapValidationError } from '../errors.js';


function pf(options) {
  options = options || {};

  /**
   * How commands are run. Defaults to spawning the real tool; a test supplies
   * its own to assert on the exact command built for a given mapping, which is
   * where the mistakes in this file would be — a rule that differs by one flag
   * from the one that created it can never be deleted again.
   */
  var run = options.exec || system_run;

  var anchor  = options.anchor || 'port-mapper';
  var command = options.command || 'pfctl';
  var wan     = options.wanInterface || null;
  var family  = options.family === 'ipv6' ? 'inet6' : 'inet';
  var destroyed = false;

  var entries = Object.create(null);
  var seq = 0;


  function key_of(protocol, port) { return String(protocol).toLowerCase() + ':' + port; }


  /**
   * Build the complete ruleset for the anchor.
   *
   * `rdr pass` does the redirect and lets the packet through in one rule,
   * which is pf's equivalent of the DNAT-plus-forward-accept pair the Linux
   * adapters need two rules for.
   */
  function ruleset() {
    var lines = [];
    var keys = Object.keys(entries);

    for (var i = 0; i < keys.length; i++) {
      var e = entries[keys[i]];
      var on = wan ? 'on ' + wan + ' ' : '';
      lines.push(
        'rdr pass ' + on + family + ' proto ' + e.protocol +
        ' from any to any port ' + e.externalPort +
        ' -> ' + e.internalIp + ' port ' + e.internalPort
      );
    }

    // pfctl reads an empty ruleset as "clear the anchor", which is exactly
    // what should happen when the last mapping goes away
    return lines.join('\n') + (lines.length ? '\n' : '');
  }


  function reload(cb) {
    var rules = ruleset();
    dbg('enforce', 'pf anchor', anchor, 'reload,', Object.keys(entries).length, 'rule(s)');

    run(command, ['-a', anchor, '-f', '-'], { stdin: rules }, function(err) {
      if (!err) return cb(null);
      cb(new PortMapNetworkError(
        'Could not load the pf anchor "' + anchor + '": ' + err.message +
        ' — the anchor must be declared in /etc/pf.conf as: anchor "' + anchor + '"', err));
    });
  }


  return {
    name: 'pf',

    capabilities: {
      platforms:         ['darwin', 'freebsd', 'openbsd', 'netbsd'],
      requiresRoot:      true,
      requiresPort:      false,
      preservesSourceIp: true,
      forwardsSourceIp:  true,
      protocols:         ['tcp', 'udp'],
      families:          ['ipv4', 'ipv6'],
      // A separate no-nat/nat rule would be needed for traffic originating
      // inside the LAN, which this adapter does not write
      hairpin:           false,
      throughput:        'wire-speed',
      // The anchor is loaded, not stored: nothing reloads it after a reboot
      persistent:        false
    },

    check: function(cb) {
      var platforms = ['darwin', 'freebsd', 'openbsd', 'netbsd'];
      if (platforms.indexOf(process.platform) === -1) {
        return cb(null, { available: false, reason: 'pf is BSD and macOS only' });
      }

      probe_tool(command, ['-s', 'info'], function(err, res) {
        if (err || !res.available) return cb(err, res);

        // Being able to run pfctl is not enough: without the anchor declared
        // in the main ruleset, loading into it succeeds and forwards nothing
        run(command, ['-s', 'Anchors'], function(e, out) {
          if (e) return cb(null, { available: true });
          if ((out || '').indexOf(anchor) === -1) {
            return cb(null, {
              available: false,
              reason: 'the anchor "' + anchor + '" is not declared in /etc/pf.conf — ' +
                      'add: anchor "' + anchor + '"'
            });
          }
          cb(null, { available: true });
        });
      });
    },

    init: function(config, cb) {
      if (typeof config === 'function') { cb = config; config = {}; }
      config = config || {};
      if (config.wanInterface) wan = config.wanInterface;

      // Enabling pf is deliberately not done here. It is a system-wide switch
      // that can drop every connection on the host if the main ruleset is not
      // ready for it, and that is an operator's decision, not a library's.
      reload(cb);
    },

    add: function(mapping, cb) {
      if (destroyed) return cb(new PortMapNetworkError('adapter destroyed'));
      if (!mapping.internalIp) {
        return cb(new PortMapValidationError('internalIp required', 'internalIp'));
      }

      var protocol = String(mapping.protocol).toLowerCase();
      if (protocol !== 'tcp' && protocol !== 'udp') {
        return cb(new PortMapValidationError('protocol must be tcp or udp', 'protocol'));
      }

      var key = key_of(protocol, mapping.externalPort);
      var previous = entries[key];
      seq++;

      entries[key] = {
        protocol:     protocol,
        externalPort: mapping.externalPort,
        internalIp:   mapping.internalIp,
        internalPort: mapping.internalPort,
        handle:       seq
      };

      reload(function(err) {
        if (err) {
          // Put the anchor back the way it was rather than leaving this
          // process believing in a rule the kernel never accepted
          if (previous) entries[key] = previous;
          else delete entries[key];
          return cb(err);
        }
        cb(null, { handle: seq });
      });
    },

    remove: function(mapping, cb) {
      cb = cb || function() {};
      var key = key_of(String(mapping.protocol).toLowerCase(), mapping.externalPort);
      if (!entries[key]) return cb(null);

      var previous = entries[key];
      delete entries[key];
      reload(function(err) {
        if (err) { entries[key] = previous; return cb(err); }
        cb(null);
      });
    },

    list: function(cb) {
      cb(null, Object.keys(entries).map(function(k) {
        var e = entries[k];
        return {
          protocol:     e.protocol,
          externalPort: e.externalPort,
          internalIp:   e.internalIp,
          internalPort: e.internalPort,
          handle:       e.handle
        };
      }));
    },

    destroy: function(cb) {
      cb = cb || function() {};
      if (destroyed) return cb(null);
      destroyed = true;
      entries = Object.create(null);
      // An empty ruleset empties the anchor and leaves the rest of pf alone
      run(command, ['-a', anchor, '-F', 'all'], function() { cb(null); });
    }
  };
}


export { pf };
export default pf;
