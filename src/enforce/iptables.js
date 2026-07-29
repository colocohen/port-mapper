/**
 * enforce/iptables.js — kernel NAT through iptables.
 *
 * The predecessor of nftables, and still what a great many systems run:
 * older distributions, most container images, and a large amount of embedded
 * networking gear. On modern distributions `iptables` is often a compatibility
 * shim that writes nftables rules underneath, which works but means the two
 * adapters can see each other's work — a reason to prefer nftables when both
 * are available, as the selection order does.
 *
 * Two differences from nftables shape this file:
 *
 *   Rules are deleted by repeating their full specification, not by a handle.
 *   The delete command is the add command with -A swapped for -D, so the
 *   arguments have to be reproduced exactly — a single differing flag and the
 *   rule stays.
 *
 *   There are no per-table user chains by default, so one is created and
 *   jumped to from PREROUTING. Everything then lives inside it, which keeps
 *   the operator's own rules out of reach and makes cleanup a flush.
 */

import { run as system_run, run_series as system_run_series, probe_tool } from './exec.js';
import { dbg } from '../debug.js';
import { PortMapNetworkError, PortMapValidationError } from '../errors.js';


function iptables(options) {
  options = options || {};

  /**
   * How commands are run. Defaults to spawning the real tool; a test supplies
   * its own to assert on the exact command built for a given mapping, which is
   * where the mistakes in this file would be — a rule that differs by one flag
   * from the one that created it can never be deleted again.
   */
  var run = options.exec || system_run;
  var run_series = options.execSeries || function(commands, cb) {
    if (!options.exec) return system_run_series(commands, cb);
    var outputs = [];
    (function step(i) {
      if (i >= commands.length) return cb(null, outputs);
      run(commands[i].command, commands[i].args, commands[i].options || {}, function(err, out) {
        if (err && !commands[i].ignoreErrors) return cb(err, outputs);
        outputs.push(out);
        step(i + 1);
      });
    })(0);
  };

  var family  = options.family === 'ipv6' ? 'ipv6' : 'ipv4';
  var command = options.command || (family === 'ipv6' ? 'ip6tables' : 'iptables');
  var chain   = options.chain || 'PORTMAPPER';
  var forward_chain = chain + '_FWD';
  var wan     = options.wanInterface || null;
  var hairpin = options.hairpin !== false;
  var initialised = false;
  var destroyed = false;

  var entries = Object.create(null);
  var seq = 0;


  function key_of(protocol, port) { return String(protocol).toLowerCase() + ':' + port; }
  function comment_for(protocol, port) { return 'port-mapper:' + protocol + ':' + port; }


  /**
   * Create the chains and hook them in, idempotently. `-N` on a chain that
   * exists is an error, and `-A` on a jump that exists would add a duplicate,
   * so each is guarded: create-and-ignore, then check-before-append.
   */
  function init_commands() {
    return [
      { command: command, args: ['-t', 'nat', '-N', chain], ignoreErrors: true },
      { command: command, args: ['-t', 'filter', '-N', forward_chain], ignoreErrors: true },
      // -C is the check form: it succeeds when the rule is present, so the
      // append only runs when it is missing
      { command: command, args: ['-t', 'nat', '-C', 'PREROUTING', '-j', chain],
        ignoreErrors: true, guard: true },
      { command: command, args: ['-t', 'filter', '-C', 'FORWARD', '-j', forward_chain],
        ignoreErrors: true, guard: true }
    ];
  }


  function ensure_jumps(cb) {
    run(command, ['-t', 'nat', '-C', 'PREROUTING', '-j', chain], function(err) {
      var next = err
        ? [{ command: command, args: ['-t', 'nat', '-I', 'PREROUTING', '1', '-j', chain] }]
        : [];

      run(command, ['-t', 'filter', '-C', 'FORWARD', '-j', forward_chain], function(err2) {
        if (err2) {
          next.push({ command: command,
                      args: ['-t', 'filter', '-I', 'FORWARD', '1', '-j', forward_chain] });
        }
        run_series(next, function(e) { cb(e); });
      });
    });
  }


  /**
   * The rule specification, without the -A/-D verb. Both add and remove build
   * it from here so the delete can never drift from the insert.
   */
  function dnat_spec(mapping) {
    var protocol = String(mapping.protocol).toLowerCase();
    var spec = ['-t', 'nat', chain];
    if (wan) spec = spec.concat(['-i', wan]);
    return spec.concat([
      '-p', protocol,
      '--dport', String(mapping.externalPort),
      '-m', 'comment', '--comment', comment_for(protocol, mapping.externalPort),
      '-j', 'DNAT',
      '--to-destination', family === 'ipv6'
        ? '[' + mapping.internalIp + ']:' + mapping.internalPort
        : mapping.internalIp + ':' + mapping.internalPort
    ]);
  }


  function forward_spec(mapping) {
    var protocol = String(mapping.protocol).toLowerCase();
    return ['-t', 'filter', forward_chain,
            '-d', mapping.internalIp,
            '-p', protocol,
            '--dport', String(mapping.internalPort),
            '-m', 'conntrack', '--ctstate', 'NEW,ESTABLISHED,RELATED',
            '-m', 'comment', '--comment', comment_for(protocol, mapping.externalPort),
            '-j', 'ACCEPT'];
  }


  function hairpin_spec(mapping) {
    var protocol = String(mapping.protocol).toLowerCase();
    return ['-t', 'nat', 'POSTROUTING',
            '-d', mapping.internalIp,
            '-p', protocol,
            '--dport', String(mapping.internalPort),
            '-m', 'comment', '--comment', comment_for(protocol, mapping.externalPort),
            '-j', 'MASQUERADE'];
  }


  function verb(spec, v) {
    // spec is [-t, table, chain, ...]; the verb goes between table and chain
    return [spec[0], spec[1], v, spec[2]].concat(spec.slice(3));
  }


  /**
   * Read our chain back. `-S` prints rules as the commands that would create
   * them, which is the only machine-readable form iptables offers.
   */
  function list_rules(cb) {
    run(command, ['-t', 'nat', '-S', chain], function(err, out) {
      if (err) {
        if (/No chain|does not exist/i.test(err.message)) return cb(null, []);
        return cb(err);
      }

      var rules = [];
      var lines = (out || '').split('\n');
      for (var i = 0; i < lines.length; i++) {
        var line = lines[i];
        if (line.indexOf('port-mapper:') === -1) continue;

        var comment = /--comment\s+"?(port-mapper:[^"\s]+)"?/.exec(line);
        var to = /--to-destination\s+(\S+)/.exec(line);
        if (!comment) continue;

        var parts = comment[1].split(':');
        var dest = to ? to[1] : '';
        var m = /^\[?([^\]]+)\]?:(\d+)$/.exec(dest);

        rules.push({
          protocol:     parts[1],
          externalPort: parseInt(parts[2], 10),
          internalIp:   m ? m[1] : null,
          internalPort: m ? parseInt(m[2], 10) : null
        });
      }
      cb(null, rules);
    });
  }


  return {
    name: 'iptables',

    capabilities: {
      platforms:         ['linux'],
      requiresRoot:      true,
      requiresPort:      false,
      preservesSourceIp: true,
      forwardsSourceIp:  true,
      protocols:         ['tcp', 'udp'],
      families:          ['ipv4', 'ipv6'],
      hairpin:           hairpin,
      throughput:        'wire-speed',
      persistent:        true
    },

    check: function(cb) {
      if (process.platform !== 'linux') {
        return cb(null, { available: false, reason: 'iptables is Linux only' });
      }
      probe_tool(command, ['-t', 'nat', '-L', '-n'], cb);
    },

    init: function(config, cb) {
      if (typeof config === 'function') { cb = config; config = {}; }
      config = config || {};
      if (config.wanInterface) wan = config.wanInterface;

      run_series(init_commands().filter(function(c) { return !c.guard; }), function(err) {
        if (err) return cb(err);
        ensure_jumps(function(err2) {
          if (err2) return cb(err2);
          initialised = true;
          dbg('enforce', 'iptables chain', chain, 'ready');
          cb(null);
        });
      });
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

      var self = this;
      function write() {
        self.remove({ protocol: protocol, externalPort: mapping.externalPort }, function() {
          var commands = [
            { command: command, args: verb(dnat_spec(mapping), '-A') },
            { command: command, args: verb(forward_spec(mapping), '-A'), ignoreErrors: true }
          ];
          if (hairpin) {
            commands.push({ command: command, args: verb(hairpin_spec(mapping), '-A'),
                            ignoreErrors: true });
          }

          run_series(commands, function(err) {
            if (err) return cb(err);
            seq++;
            entries[key_of(protocol, mapping.externalPort)] = {
              protocol: protocol, externalPort: mapping.externalPort,
              internalIp: mapping.internalIp, internalPort: mapping.internalPort,
              handle: seq, mapping: mapping
            };
            cb(null, { handle: seq });
          });
        });
      }

      if (initialised) return write();
      this.init({}, function(err) {
        if (err) return cb(err);
        write();
      });
    },

    remove: function(mapping, cb) {
      cb = cb || function() {};
      var protocol = String(mapping.protocol).toLowerCase();
      var key = key_of(protocol, mapping.externalPort);
      var known = entries[key];

      // A delete has to repeat the full specification, so the original mapping
      // is needed. Without it — a rule from a previous run — the destination
      // is read back out of the chain instead.
      function with_mapping(full) {
        if (!full) return cb(null);
        var commands = [
          { command: command, args: verb(dnat_spec(full), '-D'), ignoreErrors: true },
          { command: command, args: verb(forward_spec(full), '-D'), ignoreErrors: true }
        ];
        if (hairpin) {
          commands.push({ command: command, args: verb(hairpin_spec(full), '-D'),
                          ignoreErrors: true });
        }
        run_series(commands, function() {
          delete entries[key];
          cb(null);
        });
      }

      if (known) return with_mapping(known.mapping || known);

      list_rules(function(err, rules) {
        if (err) return cb(null);
        for (var i = 0; i < rules.length; i++) {
          if (rules[i].protocol === protocol &&
              rules[i].externalPort === Number(mapping.externalPort)) {
            return with_mapping(rules[i]);
          }
        }
        cb(null);
      });
    },

    list: function(cb) {
      list_rules(function(err, rules) {
        if (err) return cb(err);
        cb(null, rules.map(function(r) {
          var known = entries[key_of(r.protocol, r.externalPort)];
          return {
            protocol:     r.protocol,
            externalPort: r.externalPort,
            internalIp:   r.internalIp,
            internalPort: r.internalPort,
            handle:       known ? known.handle : null
          };
        }));
      });
    },

    destroy: function(cb) {
      cb = cb || function() {};
      if (destroyed) return cb(null);
      destroyed = true;
      entries = Object.create(null);

      // Unhook first, then empty, then remove: a chain that is still jumped to
      // cannot be deleted, and one that still holds rules cannot either
      run_series([
        { command: command, args: ['-t', 'nat', '-D', 'PREROUTING', '-j', chain],
          ignoreErrors: true },
        { command: command, args: ['-t', 'filter', '-D', 'FORWARD', '-j', forward_chain],
          ignoreErrors: true },
        { command: command, args: ['-t', 'nat', '-F', chain], ignoreErrors: true },
        { command: command, args: ['-t', 'filter', '-F', forward_chain], ignoreErrors: true },
        { command: command, args: ['-t', 'nat', '-X', chain], ignoreErrors: true },
        { command: command, args: ['-t', 'filter', '-X', forward_chain], ignoreErrors: true }
      ], function() { cb(null); });
    }
  };
}


export { iptables };
export default iptables;
