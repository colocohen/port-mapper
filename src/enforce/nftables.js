/**
 * enforce/nftables.js — kernel NAT through nftables.
 *
 * nftables replaced iptables as the Linux packet-filtering framework and is
 * the default on Debian 10+, Ubuntu 20.04+ and RHEL 8+. The `nft` binary is
 * the administrative front end; the rules themselves live in the kernel, so
 * they survive this process exiting and cost nothing per packet beyond what
 * the router already does.
 *
 * Everything is created inside a table of our own — `port-mapper` by default.
 * That is not tidiness: it means the adapter never touches a rule somebody
 * else wrote, `list table` sees only our rules, and a reset is one `flush
 * table` rather than a careful search-and-delete through the operator's
 * firewall.
 *
 * Three rules make a working mapping, and leaving out either of the last two
 * is the classic reason a port "is forwarded" and still does not work:
 *
 *   prerouting   dnat   rewrite the destination — the mapping itself
 *   forward      accept let the rewritten packet through the filter, which
 *                       otherwise drops it on any gateway with a default-drop
 *                       policy, after the DNAT has already succeeded
 *   postrouting  snat   hairpin: a host inside the LAN reaching the external
 *                       address needs its source rewritten too, or the reply
 *                       goes direct and the client rejects it
 */

import { run as system_run, run_series as system_run_series, probe_tool } from './exec.js';
import { dbg } from '../debug.js';
import { PortMapNetworkError, PortMapValidationError } from '../errors.js';


// nft accepts a comment on every rule, and it is the only place to record
// which mapping a rule belongs to
const COMMENT_PREFIX = 'port-mapper';


function nftables(options) {
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

  var table    = options.table || 'port-mapper';
  var family   = options.family === 'ipv6' ? 'ip6' : 'ip';
  var wan      = options.wanInterface || null;
  var lan      = options.lanInterface || null;
  var hairpin  = options.hairpin !== false;
  var command  = options.command || 'nft';
  var initialised = false;
  var destroyed = false;

  // externalPort → { handles: { prerouting, forward, postrouting } }
  var entries = Object.create(null);
  var seq = 0;


  function key_of(protocol, port) { return String(protocol).toLowerCase() + ':' + port; }
  function comment_for(protocol, port) { return COMMENT_PREFIX + ':' + protocol + ':' + port; }


  /**
   * Chains are created with the priorities nftables defines for NAT hooks.
   * Using the names rather than numbers keeps them correct relative to
   * whatever else is registered on the same hook.
   */
  function chain_commands() {
    return [
      { command: command, args: ['add', 'table', family, table] },
      { command: command, args: ['add', 'chain', family, table, 'prerouting',
                                 '{ type nat hook prerouting priority dstnat; policy accept; }'] },
      { command: command, args: ['add', 'chain', family, table, 'postrouting',
                                 '{ type nat hook postrouting priority srcnat; policy accept; }'] },
      // filter, not nat: the forward accept has to sit on the filter hook or
      // it will not be consulted when the policy drops
      { command: command, args: ['add', 'chain', family, table, 'forward',
                                 '{ type filter hook forward priority filter; policy accept; }'] }
    ];
  }


  function rule_args(mapping) {
    var protocol = String(mapping.protocol).toLowerCase();
    var dest = family === 'ip6'
      ? '[' + mapping.internalIp + ']:' + mapping.internalPort
      : mapping.internalIp + ':' + mapping.internalPort;

    var pre = ['add', 'rule', family, table, 'prerouting'];
    if (wan) pre = pre.concat(['iif', wan]);
    pre = pre.concat([protocol, 'dport', String(mapping.externalPort),
                      'dnat', 'to', dest,
                      'comment', comment_for(protocol, mapping.externalPort)]);

    var fwd = ['add', 'rule', family, table, 'forward'];
    if (wan) fwd = fwd.concat(['iif', wan]);
    fwd = fwd.concat([family === 'ip6' ? 'ip6' : 'ip', 'daddr', mapping.internalIp,
                      protocol, 'dport', String(mapping.internalPort),
                      'ct', 'state', 'new,established,related', 'accept',
                      'comment', comment_for(protocol, mapping.externalPort)]);

    // Hairpin: a packet that came from the LAN and was just DNATed still has
    // its original source, so the internal service would answer it directly
    // and the client would drop the reply as coming from the wrong address.
    // Masquerading fixes the source so the reply comes back through us.
    var post = ['add', 'rule', family, table, 'postrouting'];
    if (lan) post = post.concat(['oif', lan]);
    post = post.concat([family === 'ip6' ? 'ip6' : 'ip', 'daddr', mapping.internalIp,
                        protocol, 'dport', String(mapping.internalPort),
                        'masquerade',
                        'comment', comment_for(protocol, mapping.externalPort)]);

    return { pre: pre, fwd: fwd, post: post };
  }


  /**
   * Read the table back as JSON. Rules cannot be deleted by their content in
   * nftables — only by the numeric handle the kernel assigned — so anything
   * that removes a rule has to look it up first.
   */
  function list_rules(cb) {
    run(command, ['-a', '-j', 'list', 'table', family, table], function(err, out) {
      if (err) {
        // A table that does not exist yet is an empty table, not a failure
        if (/No such file or directory|does not exist/i.test(err.message)) return cb(null, []);
        return cb(err);
      }

      var parsed;
      try { parsed = JSON.parse(out); }
      catch (e) { return cb(new PortMapNetworkError('Could not read nft output: ' + e.message)); }

      var rules = [];
      var items = (parsed && parsed.nftables) || [];
      for (var i = 0; i < items.length; i++) {
        if (!items[i].rule) continue;
        var r = items[i].rule;
        var comment = r.comment || '';
        if (comment.indexOf(COMMENT_PREFIX + ':') !== 0) continue;
        var parts = comment.split(':');
        rules.push({
          handle:   r.handle,
          chain:    r.chain,
          protocol: parts[1],
          externalPort: parseInt(parts[2], 10),
          expr:     r.expr
        });
      }
      cb(null, rules);
    });
  }


  function delete_by_comment(protocol, external_port, cb) {
    list_rules(function(err, rules) {
      if (err) return cb(err);

      var mine = rules.filter(function(r) {
        return r.protocol === String(protocol).toLowerCase() &&
               r.externalPort === Number(external_port);
      });
      if (!mine.length) return cb(null, 0);

      var commands = mine.map(function(r) {
        return { command: command,
                 args: ['delete', 'rule', family, table, r.chain, 'handle', String(r.handle)],
                 ignoreErrors: true };
      });
      run_series(commands, function(e) { cb(e, mine.length); });
    });
  }


  return {
    name: 'nftables',

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
        return cb(null, { available: false, reason: 'nftables is Linux only' });
      }
      // Listing ruleset needs the same privilege adding a rule does, so this
      // answers both "is nft here" and "may we use it" in one call
      probe_tool(command, ['list', 'ruleset'], cb);
    },

    init: function(config, cb) {
      if (typeof config === 'function') { cb = config; config = {}; }
      config = config || {};
      if (config.wanInterface) wan = config.wanInterface;
      if (config.lanInterface) lan = config.lanInterface;

      run_series(chain_commands(), function(err) {
        if (err) return cb(err);
        initialised = true;
        dbg('enforce', 'nftables table', family, table, 'ready');
        cb(null);
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

      function write() {
        // Replacing rather than stacking: an add for a port we already hold
        // must repoint it, so the old rules go first
        delete_by_comment(protocol, mapping.externalPort, function() {
          var r = rule_args(mapping);
          var commands = [
            { command: command, args: r.pre },
            { command: command, args: r.fwd, ignoreErrors: true }
          ];
          if (hairpin) commands.push({ command: command, args: r.post, ignoreErrors: true });

          run_series(commands, function(err) {
            if (err) return cb(err);
            seq++;
            entries[key_of(protocol, mapping.externalPort)] = {
              protocol:     protocol,
              externalPort: mapping.externalPort,
              internalIp:   mapping.internalIp,
              internalPort: mapping.internalPort,
              handle:       seq
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
      delete_by_comment(protocol, mapping.externalPort, function(err) {
        // Removing what is not there is a success, so reconciliation does not
        // have to check first
        if (err) return cb(err);
        delete entries[key_of(protocol, mapping.externalPort)];
        cb(null);
      });
    },

    /**
     * What is actually in the kernel, not what this process believes. The
     * difference matters after a restart: the rules outlive us, so the table
     * is the truth and our own map is only a cache.
     */
    list: function(cb) {
      list_rules(function(err, rules) {
        if (err) return cb(err);

        var seen = Object.create(null);
        var out = [];
        for (var i = 0; i < rules.length; i++) {
          if (rules[i].chain !== 'prerouting') continue;
          var k = rules[i].protocol + ':' + rules[i].externalPort;
          if (seen[k]) continue;
          seen[k] = true;
          var known = entries[k];
          out.push({
            protocol:     rules[i].protocol,
            externalPort: rules[i].externalPort,
            internalIp:   known ? known.internalIp : null,
            internalPort: known ? known.internalPort : null,
            handle:       rules[i].handle
          });
        }
        cb(null, out);
      });
    },

    destroy: function(cb) {
      cb = cb || function() {};
      if (destroyed) return cb(null);
      destroyed = true;
      entries = Object.create(null);

      // Only our own table is removed. Anything the operator wrote elsewhere
      // is untouched, which is the whole reason for having a private table.
      run(command, ['delete', 'table', family, table], function() { cb(null); });
    }
  };
}


export { nftables };
export default nftables;
