/**
 * enforce/exec.js — running system commands, shared by the kernel adapters.
 *
 * The kernel's NAT tables are configured over AF_NETLINK sockets, which Node
 * exposes no interface to: `net` and `dgram` cover TCP, UDP and IPC and
 * nothing else. Reaching netlink means a compiled binding, which would break
 * the promise that this installs without a toolchain. So the same route the
 * DHCP server's conflict probe already takes is used here — spawn the
 * administrative tool, exactly as an operator would.
 *
 * Everything goes through spawn() with an argument array rather than a shell
 * string. Descriptions, interface names and addresses reach these adapters
 * from a gateway session that got them off the network, so a shell would be
 * an injection point for anything that can talk to the gateway.
 */

import { spawn } from 'node:child_process';
import { dbg } from '../debug.js';
import { PortMapNetworkError } from '../errors.js';


/**
 * Run a command and collect its output.
 *
 *   run('nft', ['list', 'table', 'ip', 'port-mapper'], function (err, out) { ... })
 *
 * A non-zero exit is an error carrying `code` and whatever the tool wrote to
 * stderr, because those messages are usually the only useful diagnosis
 * available — "Operation not permitted", "No such file or directory".
 */
function run(command, args, options, cb) {
  if (typeof options === 'function') { cb = options; options = {}; }
  options = options || {};

  var timeout = options.timeout || 5000;
  var finished = false;

  function finish(err, stdout, stderr) {
    if (finished) return;
    finished = true;
    clearTimeout(guard);
    cb(err, stdout, stderr);
  }

  var child;
  try {
    child = spawn(command, args, { stdio: ['pipe', 'pipe', 'pipe'] });
  } catch (e) {
    return cb(new PortMapNetworkError('Could not run ' + command + ': ' + e.message, e));
  }

  var guard = setTimeout(function() {
    try { child.kill(); } catch (e) {}
    finish(new PortMapNetworkError(command + ' timed out after ' + timeout + 'ms'));
  }, timeout);

  var out = '', err_out = '';
  child.stdout.on('data', function(d) { out += d.toString(); });
  child.stderr.on('data', function(d) { err_out += d.toString(); });

  child.on('error', function(e) {
    // ENOENT here means the tool is simply not installed, which is a normal
    // answer to "is this adapter usable" rather than a failure
    finish(new PortMapNetworkError(
      e.code === 'ENOENT' ? command + ' is not installed' : command + ': ' + e.message, e));
  });

  child.on('close', function(code) {
    dbg('enforce', command, args.join(' '), '→', code);
    if (code === 0) return finish(null, out, err_out);

    var message = (err_out || out || '').trim().split('\n')[0] || ('exit ' + code);
    var error = new PortMapNetworkError(command + ': ' + message);
    error.exitCode = code;
    error.stderr = err_out;
    finish(error, out, err_out);
  });

  if (options.stdin !== undefined) {
    try { child.stdin.end(options.stdin); } catch (e) {}
  } else {
    try { child.stdin.end(); } catch (e) {}
  }
}


/** Run several commands in order, stopping at the first failure. */
function run_series(commands, cb) {
  var outputs = [];

  function step(i) {
    if (i >= commands.length) return cb(null, outputs);
    var c = commands[i];
    run(c.command, c.args, c.options || {}, function(err, out) {
      if (err && !c.ignoreErrors) return cb(err, outputs);
      outputs.push(out);
      step(i + 1);
    });
  }

  step(0);
}


/**
 * Is this tool present and usable by this process?
 *
 * Presence and permission are separate answers on purpose. A tool that is
 * installed but refuses because we are not root is a different situation from
 * one that is not there at all, and the caller's next step differs: run with
 * sudo, or install a package, or accept the userspace relay.
 */
function probe_tool(command, args, cb) {
  run(command, args, { timeout: 3000 }, function(err) {
    if (!err) return cb(null, { available: true });

    var message = err.message || '';
    if (/not installed/.test(message)) {
      return cb(null, { available: false, reason: command + ' is not installed' });
    }
    if (/not permitted|Permission denied|must be root|EACCES/i.test(message) ||
        (process.getuid && process.getuid() !== 0)) {
      return cb(null, { available: false, reason: command + ' needs root' });
    }
    cb(null, { available: false, reason: message });
  });
}


export { run, run_series, probe_tool };
