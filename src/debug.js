/**
 * debug.js — Debug logging helper.
 *
 * Enabled via PORTMAP_DEBUG=1 env var.
 *
 * Tags: 'session', 'wire', 'transport', 'discovery', 'mapping', 'enforce'
 */

var DEBUG = false;
try {
  DEBUG = typeof process !== 'undefined'
       && process.env
       && (process.env.PORTMAP_DEBUG === '1' || process.env.PORTMAP_DEBUG === 'true');
} catch (e) {}


function dbg(tag, message) {
  if (!DEBUG) return;
  var args = ['[port-mapper ' + tag + ']', message];
  for (var i = 2; i < arguments.length; i++) args.push(arguments[i]);
  console.error.apply(console, args);
}


function isEnabled() { return DEBUG; }


export { dbg, isEnabled };
