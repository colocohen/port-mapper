/**
 * enforce/conformance.js — the shared adapter test suite.
 *
 * Five backends times several platforms is a matrix nobody tests by hand,
 * which is how "flexible" libraries rot. The interface is small enough that
 * one suite can check all of them, so an adapter is correct when it passes
 * this — whoever wrote it.
 *
 *   import { conformance } from 'port-mapper/enforce'
 *
 *   conformance(relay(), { name: 'relay' }, function (err, report) {
 *     console.log(report.passed + '/' + report.total)
 *   })
 *
 * Checks that need a capability the adapter does not claim are skipped rather
 * than failed: a `noop` adapter that moves no packets is still a valid
 * adapter, and the dataplane checks simply do not apply to it.
 */

import net from 'node:net';
import dgram from 'node:dgram';
import { capabilities_of } from './index.js';


function conformance(adapter, options, cb) {
  if (typeof options === 'function') { cb = options; options = {}; }
  options = options || {};

  var caps = capabilities_of(adapter);
  var name = options.name || adapter.name || 'adapter';
  // A high port, so nothing here needs privileges it was not given
  var port = options.port || (41000 + Math.floor(Math.random() * 2000));

  var results = [];
  var queue = [];

  function test(title, requires, fn) {
    queue.push({ title: title, requires: requires, fn: fn });
  }

  function skip_reason(requires) {
    if (!requires) return null;
    for (var i = 0; i < requires.length; i++) {
      var need = requires[i];
      if (need === 'dataplane' && caps.throughput === 'none') return 'moves no packets';
      if (need === 'root' && process.getuid && process.getuid() !== 0) return 'not running as root';
      if (need === 'tcp' && caps.protocols.indexOf('tcp') === -1) return 'no TCP support';
      if (need === 'udp' && caps.protocols.indexOf('udp') === -1) return 'no UDP support';
    }
    return null;
  }


  /* =========================== The contract =========================== */

  test('shape: every required method exists', null, function(done) {
    ['check', 'init', 'add', 'remove', 'list', 'destroy'].forEach(function(m) {
      if (typeof adapter[m] !== 'function') throw new Error('missing ' + m + '()');
    });
    if (!adapter.name) throw new Error('missing name');
    if (!adapter.capabilities) throw new Error('missing capabilities');
    done();
  });

  test('capabilities: platforms and protocols are declared', null, function(done) {
    if (!Array.isArray(caps.platforms) || !caps.platforms.length) {
      throw new Error('platforms must list at least one platform');
    }
    if (!Array.isArray(caps.protocols)) throw new Error('protocols must be an array');
    done();
  });

  test('check() reports availability without throwing', null, function(done) {
    adapter.check(function(err, res) {
      if (err) return done();                       // unavailable is a valid answer
      if (!res || typeof res.available !== 'boolean') {
        throw new Error('check() must yield { available: boolean }');
      }
      done();
    });
  });

  test('init() accepts a config and a bare callback', null, function(done) {
    adapter.init({}, function(err) {
      if (err) throw err;
      adapter.init(function(err2) {
        if (err2) throw err2;
        done();
      });
    });
  });

  test('add() yields a handle and list() then shows the entry', null, function(done) {
    adapter.add({ protocol: 'tcp', externalPort: port,
                  internalIp: '127.0.0.1', internalPort: port + 1 }, function(err, res) {
      if (err) throw err;
      if (!res || res.handle === undefined) throw new Error('add() must yield { handle }');

      adapter.list(function(err2, list) {
        if (err2) throw err2;
        var found = list.filter(function(e) {
          return e.protocol === 'tcp' && Number(e.externalPort) === port;
        });
        if (!found.length) throw new Error('the entry is missing from list()');
        done();
      });
    });
  });

  test('remove() takes the entry back out', null, function(done) {
    adapter.remove({ protocol: 'tcp', externalPort: port }, function(err) {
      if (err) throw err;
      adapter.list(function(err2, list) {
        if (err2) throw err2;
        var still = list.filter(function(e) {
          return e.protocol === 'tcp' && Number(e.externalPort) === port;
        });
        if (still.length) throw new Error('the entry survived remove()');
        done();
      });
    });
  });

  test('remove() of something absent is not an error', null, function(done) {
    // A caller reconciling its own state against the system should not have
    // to check first
    adapter.remove({ protocol: 'tcp', externalPort: port + 900 }, function(err) {
      if (err) throw new Error('removing an absent entry failed: ' + err.message);
      done();
    });
  });

  test('add() twice on one port replaces rather than duplicating', null, function(done) {
    adapter.add({ protocol: 'tcp', externalPort: port, internalIp: '127.0.0.1',
                  internalPort: port + 1 }, function(err) {
      if (err) throw err;
      adapter.add({ protocol: 'tcp', externalPort: port, internalIp: '127.0.0.1',
                    internalPort: port + 2 }, function(err2) {
        if (err2) throw err2;
        adapter.list(function(err3, list) {
          if (err3) throw err3;
          var same = list.filter(function(e) {
            return e.protocol === 'tcp' && Number(e.externalPort) === port;
          });
          if (same.length !== 1) throw new Error('found ' + same.length + ' entries for one port');
          adapter.remove({ protocol: 'tcp', externalPort: port }, function() { done(); });
        });
      });
    });
  });


  /* ============================ Data plane ============================ */

  test('TCP: bytes reach the internal service and come back', ['dataplane', 'tcp'], function(done) {
    var inner = net.createServer(function(sock) {
      sock.on('data', function(d) { sock.write('echo:' + d.toString()); });
    });

    inner.listen(port + 1, '127.0.0.1', function() {
      adapter.add({ protocol: 'tcp', externalPort: port,
                    internalIp: '127.0.0.1', internalPort: port + 1 }, function(err) {
        if (err) { inner.close(); throw err; }

        var client = net.connect(port, '127.0.0.1', function() { client.write('hello'); });
        var guard = setTimeout(function() {
          client.destroy(); inner.close();
          throw new Error('no reply came back through the relay');
        }, 2000);

        client.on('data', function(d) {
          clearTimeout(guard);
          var text = d.toString();
          client.destroy();
          inner.close();
          adapter.remove({ protocol: 'tcp', externalPort: port }, function() {
            if (text !== 'echo:hello') throw new Error('got "' + text + '"');
            done();
          });
        });

        client.on('error', function(e) {
          clearTimeout(guard); inner.close();
          throw new Error('connect failed: ' + e.message);
        });
      });
    });
  });

  test('UDP: datagrams reach the internal service and come back', ['dataplane', 'udp'], function(done) {
    var inner = dgram.createSocket('udp4');
    inner.on('message', function(msg, rinfo) {
      inner.send('echo:' + msg.toString(), rinfo.port, rinfo.address);
    });

    inner.bind(port + 3, '127.0.0.1', function() {
      adapter.add({ protocol: 'udp', externalPort: port + 2,
                    internalIp: '127.0.0.1', internalPort: port + 3 }, function(err) {
        if (err) { inner.close(); throw err; }

        var client = dgram.createSocket('udp4');
        var guard = setTimeout(function() {
          client.close(); inner.close();
          throw new Error('no datagram came back through the relay');
        }, 2000);

        client.on('message', function(msg) {
          clearTimeout(guard);
          var text = msg.toString();
          client.close();
          inner.close();
          adapter.remove({ protocol: 'udp', externalPort: port + 2 }, function() {
            if (text !== 'echo:hello') throw new Error('got "' + text + '"');
            done();
          });
        });

        client.send('hello', port + 2, '127.0.0.1');
      });
    });
  });

  test('destroy() leaves nothing behind', null, function(done) {
    adapter.destroy(function(err) {
      if (err) throw err;
      adapter.list(function(err2, list) {
        // An adapter may legitimately refuse to list after destroy
        if (err2) return done();
        if (list.length) throw new Error(list.length + ' entries survived destroy()');
        done();
      });
    });
  });


  /* ============================== Runner ============================== */

  function run(i) {
    if (i >= queue.length) {
      var passed = results.filter(function(r) { return r.status === 'pass'; }).length;
      var failed = results.filter(function(r) { return r.status === 'fail'; });
      return cb(failed.length ? new Error(name + ': ' + failed.length + ' check(s) failed') : null, {
        name:    name,
        total:   queue.length,
        passed:  passed,
        skipped: results.filter(function(r) { return r.status === 'skip'; }).length,
        failed:  failed.length,
        results: results
      });
    }

    var item = queue[i];
    var reason = skip_reason(item.requires);
    if (reason) {
      results.push({ title: item.title, status: 'skip', reason: reason });
      return run(i + 1);
    }

    var settled = false;
    function done(err) {
      if (settled) return;
      settled = true;
      clearTimeout(guard);
      results.push(err
        ? { title: item.title, status: 'fail', reason: err.message }
        : { title: item.title, status: 'pass' });
      setImmediate(function() { run(i + 1); });
    }

    var guard = setTimeout(function() { done(new Error('timed out')); }, options.timeout || 5000);

    try { item.fn(function() { done(null); }); }
    catch (e) { done(e); }
  }

  run(0);
}


export { conformance };
export default conformance;
