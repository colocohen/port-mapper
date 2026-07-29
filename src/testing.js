/**
 * testing.js — Official in-memory test transport.
 *
 * Wires client sessions to a gateway session with no sockets, no root and no
 * router. Everything the library does short of touching the network can be
 * exercised inside any test runner:
 *
 *   import { createTestPair } from 'port-mapper'
 *
 *   var pair = createTestPair({ server: { policy: 'allow-all' } })
 *   pair.client.map({ internalPort: 8080 }, function (err, m) {
 *     assert.equal(m.externalPort, 8080)
 *     pair.destroy()
 *   })
 *
 * There are two pairs because the two protocol families share no transport:
 * createTestPair() joins PMPSession to PMPServerSession over datagrams, and
 * createUPnPTestPair() joins UPnPSession to UPnPServerSession over SSDP
 * datagrams plus an http() function routed straight into the gateway.
 *
 * Delivery is asynchronous — setImmediate, or `latency` ms — so the real
 * ordering semantics are preserved rather than collapsing into synchronous
 * calls that would hide races. The `intercept` hook can inspect or drop
 * packets; return false to simulate loss:
 *
 *   var pair = createTestPair({
 *     intercept: function (direction, buf) {
 *       if (direction === 'server->client' && Math.random() < 0.5) return false
 *     }
 *   })
 */

import PMPSession from './pmp_session.js';
import PMPServerSession from './pmp_server_session.js';
import UPnPSession from './upnp_session.js';
import UPnPServerSession from './upnp_server_session.js';
import * as wire from './wire.js';
import * as ssdp from './ssdp.js';


var DEFAULT_GATEWAY = '192.168.77.1';
var DEFAULT_EXTERNAL = '81.2.3.4';


/* ========================= PCP / NAT-PMP pair ========================= */

/**
 * options = {
 *   server:    passed to PMPServerSession
 *   client:    passed to PMPSession
 *   gateway:   the address both sides believe the gateway has
 *   latency:   ms applied to each hop
 *   intercept: function (direction, buf) → false to drop
 * }
 */
function createTestPair(options) {
  options = options || {};

  var gateway = options.gateway || DEFAULT_GATEWAY;
  var latency = options.latency || 0;
  var intercept = options.intercept || null;

  var server = new PMPServerSession(Object.assign({
    externalIp: DEFAULT_EXTERNAL
  }, options.server || {}));

  var clients = [];
  var by_address = Object.create(null);
  var destroyed = false;
  var seq = 0;

  function deliver(direction, buf, target, meta) {
    if (destroyed) return;
    if (intercept && intercept(direction, buf) === false) return;

    function send() {
      if (destroyed) return;
      target.process_packet(buf, meta);
    }

    if (latency > 0) setTimeout(send, latency);
    else setImmediate(send);
  }

  // Everything the gateway sends: either a unicast reply, or a multicast
  // announcement that every client on the segment hears
  server.on('packet', function(buf, dest) {
    if (dest.address === wire.NATPMP_MULTICAST) {
      for (var i = 0; i < clients.length; i++) {
        deliver('server->client', buf, clients[i], { address: gateway, port: wire.SERVER_PORT });
      }
      return;
    }
    var client = by_address[dest.address];
    if (client) deliver('server->client', buf, client, { address: gateway, port: wire.SERVER_PORT });
  });

  function addClient(client_opts) {
    client_opts = Object.assign({}, options.client || {}, client_opts || {});
    seq++;

    var address = client_opts.clientIp || ('192.168.77.' + (10 + seq));
    var client = new PMPSession(Object.assign({}, client_opts, {
      gateway:  gateway,
      clientIp: address
    }));

    client.on('packet', function(buf) {
      deliver('client->server', buf, server, { address: address, port: wire.CLIENT_PORT });
    });

    by_address[address] = client;
    clients.push(client);
    client.listening();
    return client;
  }

  var first = addClient();

  return {
    server: server,
    client: first,
    gateway: gateway,
    addClient: addClient,
    get clients() { return clients.slice(); },
    destroy: function() {
      if (destroyed) return;
      destroyed = true;
      for (var i = 0; i < clients.length; i++) clients[i].destroy();
      server.destroy();
    }
  };
}


/* ============================= UPnP pair ============================= */

/**
 * The UPnP pair needs one more wire than the PMP one: SSDP travels as
 * datagrams, but control is HTTP, so the client's injected http() is routed
 * into the gateway's handle_http() rather than through a socket.
 */
function createUPnPTestPair(options) {
  options = options || {};

  var gateway = options.gateway || DEFAULT_GATEWAY;
  var latency = options.latency || 0;
  var intercept = options.intercept || null;
  var http_intercept = options.interceptHttp || null;

  var location = options.location || ('http://' + gateway + ':5000/rootDesc.xml');

  var server = new UPnPServerSession(Object.assign({
    udn:        'uuid:test-pair-0001',
    location:   location,
    externalIp: DEFAULT_EXTERNAL
  }, options.server || {}));

  var clients = [];
  var by_address = Object.create(null);
  var by_callback = Object.create(null);
  var destroyed = false;
  var seq = 0;

  function deliver(direction, buf, target, meta) {
    if (destroyed) return;
    if (intercept && intercept(direction, buf) === false) return;

    function send() {
      if (destroyed) return;
      target.process_packet(buf, meta);
    }

    if (latency > 0) setTimeout(send, latency);
    else setImmediate(send);
  }

  server.on('packet', function(buf, dest) {
    if (dest.address === ssdp.MULTICAST_ADDR) {
      for (var i = 0; i < clients.length; i++) {
        deliver('server->client', buf, clients[i], { address: gateway, port: ssdp.MULTICAST_PORT });
      }
      return;
    }
    var client = by_address[dest.address];
    if (client) deliver('server->client', buf, client, { address: gateway, port: ssdp.MULTICAST_PORT });
  });


  function make_http(address) {
    return function do_http(req, cb) {
      if (destroyed) return cb(new Error('test pair destroyed'));
      if (http_intercept && http_intercept(req) === false) {
        return setImmediate(function() { cb(new Error('intercepted')); });
      }

      function run() {
        if (destroyed) return;
        // The gateway is addressed by path, so a full URL from the client is
        // reduced the way a real HTTP server would see it
        var path = String(req.url || '/').replace(/^https?:\/\/[^/]+/, '');
        server.handle_http({
          method:  req.method,
          url:     path,
          headers: req.headers,
          body:    req.body,
          remote:  { address: address }
        }, function(err, res) {
          if (err) return cb(err);
          // Header names are lower-cased the way a real HTTP client presents
          // them, so a caller cannot accidentally depend on the casing a
          // particular gateway happened to use
          var headers = Object.create(null);
          Object.keys(res.headers || {}).forEach(function(k) {
            headers[k.toLowerCase()] = res.headers[k];
          });
          cb(null, {
            statusCode: res.statusCode,
            headers:    headers,
            body:       typeof res.body === 'string' ? ssdp.textToBytes(res.body) : res.body
          });
        });
      }

      if (latency > 0) setTimeout(run, latency);
      else setImmediate(run);
    };
  }


  // The gateway posts notifications to a URL the client chose, so the pair
  // routes them straight back into the client that subscribed
  server.on('notify', function(messages) {
    messages.forEach(function(m) {
      var target = by_callback[m.url];
      if (!target) return;
      setImmediate(function() {
        if (!destroyed) target.handle_notify(m.headers, m.body);
      });
    });
  });


  function addClient(client_opts) {
    client_opts = Object.assign({}, options.client || {}, client_opts || {});
    seq++;

    var address = client_opts.localIp || ('192.168.77.' + (10 + seq));
    var client = new UPnPSession(Object.assign({
      // In memory there is no network to spread replies across, so the
      // smallest legal MX keeps discovery quick. The session widens its own
      // window to cover whatever MX it sends.
      searchMx:      1,
      searchTimeout: 200
    }, client_opts, {
      localIp: address,
      gateway: gateway,
      http:    make_http(address)
    }));

    client.on('packet', function(buf) {
      deliver('client->server', buf, server, { address: address, port: 1900 });
    });

    by_address[address] = client;
    by_callback['http://' + address + ':9999/notify'] = client;
    client.callbackUrl = 'http://' + address + ':9999/notify';
    clients.push(client);
    return client;
  }

  var first = addClient();

  return {
    server: server,
    client: first,
    gateway: gateway,
    location: location,
    addClient: addClient,
    get clients() { return clients.slice(); },
    destroy: function() {
      if (destroyed) return;
      destroyed = true;
      for (var i = 0; i < clients.length; i++) clients[i].destroy();
      server.destroy();
    }
  };
}


export { createTestPair, createUPnPTestPair };
export default createTestPair;
