/**
 * port-mapper — Pure JavaScript NAT port mapping for Node.js.
 *
 * UPnP-IGD (v1/v2), NAT-PMP (RFC 6886) and PCP (RFC 6887). Client, server and
 * diagnostics. Zero dependencies. Callback-style.
 *
 * Usage:
 *   import { createMapper } from 'port-mapper'
 *
 *   const mapper = createMapper()          // auto-detects gateway and local IP
 *   mapper.start(function (err, info) {
 *     mapper.map({ internalPort: 8080 }, function (err, m) {
 *       console.log(m.externalIp + ':' + m.externalPort)
 *     })
 *   })
 */

import Mapper, { createMapper } from './src/mapper.js';
import { open } from './src/open.js';
import PortMapServer, { createServer } from './src/server.js';
import PMPServerSession from './src/pmp_server_session.js';
import UPnPServerSession from './src/upnp_server_session.js';
import { createTestPair, createUPnPTestPair } from './src/testing.js';
import * as enforce from './src/enforce/index.js';
import * as quirks from './src/quirks.js';
import * as interfaces from './src/interfaces.js';
import * as reachability from './src/reachability.js';
import PMPSession from './src/pmp_session.js';
import UPnPSession from './src/upnp_session.js';
import { negotiate } from './src/negotiate.js';
import * as ssdp from './src/ssdp.js';
import * as soap from './src/soap.js';
import * as wire from './src/wire.js';
import * as lifecycle from './src/lifecycle.js';
import * as errors from './src/errors.js';

import {
  PortMapError,
  PortMapValidationError,
  PortMapNetworkError,
  PortMapProtocolError,
  PortMapTimeoutError,
  PortMapStateError,
  NoGatewayError,
  CGNATError
} from './src/errors.js';

export {
  // Main API
  open,
  createMapper,
  createServer,
  PortMapServer,
  Mapper,

  // Sessions (advanced — for custom transport)
  PMPSession,
  UPnPSession,
  PMPServerSession,
  UPnPServerSession,

  // Testing — in-memory transport, no sockets or root needed
  createTestPair,
  createUPnPTestPair,

  negotiate,

  // Wire format, constants and lifecycle policy
  wire,
  ssdp,
  enforce,
  quirks,
  interfaces,
  reachability,
  soap,
  lifecycle,
  errors,

  // Errors
  PortMapError,
  PortMapValidationError,
  PortMapNetworkError,
  PortMapProtocolError,
  PortMapTimeoutError,
  PortMapStateError,
  NoGatewayError,
  CGNATError
};

export default { open, createMapper };
