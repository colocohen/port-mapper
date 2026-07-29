/**
 * errors.js — Custom error classes for port-mapper.
 */


function PortMapError(message) {
  Error.call(this, message);
  this.name = 'PortMapError';
  this.message = message;
  if (Error.captureStackTrace) Error.captureStackTrace(this, this.constructor);
}
PortMapError.prototype = Object.create(Error.prototype);
PortMapError.prototype.constructor = PortMapError;


function PortMapValidationError(message, field) {
  PortMapError.call(this, message);
  this.name = 'PortMapValidationError';
  this.field = field || null;
}
PortMapValidationError.prototype = Object.create(PortMapError.prototype);
PortMapValidationError.prototype.constructor = PortMapValidationError;


function PortMapNetworkError(message, cause) {
  PortMapError.call(this, message);
  this.name = 'PortMapNetworkError';
  this.cause = cause || null;
}
PortMapNetworkError.prototype = Object.create(PortMapError.prototype);
PortMapNetworkError.prototype.constructor = PortMapNetworkError;


/**
 * A protocol-level rejection from the gateway.
 * `code` is the raw numeric code, `protocol` says which numbering space it
 * belongs to ('pcp' | 'natpmp' | 'upnp'), since the same number means
 * different things in each.
 */
function PortMapProtocolError(message, code, protocol) {
  PortMapError.call(this, message);
  this.name = 'PortMapProtocolError';
  this.code = (code === undefined || code === null) ? null : code;
  this.protocol = protocol || null;
}
PortMapProtocolError.prototype = Object.create(PortMapError.prototype);
PortMapProtocolError.prototype.constructor = PortMapProtocolError;


function PortMapTimeoutError(message, timeout) {
  PortMapError.call(this, message);
  this.name = 'PortMapTimeoutError';
  this.timeout = timeout || null;
}
PortMapTimeoutError.prototype = Object.create(PortMapError.prototype);
PortMapTimeoutError.prototype.constructor = PortMapTimeoutError;


function PortMapStateError(message, state) {
  PortMapError.call(this, message);
  this.name = 'PortMapStateError';
  this.state = state || null;
}
PortMapStateError.prototype = Object.create(PortMapError.prototype);
PortMapStateError.prototype.constructor = PortMapStateError;


/** No gateway answered any of the discovery probes. */
function NoGatewayError(message, tried) {
  PortMapError.call(this, message);
  this.name = 'NoGatewayError';
  this.tried = tried || [];
}
NoGatewayError.prototype = Object.create(PortMapError.prototype);
NoGatewayError.prototype.constructor = NoGatewayError;


/**
 * The mapping succeeded on the local gateway but the host is behind
 * carrier-grade NAT, so it can never be reachable from the internet.
 */
function CGNATError(message, routerExternalIp, realExternalIp) {
  PortMapError.call(this, message);
  this.name = 'CGNATError';
  this.routerExternalIp = routerExternalIp || null;
  this.realExternalIp = realExternalIp || null;
}
CGNATError.prototype = Object.create(PortMapError.prototype);
CGNATError.prototype.constructor = CGNATError;


export {
  PortMapError,
  PortMapValidationError,
  PortMapNetworkError,
  PortMapProtocolError,
  PortMapTimeoutError,
  PortMapStateError,
  NoGatewayError,
  CGNATError
};
