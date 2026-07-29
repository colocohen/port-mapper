/**
 * soap.js — SOAP envelope encoding, response decoding and UPnP error mapping.
 *
 * Pure functions, zero state. Nothing here opens a connection; it turns an
 * action plus arguments into bytes and headers, and turns a response body
 * back into a plain object. The transport lives in upnp_session.js.
 *
 * The shape of a UPnP control message is narrow: the element inside the SOAP
 * Body is the action name, its namespace is the serviceType, and each child
 * element is one input argument carrying no namespace of its own. The
 * SOAPAction HTTP header repeats the same pair as "serviceType#actionName",
 * quoted.
 *
 * References:
 *   UPnP Device Architecture 1.1 §3 — control, action invocation, errors
 *   IGD:1 WANIPConnection / WANPPPConnection — actions and error codes
 *   IGD:2 WANIPConnection:2 — AddAnyPortMapping, DeletePortMappingRange, 728/729
 *   RFC 6970 §4 — how a PCP-backed IGD maps PCP results onto these codes
 */

import { parse_xml, child, child_text, descendants, escape_xml, textToBytes } from './ssdp.js';


/* ============================== Actions ============================== */

const ACTION = {
  ADD_PORT_MAPPING:       'AddPortMapping',
  DELETE_PORT_MAPPING:    'DeletePortMapping',
  GET_EXTERNAL_IP:        'GetExternalIPAddress',
  GET_STATUS_INFO:        'GetStatusInfo',
  GET_GENERIC_MAPPING:    'GetGenericPortMappingEntry',
  GET_SPECIFIC_MAPPING:   'GetSpecificPortMappingEntry',
  GET_MAPPING_COUNT:      'GetPortMappingNumberOfEntries',
  GET_CONNECTION_TYPE:    'GetConnectionTypeInfo',

  // WANCommonInterfaceConfig:1 — a third service on the same device, holding
  // link speed and traffic counters. Not needed to map a port, but it is what
  // turns "the mapping failed" into "the WAN is a 10 Mbit link that has moved
  // 40 GB", which is the difference between a diagnosis and a shrug.
  GET_COMMON_LINK_PROPERTIES: 'GetCommonLinkProperties',
  GET_TOTAL_BYTES_SENT:       'GetTotalBytesSent',
  GET_TOTAL_BYTES_RECEIVED:   'GetTotalBytesReceived',
  GET_TOTAL_PACKETS_SENT:     'GetTotalPacketsSent',
  GET_TOTAL_PACKETS_RECEIVED: 'GetTotalPacketsReceived',

  // IGD:2 — WANIPConnection:2
  ADD_ANY_PORT_MAPPING:   'AddAnyPortMapping',
  DELETE_MAPPING_RANGE:   'DeletePortMappingRange',
  GET_LIST_OF_MAPPINGS:   'GetListOfPortMappings',

  // IGD:2 — WANIPv6FirewallControl:1. These open a hole in the firewall for
  // an address that is already globally routable; there is no translation
  // involved, which is why the vocabulary is "pinhole" rather than "mapping".
  GET_FIREWALL_STATUS:        'GetFirewallStatus',
  GET_OUTBOUND_PINHOLE_TIMEOUT: 'GetOutboundPinholeTimeout',
  ADD_PINHOLE:                'AddPinhole',
  UPDATE_PINHOLE:             'UpdatePinhole',
  DELETE_PINHOLE:             'DeletePinhole',
  GET_PINHOLE_PACKETS:        'GetPinholePackets',
  CHECK_PINHOLE_WORKING:      'CheckPinholeWorking'
};

/**
 * Argument order matters. The architecture requires arguments in the order the
 * service description declares them, and gateways do reject reordered bodies,
 * so these are written out rather than derived from an object's key order.
 */
const ACTION_ARGS = {
  AddPortMapping: [
    'NewRemoteHost', 'NewExternalPort', 'NewProtocol', 'NewInternalPort',
    'NewInternalClient', 'NewEnabled', 'NewPortMappingDescription', 'NewLeaseDuration'
  ],
  AddAnyPortMapping: [
    'NewRemoteHost', 'NewExternalPort', 'NewProtocol', 'NewInternalPort',
    'NewInternalClient', 'NewEnabled', 'NewPortMappingDescription', 'NewLeaseDuration'
  ],
  DeletePortMapping: ['NewRemoteHost', 'NewExternalPort', 'NewProtocol'],
  DeletePortMappingRange: ['NewStartPort', 'NewEndPort', 'NewProtocol', 'NewManage'],
  GetGenericPortMappingEntry: ['NewPortMappingIndex'],
  GetSpecificPortMappingEntry: ['NewRemoteHost', 'NewExternalPort', 'NewProtocol'],
  GetExternalIPAddress: [],
  GetStatusInfo: [],
  GetConnectionTypeInfo: [],
  GetPortMappingNumberOfEntries: [],
  GetCommonLinkProperties: [],
  GetTotalBytesSent: [],
  GetTotalBytesReceived: [],
  GetTotalPacketsSent: [],
  GetTotalPacketsReceived: [],
  GetListOfPortMappings: [
    'NewStartPort', 'NewEndPort', 'NewProtocol', 'NewManage', 'NewNumberOfPorts'
  ],

  // WANIPv6FirewallControl arguments carry no "New" prefix, unlike every
  // WANIPConnection argument. Assuming otherwise is a silent failure: the
  // gateway sees arguments it does not recognise and answers 402 InvalidArgs.
  GetFirewallStatus: [],
  GetOutboundPinholeTimeout: [
    'RemoteHost', 'RemotePort', 'InternalClient', 'InternalPort', 'Protocol'
  ],
  AddPinhole: [
    'RemoteHost', 'RemotePort', 'InternalClient', 'InternalPort', 'Protocol', 'LeaseTime'
  ],
  UpdatePinhole:       ['UniqueID', 'NewLeaseTime'],
  DeletePinhole:       ['UniqueID'],
  GetPinholePackets:   ['UniqueID'],
  CheckPinholeWorking: ['UniqueID']
};


/* ============================ Error codes ============================ */

/**
 * UPnP error codes. 4xx/5xx are architecture-wide; 7xx come from the IGD
 * service templates.
 *
 * `retry` says what a client should do, in the same vocabulary the PCP side
 * uses, so both protocols can be handled by one caller:
 *   'none'      the request itself is wrong; repeating it unchanged is futile
 *   'short'     transient
 *   'long'      policy or capacity; back off well before trying again
 *   'conflict'  the port is taken — try a different external port, or ask the
 *               gateway to choose one
 *   'end'       not a failure at all; the enumeration has run off the end
 */
const ERROR = {
  401: { name: 'InvalidAction',                retry: 'none' },
  402: { name: 'InvalidArgs',                  retry: 'none' },
  404: { name: 'InvalidVar',                   retry: 'none' },
  501: { name: 'ActionFailed',                 retry: 'short' },
  600: { name: 'ArgumentValueInvalid',         retry: 'none' },
  601: { name: 'ArgumentValueOutOfRange',      retry: 'none' },
  602: { name: 'OptionalActionNotImplemented', retry: 'none' },
  603: { name: 'OutOfMemory',                  retry: 'short' },
  604: { name: 'HumanInterventionRequired',    retry: 'long' },
  605: { name: 'StringArgumentTooLong',        retry: 'none' },
  606: { name: 'ActionNotAuthorized',          retry: 'long' },

  // 713 terminates an enumeration rather than reporting a fault: walking
  // GetGenericPortMappingEntry from index 0 upwards ends when it appears.
  // WANIPv6FirewallControl:1 — the pinhole error space
  701: { name: 'PinholeSpaceExhausted',        retry: 'long' },
  702: { name: 'FirewallDisabled',             retry: 'long' },
  703: { name: 'InboundPinholeNotAllowed',     retry: 'long' },
  704: { name: 'NoSuchEntry',                  retry: 'none' },
  705: { name: 'ProtocolNotSupported',         retry: 'none' },
  706: { name: 'InternalPortWildcardingNotAllowed', retry: 'none' },
  707: { name: 'ProtocolWildcardingNotAllowed', retry: 'none' },
  708: { name: 'WildcardNotPermittedInSrcIP',  retry: 'none' },
  709: { name: 'NoPacketSent',                 retry: 'short' },

  713: { name: 'SpecifiedArrayIndexInvalid',   retry: 'end' },
  714: { name: 'NoSuchEntryInArray',           retry: 'none' },
  715: { name: 'WildCardNotPermittedInSrcIP',  retry: 'none' },
  716: { name: 'WildCardNotPermittedInExtPort', retry: 'none' },
  718: { name: 'ConflictInMappingEntry',       retry: 'conflict' },
  724: { name: 'SamePortValuesRequired',       retry: 'none' },
  725: { name: 'OnlyPermanentLeasesSupported', retry: 'none' },
  726: { name: 'RemoteHostOnlySupportsWildcard',  retry: 'none' },
  727: { name: 'ExternalPortOnlySupportsWildcard', retry: 'none' },
  728: { name: 'NoPortMapsAvailable',          retry: 'long' },   // IGD:2
  729: { name: 'ConflictWithOtherMechanisms',  retry: 'conflict' }, // IGD:2
  730: { name: 'PortMappingNotFound',          retry: 'none' },   // IGD:2 range ops
  731: { name: 'ReadOnly',                     retry: 'none' },
  733: { name: 'InconsistantParameters',       retry: 'none' },   // start > end
  732: { name: 'WildCardNotPermittedInIntPort', retry: 'none' }
};


function error_name(code) {
  return ERROR[code] ? ERROR[code].name : 'UnknownError' + code;
}

/**
 * Classify a fault. IGD:1 and IGD:2 disagree about 718: RFC 6970 §4 records
 * that a PCP NOT_AUTHORIZED surfaces as 718 "ConflictInMappingEntry" on IGD:1
 * but as 606 "Action not authorized" on IGD:2. So on a v1 gateway a 718 may
 * mean either a genuine port conflict or a refusal, and a client that only
 * ever retries a different port can loop forever against a gateway that is
 * simply saying no. Callers get told, rather than guessing.
 */
function classify_error(code, igd_version) {
  var entry = ERROR[code];
  var out = {
    code:      code,
    name:      entry ? entry.name : 'UnknownError',
    retry:     entry ? entry.retry : 'none',
    ambiguous: false
  };

  if (code === 718 && igd_version === 1) {
    out.ambiguous = true;
    out.note = 'On IGD:1 this may mean "not authorized" rather than a port conflict ' +
               '(RFC 6970 §4) — limit retries on a different port.';
  }
  return out;
}


/* ============================== Encoding ============================== */

/**
 * Build the SOAP body for one action.
 *
 * Arguments are emitted in the order the service declares them; anything the
 * caller supplies that the action does not declare is appended afterwards, so
 * vendor extensions still work.
 */
function encode_envelope(service_type, action, args) {
  args = args || {};

  var order = ACTION_ARGS[action] || [];
  var seen = Object.create(null);
  var body = '';
  var i, name;

  for (i = 0; i < order.length; i++) {
    name = order[i];
    seen[name] = true;
    body += '<' + name + '>' + encode_value(args[name]) + '</' + name + '>';
  }

  var extra = Object.keys(args);
  for (i = 0; i < extra.length; i++) {
    name = extra[i];
    if (seen[name]) continue;
    body += '<' + name + '>' + encode_value(args[name]) + '</' + name + '>';
  }

  var xml =
    '<?xml version="1.0"?>' +
    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" ' +
    's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">' +
    '<s:Body>' +
    '<u:' + action + ' xmlns:u="' + service_type + '">' +
    body +
    '</u:' + action + '>' +
    '</s:Body></s:Envelope>';

  return xml;
}


/**
 * Undefined and null become the empty element the gateway expects — an empty
 * NewRemoteHost is the wildcard "any remote host", not a missing argument.
 * Booleans become 1/0, which is how the service templates spell them.
 */
function encode_value(v) {
  if (v === undefined || v === null) return '';
  if (v === true) return '1';
  if (v === false) return '0';
  return escape_xml(v);
}


/** The SOAPAction header value, quotes included. */
function soap_action_header(service_type, action) {
  return '"' + service_type + '#' + action + '"';
}


/**
 * Everything the transport needs for one call: a URL is not included because
 * that comes from the device description.
 */
function encode_request(service_type, action, args) {
  var body = encode_envelope(service_type, action, args);
  var bytes = textToBytes(body);
  return {
    body: bytes,
    headers: {
      'Content-Type':   'text/xml; charset="utf-8"',
      'Content-Length': String(bytes.length),
      'SOAPAction':     soap_action_header(service_type, action),
      'Connection':     'close'
    }
  };
}


/* ============================== Decoding ============================== */

/**
 * Parse a control response body.
 *
 * Success →  { fault: false, action: 'AddPortMappingResponse', args: { ... } }
 * Fault   →  { fault: true, code, name, description, retry, ambiguous }
 *
 * Faults are returned rather than thrown: a 713 while enumerating is a normal
 * end-of-list, and a 718 is a routine outcome the caller reacts to. Throwing
 * would make the ordinary path exceptional.
 */
function decode_response(xml, igd_version) {
  var root = parse_xml(xml);

  var body = child(root, 'Body');
  if (!body) throw new Error('Malformed SOAP: no Body element');

  var fault = child(body, 'Fault');
  if (fault) return decode_fault(fault, igd_version);

  // The response element is the only child, named <Action>Response
  var response = body.children[0];
  if (!response) throw new Error('Malformed SOAP: empty Body');

  var args = Object.create(null);
  for (var i = 0; i < response.children.length; i++) {
    var arg = response.children[i];
    args[arg.name] = arg.text.trim();
  }

  return { fault: false, action: response.name, args: args };
}


/**
 * A UPnP fault nests the interesting part several levels down:
 *
 *   <s:Fault>
 *     <faultcode>s:Client</faultcode>
 *     <faultstring>UPnPError</faultstring>
 *     <detail>
 *       <UPnPError xmlns="urn:schemas-upnp-org:control-1-0">
 *         <errorCode>718</errorCode>
 *         <errorDescription>ConflictInMappingEntry</errorDescription>
 *
 * Gateways vary in how they nest and namespace the detail, so the errorCode
 * is looked up by descendant search rather than by fixed path.
 */
function decode_fault(fault, igd_version) {
  var codes = descendants(fault, 'errorCode');
  var code = codes.length ? parseInt(codes[0].text.trim(), 10) : null;

  var descriptions = descendants(fault, 'errorDescription');
  var description = descriptions.length ? descriptions[0].text.trim() : null;

  var info = code === null
    ? { code: null, name: 'UnknownError', retry: 'none', ambiguous: false }
    : classify_error(code, igd_version);

  return {
    fault:       true,
    code:        info.code,
    name:        info.name,
    description: description || (code === null ? null : error_name(code)),
    retry:       info.retry,
    ambiguous:   info.ambiguous,
    note:        info.note || null,
    faultCode:   child_text(fault, 'faultcode'),
    faultString: child_text(fault, 'faultstring')
  };
}


/* ===================== Server side: requests in ===================== */

/**
 * Parse a control request body (the gateway's view).
 *
 * The element inside the SOAP Body is the action name and each of its
 * children is one input argument, so both come out of the same walk.
 *
 * Returns { action, args }.
 */
function decode_request(xml) {
  var root = parse_xml(xml);

  var body = child(root, 'Body');
  if (!body) throw new Error('Malformed SOAP: no Body element');

  var action_el = body.children[0];
  if (!action_el) throw new Error('Malformed SOAP: empty Body');

  var args = Object.create(null);
  for (var i = 0; i < action_el.children.length; i++) {
    var arg = action_el.children[i];
    args[arg.name] = arg.text.trim();
  }

  return { action: action_el.name, args: args };
}


/**
 * The serviceType a request was addressed to, taken from the SOAPAction
 * header rather than the body, since that is what the architecture defines as
 * authoritative for routing.
 */
function parse_soap_action(header) {
  if (!header) return null;
  var m = /^"?([^#"]+)#([^"]+)"?$/.exec(String(header).trim());
  return m ? { serviceType: m[1], action: m[2] } : null;
}


/** Build a success response for `action`, carrying `args` as out-parameters. */
function encode_response(service_type, action, args) {
  args = args || {};
  var body = '';
  var names = Object.keys(args);
  for (var i = 0; i < names.length; i++) {
    body += '<' + names[i] + '>' + encode_value(args[names[i]]) + '</' + names[i] + '>';
  }

  return '<?xml version="1.0"?>' +
    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" ' +
    's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">' +
    '<s:Body>' +
    '<u:' + action + 'Response xmlns:u="' + service_type + '">' +
    body +
    '</u:' + action + 'Response>' +
    '</s:Body></s:Envelope>';
}


/**
 * Build a UPnP fault. Always sent with HTTP 500, per the architecture.
 */
function encode_fault(code, description) {
  var name = description || error_name(code);
  return '<?xml version="1.0"?>' +
    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" ' +
    's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">' +
    '<s:Body><s:Fault>' +
    '<faultcode>s:Client</faultcode>' +
    '<faultstring>UPnPError</faultstring>' +
    '<detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0">' +
    '<errorCode>' + code + '</errorCode>' +
    '<errorDescription>' + escape_xml(name) + '</errorDescription>' +
    '</UPnPError></detail>' +
    '</s:Fault></s:Body></s:Envelope>';
}


/**
 * Build the PortListing document GetListOfPortMappings returns. It is nested
 * inside the SOAP response as escaped text, so the caller passes the result
 * through encode_response like any other argument.
 */
function encode_port_listing(entries) {
  var xml = '<PortMappingList xmlns="urn:schemas-upnp-org:gw:WANIPConnection">';
  for (var i = 0; i < entries.length; i++) {
    var e = entries[i];
    xml += '<PortMappingEntry>' +
      '<NewRemoteHost>' + escape_xml(e.remoteHost || '') + '</NewRemoteHost>' +
      '<NewExternalPort>' + e.externalPort + '</NewExternalPort>' +
      '<NewProtocol>' + String(e.protocol).toUpperCase() + '</NewProtocol>' +
      '<NewInternalPort>' + e.internalPort + '</NewInternalPort>' +
      '<NewInternalClient>' + escape_xml(e.internalIp || '') + '</NewInternalClient>' +
      '<NewEnabled>1</NewEnabled>' +
      '<NewDescription>' + escape_xml(e.description || '') + '</NewDescription>' +
      '<NewLeaseTime>' + (e.leaseDuration || 0) + '</NewLeaseTime>' +
      '</PortMappingEntry>';
  }
  return xml + '</PortMappingList>';
}


/* =============== Service description (SCPD) and eventing =============== */

/**
 * Parse a service description document.
 *
 * Every service publishes one at its SCPDURL, listing the actions it actually
 * implements and the state variables it exposes. Without reading it a client
 * is guessing: a device that calls itself IGD:2 has not promised to implement
 * AddAnyPortMapping, and plenty answer 401 InvalidAction when asked. Knowing
 * in advance is the difference between choosing the right action and
 * discovering the wrong one by failing.
 *
 * Returns { actions: { name: { inputs: [], outputs: [] } }, variables: {...} }.
 */
function parse_scpd(xml) {
  var root = parse_xml(xml);

  var actions = Object.create(null);
  var found = descendants(root, 'action');
  for (var i = 0; i < found.length; i++) {
    var name = child_text(found[i], 'name');
    if (!name) continue;

    var inputs = [], outputs = [];
    var args = descendants(found[i], 'argument');
    for (var j = 0; j < args.length; j++) {
      var arg = {
        name:     child_text(args[j], 'name'),
        variable: child_text(args[j], 'relatedStateVariable')
      };
      if (child_text(args[j], 'direction') === 'out') outputs.push(arg);
      else inputs.push(arg);
    }
    actions[name] = { name: name, inputs: inputs, outputs: outputs };
  }

  var variables = Object.create(null);
  var vars = descendants(root, 'stateVariable');
  for (var k = 0; k < vars.length; k++) {
    var vname = child_text(vars[k], 'name');
    if (!vname) continue;
    variables[vname] = {
      name:     vname,
      dataType: child_text(vars[k], 'dataType'),
      // Only evented variables ever appear in a GENA notification, so this is
      // what decides whether subscribing can tell you about a change
      evented:  vars[k].attrs.sendEvents !== 'no',
      defaultValue: child_text(vars[k], 'defaultValue')
    };
  }

  return { actions: actions, variables: variables };
}


/**
 * Parse a GENA event body.
 *
 *   <e:propertyset xmlns:e="urn:schemas-upnp-org:event-1-0">
 *     <e:property><ExternalIPAddress>81.2.3.4</ExternalIPAddress></e:property>
 *   </e:propertyset>
 *
 * This is what makes UPnP able to announce a changed external address at all.
 * RFC 6886 §9.6 observes that a NAT-PMP gateway multicasts when its external
 * address changes and that IGD has no equivalent — true of SSDP, but
 * ExternalIPAddress is an evented state variable, so a subscription delivers
 * exactly that notification over HTTP instead.
 */
function parse_property_set(xml) {
  var root = parse_xml(xml);
  var out = Object.create(null);

  var properties = descendants(root, 'property');
  for (var i = 0; i < properties.length; i++) {
    for (var j = 0; j < properties[i].children.length; j++) {
      var el = properties[i].children[j];
      out[el.name] = el.text.trim();
    }
  }
  return out;
}


/** Build a GENA event body, for the gateway side. */
function encode_property_set(properties) {
  var body = '';
  var names = Object.keys(properties || {});
  for (var i = 0; i < names.length; i++) {
    body += '<e:property><' + names[i] + '>' + escape_xml(properties[names[i]]) +
            '</' + names[i] + '></e:property>';
  }
  return '<?xml version="1.0"?>' +
         '<e:propertyset xmlns:e="urn:schemas-upnp-org:event-1-0">' +
         body + '</e:propertyset>';
}


/**
 * Parse the TIMEOUT header of a subscription response, which arrives as
 * "Second-1800" or "Second-infinite".
 */
function parse_timeout(header) {
  if (!header) return null;
  var m = /Second-(\d+|infinite)/i.exec(String(header));
  if (!m) return null;
  return m[1].toLowerCase() === 'infinite' ? 0 : parseInt(m[1], 10);
}


/* ========================= Argument conversion ========================= */

/**
 * SOAP carries everything as text. These turn the arguments of the mapping
 * actions into the types the rest of the library uses.
 */
function parse_mapping_entry(args) {
  if (!args) return null;
  var lease = parseInt(args.NewLeaseDuration, 10);
  return {
    remoteHost:   args.NewRemoteHost || null,
    externalPort: to_int(args.NewExternalPort),
    protocol:     args.NewProtocol ? args.NewProtocol.toLowerCase() : null,
    internalPort: to_int(args.NewInternalPort),
    internalIp:   args.NewInternalClient || null,
    enabled:      args.NewEnabled === '1' || args.NewEnabled === 'true',
    description:  args.NewPortMappingDescription || '',
    // 0 means "no expiry" in IGD, not "expires immediately"
    leaseDuration: isNaN(lease) ? null : lease
  };
}


function to_int(v) {
  if (v === undefined || v === null || v === '') return null;
  var n = parseInt(v, 10);
  return isNaN(n) ? null : n;
}


/**
 * A pinhole as returned by the firewall actions. Protocol is an IANA number
 * here rather than the TCP/UDP string WANIPConnection uses, and 65535 is the
 * wildcard meaning "any protocol".
 */
function parse_pinhole(args, request) {
  if (!args) return null;
  request = request || {};
  var id = to_int(args.UniqueID);
  return {
    uniqueId:     id,
    remoteHost:   request.RemoteHost || null,
    remotePort:   to_int(request.RemotePort),
    internalIp:   request.InternalClient || null,
    internalPort: to_int(request.InternalPort),
    protocol:     protocol_name(request.Protocol),
    leaseTime:    to_int(request.LeaseTime)
  };
}


/** IANA protocol number ↔ name, with the pinhole wildcard. */
function protocol_name(n) {
  var v = to_int(n);
  if (v === 6) return 'tcp';
  if (v === 17) return 'udp';
  if (v === 65535 || v === null) return 'any';
  return String(v);
}

function protocol_number(name) {
  if (typeof name === 'number') return name;
  var s = String(name || 'any').toLowerCase();
  if (s === 'tcp') return 6;
  if (s === 'udp') return 17;
  if (s === 'any' || s === '*' || s === '') return 65535;
  var n = parseInt(s, 10);
  if (!isNaN(n)) return n;
  throw new Error('Unknown protocol: ' + name);
}


/**
 * IGD:2 GetListOfPortMappings returns the whole table in one call, as an XML
 * document nested inside the SOAP response — so it arrives XML-escaped and
 * has to be parsed a second time.
 */
function parse_port_listing(text) {
  if (!text) return [];
  var root;
  try { root = parse_xml(text); }
  catch (e) { throw new Error('Unreadable PortListing: ' + e.message); }

  var out = [];
  var entries = descendants(root, 'PortMappingEntry');
  for (var i = 0; i < entries.length; i++) {
    var e = entries[i];
    var lease = to_int(child_text(e, 'NewLeaseTime'));
    out.push({
      remoteHost:    child_text(e, 'NewRemoteHost') || null,
      externalPort:  to_int(child_text(e, 'NewExternalPort')),
      protocol:      (child_text(e, 'NewProtocol') || '').toLowerCase() || null,
      internalPort:  to_int(child_text(e, 'NewInternalPort')),
      internalIp:    child_text(e, 'NewInternalClient') || null,
      enabled:       child_text(e, 'NewEnabled') === '1',
      description:   child_text(e, 'NewDescription') || '',
      leaseDuration: lease
    });
  }
  return out;
}


/** Firewall capability from GetFirewallStatus. */
function parse_firewall_status(args) {
  if (!args) return null;
  return {
    // Both must be true before AddPinhole can succeed
    firewallEnabled:      args.FirewallEnabled === '1' || args.FirewallEnabled === 'true',
    inboundPinholeAllowed: args.InboundPinholeAllowed === '1' || args.InboundPinholeAllowed === 'true'
  };
}


const COMMON_INTERFACE_SERVICE = 'urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1';


/**
 * Link properties and traffic counters, from WANCommonInterfaceConfig.
 *
 * The counters are ui4 and wrap at about 4 GB, which on any modern link
 * happens often — miniupnpc reports them raw for the same reason. They are
 * useful as a liveness signal and for spotting a link that is not moving
 * anything, not as an accounting record.
 */
function parse_link_properties(args) {
  if (!args) return null;
  return {
    accessType:     args.NewWANAccessType || null,
    maxBitRateDown: to_int(args.NewLayer1DownstreamMaxBitRate),
    maxBitRateUp:   to_int(args.NewLayer1UpstreamMaxBitRate),
    linkStatus:     args.NewPhysicalLinkStatus || null,
    linkUp:         args.NewPhysicalLinkStatus === 'Up'
  };
}


/** What kind of connection the gateway believes it has. */
function parse_connection_type(args) {
  if (!args) return null;
  return {
    // 'IP_Routed' is the normal NAT case; 'IP_Bridged' means the device is
    // not routing, and a mapping made on it would do nothing
    type:      args.NewConnectionType || null,
    routed:    args.NewConnectionType === 'IP_Routed',
    possible: (args.NewPossibleConnectionTypes || '').split(',')
                .map(function(t) { return t.trim(); }).filter(Boolean)
  };
}


/** Connection status from GetStatusInfo — 'Connected' means mappings can work. */
function parse_status_info(args) {
  if (!args) return null;
  return {
    status:        args.NewConnectionStatus || null,
    connected:     args.NewConnectionStatus === 'Connected',
    lastError:     args.NewLastConnectionError || null,
    uptimeSeconds: to_int(args.NewUptime)
  };
}


export {
  // Actions
  ACTION,
  ACTION_ARGS,

  // Errors
  ERROR,
  error_name,
  classify_error,

  // Encoding
  encode_envelope,
  encode_request,
  soap_action_header,
  encode_value,

  // Server side
  decode_request,
  parse_soap_action,
  encode_response,
  encode_fault,
  encode_port_listing,

  // Decoding
  decode_response,
  decode_fault,
  parse_mapping_entry,
  parse_status_info,
  parse_pinhole,
  parse_port_listing,
  parse_link_properties,
  parse_connection_type,
  parse_scpd,
  parse_property_set,
  encode_property_set,
  parse_timeout,
  COMMON_INTERFACE_SERVICE,
  parse_firewall_status,
  protocol_name,
  protocol_number
};
