/**
 * ssdp.js — SSDP discovery and UPnP device description parsing.
 *
 * Pure functions, zero state. Foundation layer for the UPnP side, the way
 * wire.js is for PCP/NAT-PMP. Nothing here opens a socket, reads the clock
 * or generates randomness.
 *
 * SSDP is HTTPU: HTTP/1.1 message syntax carried over UDP multicast. The
 * three message shapes are M-SEARCH (a query), a 200 OK unicast reply, and
 * NOTIFY (an unsolicited advertisement or withdrawal).
 *
 * XML parsing is delegated to @rgrove/parse-xml — a conformant, actively
 * maintained, dependency-free parser. Writing our own would mean owning every
 * edge case a router firmware can produce, and descriptions arrive over HTTP
 * from an unauthenticated device on the LAN, so getting that wrong is not just
 * a compatibility bug. The library refuses undefined entity references by
 * design, which closes XXE and entity-expansion denial of service.
 *
 * Its document tree is converted to a small uniform shape —
 * { name, attrs, children, text } with namespace prefixes stripped — because
 * UPnP descriptions use prefixes inconsistently and nothing here depends on
 * them. Unknown *elements* are ignored rather than rejected: for future
 * extensibility, control points may ignore any unknown elements and their
 * subelements or content, per the Flexible XML Processing Profile.
 *
 * References:
 *   UPnP Device Architecture 1.1 §1 — discovery, M-SEARCH, NOTIFY
 *   UPnP Device Architecture 1.1 §2 — device description document
 *   IGD:1 / IGD:2 — WANIPConnection, WANPPPConnection, WANIPv6FirewallControl
 */


import { parseXml } from '@rgrove/parse-xml';


/* ============================== Constants ============================== */

const MULTICAST_ADDR = '239.255.255.250';
const MULTICAST_PORT = 1900;

// UDA 1.1 §1.1 — SSDP over IPv6 uses the same port with scoped multicast
// groups. Link-local reaches one segment, which is all a home gateway needs;
// site-local exists for larger networks that route multicast.
const MULTICAST_ADDR_V6_LINK = 'ff02::c';
const MULTICAST_ADDR_V6_SITE = 'ff05::c';


/** The right SSDP group for a family. */
function multicast_for(family) {
  return family === 'ipv6' ? MULTICAST_ADDR_V6_LINK : MULTICAST_ADDR;
}


/** Format a host for a HOST header: IPv6 literals must be bracketed. */
function host_header(address, port) {
  var host = String(address).indexOf(':') !== -1 ? '[' + address + ']' : address;
  return host + ':' + port;
}

// Search targets, in the order worth trying. IGD:2 first: a v2 gateway
// answers both, and knowing it is v2 unlocks AddAnyPortMapping.
const ST = {
  IGD2:        'urn:schemas-upnp-org:device:InternetGatewayDevice:2',
  IGD1:        'urn:schemas-upnp-org:device:InternetGatewayDevice:1',
  WANIP2:      'urn:schemas-upnp-org:service:WANIPConnection:2',
  WANIP1:      'urn:schemas-upnp-org:service:WANIPConnection:1',
  WANPPP1:     'urn:schemas-upnp-org:service:WANPPPConnection:1',
  ALL:         'ssdp:all',
  ROOT_DEVICE: 'upnp:rootdevice'
};

// Services that can create port mappings, best first. WANIPConnection is
// preferred; WANPPPConnection is the fallback for older PPPoE gateways.
const CONNECTION_SERVICES = [
  'urn:schemas-upnp-org:service:WANIPConnection:2',
  'urn:schemas-upnp-org:service:WANIPConnection:1',
  'urn:schemas-upnp-org:service:WANPPPConnection:1'
];

// IGD:2 only — IPv6 pinholes rather than IPv4 NAT
const FIREWALL_SERVICE = 'urn:schemas-upnp-org:service:WANIPv6FirewallControl:1';

const CRLF = '\r\n';

// RFC 6886 §9.3 observes that UPnP places no upper bound on the size of a
// description, and that 4–8 KB documents are routine. Bound it anyway: this
// is untrusted input from the network.
const MAX_XML_BYTES = 512 * 1024;
const MAX_XML_DEPTH = 100;


/* =========================== SSDP messages =========================== */

/**
 * Build an M-SEARCH query.
 *
 * MX is the maximum number of seconds a responding device should wait before
 * replying; it spreads answers so a busy network does not implode. It is
 * capped at 5 by the architecture, and MUST NOT be sent with unicast
 * searches — a unicast target answers immediately.
 */
function encode_msearch(options) {
  options = options || {};
  var st = options.st || ST.IGD1;
  var host = host_header(options.host || multicast_for(options.family),
                         options.port || MULTICAST_PORT);

  var lines = [
    'M-SEARCH * HTTP/1.1',
    'HOST: ' + host,
    'MAN: "ssdp:discover"',
    'ST: ' + st
  ];

  if (!options.unicast) {
    var mx = options.mx === undefined ? 2 : options.mx;
    if (mx > 5) mx = 5;
    if (mx < 1) mx = 1;
    lines.push('MX: ' + mx);
  }

  if (options.userAgent) lines.push('USER-AGENT: ' + options.userAgent);

  return textToBytes(lines.join(CRLF) + CRLF + CRLF);
}


/**
 * Parse any SSDP datagram.
 *
 * Returns { kind, statusCode, headers, st, nt, nts, usn, location, server,
 *           maxAge, bootId, configId } or null if it is not SSDP at all.
 *
 * `kind` is 'response' (a reply to our M-SEARCH), 'notify' (an unsolicited
 * advertisement) or 'msearch' (someone else searching — seen when we listen
 * on the multicast group).
 */
function decode_ssdp(buf) {
  var text = bytesToText(buf);
  var end = text.indexOf(CRLF + CRLF);
  if (end !== -1) text = text.slice(0, end);

  var lines = text.split(/\r?\n/);
  if (lines.length === 0) return null;

  var start = lines[0].trim();
  var msg = { headers: Object.create(null) };

  if (/^HTTP\/1\.[01]\s/i.test(start)) {
    msg.kind = 'response';
    msg.statusCode = parseInt(start.split(/\s+/)[1], 10);
  } else if (/^NOTIFY\s/i.test(start)) {
    msg.kind = 'notify';
  } else if (/^M-SEARCH\s/i.test(start)) {
    msg.kind = 'msearch';
  } else {
    return null;
  }

  for (var i = 1; i < lines.length; i++) {
    var line = lines[i];
    if (!line) continue;
    var colon = line.indexOf(':');
    if (colon === -1) continue;
    // Header names are case-insensitive and vendors are wildly inconsistent
    var name = line.slice(0, colon).trim().toLowerCase();
    msg.headers[name] = line.slice(colon + 1).trim();
  }

  var h = msg.headers;
  msg.st       = h['st'] || null;
  msg.nt       = h['nt'] || null;
  msg.nts      = h['nts'] || null;          // ssdp:alive | ssdp:byebye | ssdp:update
  msg.usn      = h['usn'] || null;
  msg.location = h['location'] || null;
  msg.server   = h['server'] || null;
  msg.bootId   = h['bootid.upnp.org'] ? parseInt(h['bootid.upnp.org'], 10) : null;
  msg.configId = h['configid.upnp.org'] ? parseInt(h['configid.upnp.org'], 10) : null;
  // Only ever present on ssdp:update: the value BOOTID is about to become,
  // announced before the change so a control point can follow the device
  // across it instead of treating the new one as a restart
  msg.nextBootId = h['nextbootid.upnp.org'] ? parseInt(h['nextbootid.upnp.org'], 10) : null;
  // A device that listens for unicast M-SEARCH somewhere other than 1900 says
  // so here. Without reading it, a unicast search aimed at such a device goes
  // to a port nothing is listening on.
  msg.searchPort = h['searchport.upnp.org'] ? parseInt(h['searchport.upnp.org'], 10) : null;
  msg.maxAge   = parse_max_age(h['cache-control']);

  return msg;
}


function parse_max_age(cache_control) {
  if (!cache_control) return null;
  var m = /max-age\s*=\s*(\d+)/i.exec(cache_control);
  return m ? parseInt(m[1], 10) : null;
}


/**
 * Extract the UUID from a USN, which looks like
 * "uuid:aabb-...::urn:schemas-upnp-org:device:InternetGatewayDevice:1".
 * The uuid identifies the physical device; the part after '::' says which
 * of its roles is being advertised.
 */
function usn_uuid(usn) {
  if (!usn) return null;
  var m = /^uuid:([^:]+(?::[^:]+)*?)(?:::|$)/.exec(usn);
  return m ? m[1] : null;
}


/**
 * True when the search target of a message matches what we asked for.
 * Handles the ssdp:all wildcard and bare-version tolerance: a device
 * answering with :1 is still a useful answer to a :2 query.
 */
function st_matches(wanted, got) {
  if (!wanted || !got) return false;
  if (wanted === ST.ALL) return true;
  if (wanted === got) return true;

  var strip = function(s) { return s.replace(/:\d+$/, ''); };
  return strip(wanted) === strip(got);
}


/* ===================== Server side: replies out ===================== */

/**
 * Reply to an M-SEARCH. Sent unicast to whoever asked, after a random delay
 * of up to MX seconds — the delay is the whole point of MX, spreading the
 * answers so a network full of devices does not answer at once. The caller
 * applies the delay; this only builds the datagram.
 */
function encode_msearch_response(options) {
  options = options || {};
  var lines = [
    'HTTP/1.1 200 OK',
    'CACHE-CONTROL: max-age=' + (options.maxAge || 1800),
    'DATE: ' + (options.date || new Date().toUTCString()),
    'EXT:',
    'LOCATION: ' + options.location,
    'SERVER: ' + (options.server || 'Node/UPnP/1.1 port-mapper/1.0'),
    'ST: ' + options.st,
    'USN: ' + options.usn
  ];
  if (options.bootId !== undefined) lines.push('BOOTID.UPNP.ORG: ' + options.bootId);
  if (options.configId !== undefined) lines.push('CONFIGID.UPNP.ORG: ' + options.configId);
  if (options.searchPort) lines.push('SEARCHPORT.UPNP.ORG: ' + options.searchPort);

  return textToBytes(lines.join(CRLF) + CRLF + CRLF);
}


/**
 * Unsolicited advertisement. `nts` is 'ssdp:alive' when announcing and
 * 'ssdp:byebye' when withdrawing; a byebye carries no LOCATION, because there
 * is nothing left to fetch.
 */
function encode_notify(options) {
  options = options || {};
  var nts = options.nts || 'ssdp:alive';

  var lines = [
    'NOTIFY * HTTP/1.1',
    'HOST: ' + host_header(options.host || multicast_for(options.family), MULTICAST_PORT),
    'NT: ' + options.nt,
    'NTS: ' + nts,
    'USN: ' + options.usn
  ];

  if (nts !== 'ssdp:byebye') {
    lines.push('CACHE-CONTROL: max-age=' + (options.maxAge || 1800));
    lines.push('LOCATION: ' + options.location);
    lines.push('SERVER: ' + (options.server || 'Node/UPnP/1.1 port-mapper/1.0'));
  }
  if (options.bootId !== undefined) lines.push('BOOTID.UPNP.ORG: ' + options.bootId);
  if (options.configId !== undefined) lines.push('CONFIGID.UPNP.ORG: ' + options.configId);
  if (options.searchPort) lines.push('SEARCHPORT.UPNP.ORG: ' + options.searchPort);

  // ssdp:update carries the value BOOTID is about to take. It is what
  // separates "this device changed" from "this device restarted" — without it
  // a control point sees a new BOOTID and has to assume the worst.
  if (nts === 'ssdp:update' && options.nextBootId !== undefined) {
    lines.push('NEXTBOOTID.UPNP.ORG: ' + options.nextBootId);
  }

  return textToBytes(lines.join(CRLF) + CRLF + CRLF);
}


/**
 * Build a device description document for an Internet Gateway Device.
 *
 * The nesting is not decorative: a control point looks for the connection
 * service inside WANConnectionDevice inside WANDevice, and a description that
 * flattens it will be rejected by clients that walk the tree by path rather
 * than by search.
 */
function encode_device_description(options) {
  options = options || {};
  var version = options.igdVersion || 1;
  var conn_type = 'urn:schemas-upnp-org:service:WANIPConnection:' + version;

  function service(type, id, control, scpd, event) {
    return '<service>' +
      '<serviceType>' + type + '</serviceType>' +
      '<serviceId>urn:upnp-org:serviceId:' + id + '</serviceId>' +
      '<controlURL>' + control + '</controlURL>' +
      '<eventSubURL>' + (event || control + '/event') + '</eventSubURL>' +
      '<SCPDURL>' + scpd + '</SCPDURL>' +
      '</service>';
  }

  var wan_services = service(conn_type, 'WANIPConn1',
                             options.controlUrl || '/ctl/IPConn',
                             options.scpdUrl || '/scpd/IPConn.xml');

  if (options.firewallControlUrl) {
    wan_services += service('urn:schemas-upnp-org:service:WANIPv6FirewallControl:1',
                            'WANIPv6Firewall1', options.firewallControlUrl,
                            options.firewallScpdUrl || '/scpd/IPv6FC.xml');
  }

  return '<?xml version="1.0"?>' +
    '<root xmlns="urn:schemas-upnp-org:device-1-0" configId="' + (options.configId || 1) + '">' +
    '<specVersion><major>1</major><minor>' + (version >= 2 ? 1 : 0) + '</minor></specVersion>' +
    '<device>' +
      '<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:' + version + '</deviceType>' +
      '<friendlyName>' + escape_xml(options.friendlyName || 'Node Router') + '</friendlyName>' +
      '<manufacturer>' + escape_xml(options.manufacturer || 'port-mapper') + '</manufacturer>' +
      '<modelName>' + escape_xml(options.modelName || 'Node IGD') + '</modelName>' +
      '<modelNumber>' + escape_xml(options.modelNumber || '1') + '</modelNumber>' +
      '<UDN>' + escape_xml(options.udn) + '</UDN>' +
      '<serviceList>' +
        service('urn:schemas-upnp-org:service:Layer3Forwarding:1', 'L3Forwarding1',
                options.l3ControlUrl || '/ctl/L3F', '/scpd/L3F.xml') +
      '</serviceList>' +
      '<deviceList><device>' +
        '<deviceType>urn:schemas-upnp-org:device:WANDevice:' + version + '</deviceType>' +
        '<friendlyName>WANDevice</friendlyName>' +
        '<manufacturer>' + escape_xml(options.manufacturer || 'port-mapper') + '</manufacturer>' +
        '<modelName>WAN Device</modelName>' +
        '<UDN>' + escape_xml(options.udn) + '-wan</UDN>' +
        '<serviceList>' +
          service('urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1',
                  'WANCommonIFC1', options.commonControlUrl || '/ctl/CommonIFC',
                  '/scpd/CommonIFC.xml') +
        '</serviceList>' +
        '<deviceList><device>' +
          '<deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:' + version + '</deviceType>' +
          '<friendlyName>WANConnectionDevice</friendlyName>' +
          '<manufacturer>' + escape_xml(options.manufacturer || 'port-mapper') + '</manufacturer>' +
          '<modelName>WAN Connection Device</modelName>' +
          '<UDN>' + escape_xml(options.udn) + '-conn</UDN>' +
          '<serviceList>' + wan_services + '</serviceList>' +
        '</device></deviceList>' +
      '</device></deviceList>' +
    '</device></root>';
}


/* ============================ URL handling ============================ */

/**
 * Resolve a possibly-relative URL against the LOCATION we fetched the
 * description from. Control URLs in the wild come as '/ctl/IPConn',
 * 'ctl/IPConn' or a full 'http://...' — all three must work.
 */
function resolve_url(base, ref) {
  if (!ref) return null;
  if (/^https?:\/\//i.test(ref)) return ref;

  var m = /^(https?:\/\/[^/]+)(\/[^?#]*)?/i.exec(base || '');
  if (!m) return ref;
  var origin = m[1];

  if (ref.charAt(0) === '/') return origin + ref;

  var dir = (m[2] || '/');
  dir = dir.slice(0, dir.lastIndexOf('/') + 1);
  return origin + dir + ref;
}


/**
 * Host and port of a LOCATION URL, for validating it against the LAN.
 *
 * The bracketed form is matched first on purpose: an IPv6 literal is full of
 * colons, so a pattern that tries the bare-host alternative first stops at the
 * first one and reports "2001" as the host of http://[2001:db8::1]:5000/.
 */
function url_host(url) {
  var m = /^https?:\/\/(\[[^\]]+\]|[^/:]+)(?::(\d+))?/i.exec(url || '');
  if (!m) return null;
  var host = m[1].replace(/^\[|\]$/g, '');
  return { host: host, port: m[2] ? parseInt(m[2], 10) : 80 };
}


/* ============================== XML ============================== */

/**
 * Parse an XML document into a tree of
 *   { name, attrs, children, text }
 *
 * Namespace prefixes are stripped from element and attribute names. Text and
 * CDATA of an element are concatenated into `text`; comments, processing
 * instructions and the XML declaration are dropped.
 *
 * Bytes are decoded first so a declared non-UTF-8 encoding is honoured, and
 * both size and depth are bounded before anything is walked: RFC 6886 §9.3
 * notes that UPnP places no upper limit on how large a description may be,
 * and this is untrusted input from the network.
 */
function parse_xml(text) {
  if (typeof text !== 'string') text = bytesToText(text);
  if (text.length > MAX_XML_BYTES) {
    throw new Error('Malformed XML: document exceeds ' + MAX_XML_BYTES + ' bytes');
  }

  var doc;
  try {
    doc = parseXml(text, { ignoreUndefinedEntities: false });
  } catch (e) {
    throw new Error('Malformed XML: ' + e.message);
  }

  if (!doc.root) throw new Error('Malformed XML: no root element');
  return convert(doc.root, 1);
}


function local_name(raw) {
  var colon = raw.indexOf(':');
  return colon === -1 ? raw : raw.slice(colon + 1);
}


function convert(el, depth) {
  if (depth > MAX_XML_DEPTH) {
    throw new Error('Malformed XML: nesting deeper than ' + MAX_XML_DEPTH);
  }

  var node = {
    name:     local_name(el.name),
    attrs:    Object.create(null),
    children: [],
    text:     ''
  };

  var attrs = el.attributes || {};
  for (var k in attrs) {
    if (Object.prototype.hasOwnProperty.call(attrs, k)) {
      node.attrs[local_name(k)] = attrs[k];
    }
  }

  var kids = el.children || [];
  for (var i = 0; i < kids.length; i++) {
    var c = kids[i];
    if (c.type === 'element') node.children.push(convert(c, depth + 1));
    else if (c.type === 'text' || c.type === 'cdata') node.text += c.text;
  }

  return node;
}


function escape_xml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}


/** First direct child with this name, or null. */
function child(node, name) {
  if (!node) return null;
  for (var i = 0; i < node.children.length; i++) {
    if (node.children[i].name === name) return node.children[i];
  }
  return null;
}

/** All direct children with this name. */
function children(node, name) {
  var out = [];
  if (!node) return out;
  for (var i = 0; i < node.children.length; i++) {
    if (node.children[i].name === name) out.push(node.children[i]);
  }
  return out;
}

/** Trimmed text of a direct child, or null. */
function child_text(node, name) {
  var c = child(node, name);
  return c ? c.text.trim() : null;
}

/** Every descendant with this name, at any depth. */
function descendants(node, name, out) {
  out = out || [];
  if (!node) return out;
  for (var i = 0; i < node.children.length; i++) {
    var c = node.children[i];
    if (c.name === name) out.push(c);
    descendants(c, name, out);
  }
  return out;
}


/* ===================== Device description parsing ===================== */

/**
 * Turn a device description document into everything the UPnP session needs.
 *
 *   parse_device_description(xml, 'http://192.168.1.1:5000/rootDesc.xml')
 *
 * Returns:
 *   {
 *     friendlyName, manufacturer, modelName, modelNumber, udn,
 *     deviceType, igdVersion,          // 1 | 2 | null
 *     services: [{ type, serviceId, controlUrl, scpdUrl, eventSubUrl }],
 *     connection: { type, controlUrl, ... } | null,   // best mapping service
 *     firewall:   { ... } | null                      // IGD:2 IPv6 pinholes
 *   }
 *
 * The tree is walked with descendants() rather than by fixed path, because
 * the nesting differs between vendors: the WANConnectionDevice may sit at
 * different depths, and some gateways expose several WAN devices.
 */
function parse_device_description(xml, base_url) {
  var root = (typeof xml === 'string' || xml instanceof Uint8Array) ? parse_xml(xml) : xml;

  var device = child(root, 'device');
  if (!device) throw new Error('Not a UPnP device description: no <device> element');

  var url_base = child_text(root, 'URLBase');
  var base = url_base || base_url;

  var device_type = child_text(device, 'deviceType');
  var igd_version = null;
  if (device_type) {
    var m = /InternetGatewayDevice:(\d+)/.exec(device_type);
    if (m) igd_version = parseInt(m[1], 10);
  }

  var info = {
    friendlyName: child_text(device, 'friendlyName'),
    manufacturer: child_text(device, 'manufacturer'),
    modelName:    child_text(device, 'modelName'),
    modelNumber:  child_text(device, 'modelNumber'),
    udn:          child_text(device, 'UDN'),
    deviceType:   device_type,
    igdVersion:   igd_version,
    services:     [],
    connection:   null,
    firewall:     null
  };

  var found = descendants(root, 'service');
  for (var i = 0; i < found.length; i++) {
    var s = found[i];
    var type = child_text(s, 'serviceType');
    if (!type) continue;

    var service = {
      type:        type,
      serviceId:   child_text(s, 'serviceId'),
      controlUrl:  resolve_url(base, child_text(s, 'controlURL')),
      scpdUrl:     resolve_url(base, child_text(s, 'SCPDURL')),
      eventSubUrl: resolve_url(base, child_text(s, 'eventSubURL'))
    };
    info.services.push(service);

    if (type === FIREWALL_SERVICE && !info.firewall) info.firewall = service;
  }

  // Pick the best mapping service by preference order, not by document order
  for (var p = 0; p < CONNECTION_SERVICES.length && !info.connection; p++) {
    for (var j = 0; j < info.services.length; j++) {
      if (info.services[j].type === CONNECTION_SERVICES[p]) {
        info.connection = info.services[j];
        break;
      }
    }
  }

  // Some gateways advertise a connection service version the root device
  // does not mention; trust the service, since that is what we will call.
  if (info.igdVersion === null && info.connection) {
    var vm = /Connection:(\d+)$/.exec(info.connection.type);
    if (vm) info.igdVersion = parseInt(vm[1], 10);
  }

  return info;
}


/* ============================== Text I/O ============================== */

var _encoder = new TextEncoder();
var _decoder = new TextDecoder('utf-8', { fatal: false });
var _latin1  = new TextDecoder('latin1');

function textToBytes(s) { return _encoder.encode(s); }

/**
 * Decode bytes to text, honouring the encoding declared in the XML prolog.
 * Most gateways send UTF-8, but ISO-8859-1 and windows-1252 do turn up, and
 * decoding those as UTF-8 mangles any non-ASCII friendlyName. The prolog is
 * ASCII by definition, so it can be read before the encoding is known.
 */
function bytesToText(b) {
  if (typeof b === 'string') return b;
  var bytes = b instanceof Uint8Array ? b : new Uint8Array(b);

  var head = _latin1.decode(bytes.subarray(0, 200));
  var m = /<\?xml[^>]*encoding\s*=\s*["']([\w-]+)["']/i.exec(head);
  if (m) {
    var label = m[1].toLowerCase();
    if (label !== 'utf-8' && label !== 'utf8') {
      try { return new TextDecoder(label, { fatal: false }).decode(bytes); }
      catch (e) { /* unknown label — fall through to UTF-8 */ }
    }
  }
  return _decoder.decode(bytes);
}


export {
  // Constants
  MULTICAST_ADDR,
  MULTICAST_PORT,
  MULTICAST_ADDR_V6_LINK,
  MULTICAST_ADDR_V6_SITE,
  multicast_for,
  host_header,
  MAX_XML_BYTES,
  MAX_XML_DEPTH,
  ST,
  CONNECTION_SERVICES,
  FIREWALL_SERVICE,

  // SSDP
  encode_msearch,
  encode_msearch_response,
  encode_notify,
  encode_device_description,
  decode_ssdp,
  usn_uuid,
  st_matches,

  // URLs
  resolve_url,
  url_host,

  // XML
  parse_xml,
  child,
  children,
  child_text,
  descendants,
  escape_xml,

  // Device description
  parse_device_description,

  // Text
  textToBytes,
  bytesToText
};
