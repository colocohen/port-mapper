/**
 * wire.js — NAT-PMP / PCP protocol constants, binary helpers, encode/decode.
 *
 * Pure functions, zero state. Foundation layer for port-mapper.
 *
 * Nothing here touches the clock or a random source: same input, same output,
 * always. Nonce generation, retransmission timing, lifetime defaults and the
 * reboot-detection heuristics are protocol behaviour, not wire format, and
 * live in the session layer.
 *
 * NAT-PMP and PCP share UDP port 5351 and are distinguished by the first
 * byte (the version): 0 = NAT-PMP, 2 = PCP. PCP was designed as NAT-PMP's
 * successor with a deliberately compatible framing, so both live here.
 *
 * References:
 *   RFC 6886 — NAT Port Mapping Protocol (NAT-PMP), version 0
 *   RFC 6887 — Port Control Protocol (PCP), version 2
 *   RFC 6887 §19 — PCP is IPv4/IPv6 agnostic: all addresses on the wire are
 *                  16 bytes, IPv4 carried as IPv4-mapped IPv6 (::ffff:a.b.c.d)
 */

// Cached instances — avoid creating new ones per call
var _encoder = new TextEncoder();
var _decoder = new TextDecoder();


/* ============================== Constants ============================== */

// Both protocols talk to the gateway on 5351. Clients additionally listen on
// 5350 for unsolicited ANNOUNCE (PCP) / address-change (NAT-PMP) multicasts.
const SERVER_PORT = 5351;
const CLIENT_PORT = 5350;

// RFC 6886 §3.2.1 / RFC 6887 §8.1 — announcements go to these groups
const NATPMP_MULTICAST = '224.0.0.1';
const PCP_MULTICAST_V4 = '224.0.0.1';
const PCP_MULTICAST_V6 = 'ff02::1';

// RFC 6887 §7: a PCP message must never exceed 1100 bytes
const MAX_PACKET_SIZE = 1100;

// RFC 6887 §7.1 — the R bit in byte 1 distinguishes request from response
const RESPONSE_BIT = 0x80;

const VERSION = {
  NATPMP: 0,
  PCP:    2
};

// ---- NAT-PMP (RFC 6886) ----

const NATPMP_OP = {
  EXTERNAL_ADDRESS: 0,   // "what is my public IPv4?"
  MAP_UDP:          1,
  MAP_TCP:          2
};

// Responses are the request opcode + 128
const NATPMP_RESULT = {
  SUCCESS:             0,
  UNSUPPORTED_VERSION: 1,
  NOT_AUTHORIZED:      2,   // NAT-PMP disabled by the administrator
  NETWORK_FAILURE:     3,   // gateway has no upstream address yet
  OUT_OF_RESOURCES:    4,
  UNSUPPORTED_OPCODE:  5
};

// ---- PCP (RFC 6887) ----

const PCP_OP = {
  ANNOUNCE: 0,
  MAP:      1,
  PEER:     2
};

// RFC 6887 §7.4
const PCP_RESULT = {
  SUCCESS:                 0,
  UNSUPP_VERSION:          1,
  NOT_AUTHORIZED:          2,
  MALFORMED_REQUEST:       3,
  UNSUPP_OPCODE:           4,
  UNSUPP_OPTION:           5,
  MALFORMED_OPTION:        6,
  NETWORK_FAILURE:         7,
  NO_RESOURCES:            8,
  UNSUPP_PROTOCOL:         9,
  USER_EX_QUOTA:          10,
  CANNOT_PROVIDE_EXTERNAL: 11,
  ADDRESS_MISMATCH:       12,
  EXCESSIVE_REMOTE_PEERS: 13
};

// RFC 6887 §13
const PCP_OPTION = {
  THIRD_PARTY:    1,
  PREFER_FAILURE: 2,
  FILTER:         3
};

// IANA protocol numbers used in the MAP opcode
const PROTO = {
  ALL: 0,    // RFC 6887 §11.1 — wildcard, maps every protocol
  TCP: 6,
  UDP: 17
};



function natpmp_result_name(code) {
  for (var k in NATPMP_RESULT) {
    if (NATPMP_RESULT[k] === code) return k;
  }
  return 'UNKNOWN_' + code;
}

function pcp_result_name(code) {
  for (var k in PCP_RESULT) {
    if (PCP_RESULT[k] === code) return k;
  }
  return 'UNKNOWN_' + code;
}

function pcp_opcode_name(op) {
  for (var k in PCP_OP) {
    if (PCP_OP[k] === op) return k;
  }
  return 'UNKNOWN_' + op;
}

function proto_name(n) {
  if (n === PROTO.TCP) return 'tcp';
  if (n === PROTO.UDP) return 'udp';
  if (n === PROTO.ALL) return 'all';
  return String(n);
}

function proto_number(name) {
  if (typeof name === 'number') return name;
  var s = String(name).toLowerCase();
  if (s === 'tcp') return PROTO.TCP;
  if (s === 'udp') return PROTO.UDP;
  if (s === 'all' || s === '*') return PROTO.ALL;
  throw new Error('Unknown protocol: ' + name);
}


/* ============================ Binary helpers ============================ */

function w_u8(buf, off, v)  { buf[off] = v & 0xFF; return off + 1; }
function w_u16(buf, off, v) { buf[off] = (v >>> 8) & 0xFF; buf[off + 1] = v & 0xFF; return off + 2; }
function w_u32(buf, off, v) {
  buf[off]     = (v >>> 24) & 0xFF;
  buf[off + 1] = (v >>> 16) & 0xFF;
  buf[off + 2] = (v >>> 8)  & 0xFF;
  buf[off + 3] = v & 0xFF;
  return off + 4;
}

function w_bytes(buf, off, src) {
  for (var i = 0; i < src.length; i++) buf[off + i] = src[i];
  return off + src.length;
}

function r_u8(buf, off)  { return [buf[off], off + 1]; }
function r_u16(buf, off) { return [(buf[off] << 8) | buf[off + 1], off + 2]; }
function r_u32(buf, off) {
  return [((buf[off] << 24) >>> 0) + (buf[off + 1] << 16) + (buf[off + 2] << 8) + buf[off + 3], off + 4];
}

function r_bytes(buf, off, len) {
  var out = new Uint8Array(len);
  for (var i = 0; i < len; i++) out[i] = buf[off + i];
  return [out, off + len];
}


/* ============================ Address helpers ============================ */

function encode_ip4(ip) {
  var parts = String(ip).split('.');
  if (parts.length !== 4) throw new Error('Invalid IPv4 address: ' + ip);

  var out = new Uint8Array(4);
  for (var i = 0; i < 4; i++) {
    var n = parseInt(parts[i], 10);
    if (isNaN(n) || n < 0 || n > 255) throw new Error('Invalid IPv4 address: ' + ip);
    out[i] = n;
  }
  return out;
}


function decode_ip4(buf, off) {
  return buf[off] + '.' + buf[off + 1] + '.' + buf[off + 2] + '.' + buf[off + 3];
}


/**
 * Encode any address as the 16-byte form PCP puts on the wire.
 * IPv4 becomes IPv4-mapped IPv6 (RFC 6887 §5): 80 zero bits, 16 one bits,
 * then the 4 address bytes.
 */
function encode_ip(ip) {
  var out = new Uint8Array(16);

  if (String(ip).indexOf(':') === -1) {
    out[10] = 0xFF;
    out[11] = 0xFF;
    var v4 = encode_ip4(ip);
    out[12] = v4[0]; out[13] = v4[1]; out[14] = v4[2]; out[15] = v4[3];
    return out;
  }

  var text = String(ip).split('%')[0];   // drop any zone id

  // An IPv6 address may embed a dotted-quad tail (::ffff:1.2.3.4)
  var tail = null;
  var last_colon = text.lastIndexOf(':');
  var after = text.slice(last_colon + 1);
  if (after.indexOf('.') !== -1) {
    tail = encode_ip4(after);
    text = text.slice(0, last_colon);        // drop the dotted quad; it fills groups 6-7
    if (text === '') text = '::';
  }

  var halves = text.split('::');
  if (halves.length > 2) throw new Error('Invalid IPv6 address: ' + ip);

  function to_groups(s) {
    if (!s) return [];
    var parts = s.split(':');
    var groups = [];
    for (var i = 0; i < parts.length; i++) {
      if (parts[i] === '') continue;
      var n = parseInt(parts[i], 16);
      if (isNaN(n) || n < 0 || n > 0xFFFF) throw new Error('Invalid IPv6 address: ' + ip);
      groups.push(n);
    }
    return groups;
  }

  var head = to_groups(halves[0]);
  var rest = halves.length === 2 ? to_groups(halves[1]) : [];

  // A dotted-quad tail occupies the final two groups
  var want = tail ? 6 : 8;

  var fill = want - head.length - rest.length;
  if (halves.length === 1) {
    if (head.length !== want) throw new Error('Invalid IPv6 address: ' + ip);
    fill = 0;
  } else if (fill < 0) {
    throw new Error('Invalid IPv6 address: ' + ip);
  }

  var groups = head.slice();
  for (var f = 0; f < fill; f++) groups.push(0);
  groups = groups.concat(rest);

  var off = 0;
  var limit = tail ? 6 : 8;
  for (var g = 0; g < limit; g++) off = w_u16(out, off, groups[g] || 0);
  if (tail) w_bytes(out, 12, tail);

  return out;
}


/**
 * Decode the 16-byte wire form. IPv4-mapped addresses come back as plain
 * dotted-quad strings, which is what callers actually want.
 */
function decode_ip(buf, off) {
  var mapped = true;
  for (var i = 0; i < 10; i++) if (buf[off + i] !== 0) { mapped = false; break; }
  if (mapped && buf[off + 10] === 0xFF && buf[off + 11] === 0xFF) {
    return decode_ip4(buf, off + 12);
  }

  var groups = [];
  for (var g = 0; g < 8; g++) {
    groups.push(((buf[off + g * 2] << 8) | buf[off + g * 2 + 1]) >>> 0);
  }

  // Collapse the longest run of zero groups into '::' (RFC 5952)
  var best_start = -1, best_len = 0, run_start = -1, run_len = 0;
  for (var j = 0; j < 8; j++) {
    if (groups[j] === 0) {
      if (run_start === -1) { run_start = j; run_len = 1; }
      else run_len++;
      if (run_len > best_len) { best_len = run_len; best_start = run_start; }
    } else {
      run_start = -1; run_len = 0;
    }
  }

  var parts = [];
  for (var k = 0; k < 8; k++) {
    if (best_len > 1 && k === best_start) {
      parts.push('');
      k += best_len - 1;
      if (k === 7) parts.push('');
      continue;
    }
    parts.push(groups[k].toString(16));
  }

  var text = parts.join(':');
  if (text.indexOf(':::') !== -1) text = text.replace(':::', '::');
  if (best_start === 0 && best_len > 1) text = ':' + text;
  return text;
}


function is_ipv4_mapped(buf, off) {
  for (var i = 0; i < 10; i++) if (buf[off + i] !== 0) return false;
  return buf[off + 10] === 0xFF && buf[off + 11] === 0xFF;
}


/**
 * RFC 6598 — 100.64.0.0/10 is the shared address space handed out by
 * carrier-grade NAT. If the gateway reports one of these as our "external"
 * address, port forwarding cannot possibly work from the internet.
 */
function is_cgnat_address(ip) {
  if (!ip || String(ip).indexOf('.') === -1) return false;
  var parts = String(ip).split('.');
  if (parseInt(parts[0], 10) !== 100) return false;
  var second = parseInt(parts[1], 10);
  return second >= 64 && second <= 127;
}


/**
 * Classify the address a gateway reports as its own external one. This is the
 * single most useful thing a client can know, because a mapping can succeed
 * completely and still be unreachable.
 *
 *   'public'     a globally routable address — a mapping here should work
 *   'cgnat'      RFC 6598 shared space; the ISP is translating too, and no
 *                mapping on this gateway can be reached from the internet
 *   'private'    RFC 1918 — the gateway is itself behind another NAT (double
 *                NAT). The upstream device would need its own mapping.
 *   'loopback' / 'linklocal' / 'unspecified' — not a working external address
 */
function classify_external_address(ip) {
  if (!ip) return 'unknown';
  if (String(ip).indexOf(':') !== -1) return classify_ipv6_address(ip);

  var p = String(ip).split('.').map(function(n) { return parseInt(n, 10); });
  if (p.length !== 4 || p.some(isNaN)) return 'unknown';

  if (p[0] === 0) return 'unspecified';
  if (p[0] === 127) return 'loopback';
  if (p[0] === 169 && p[1] === 254) return 'linklocal';
  if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return 'cgnat';
  if (p[0] === 10) return 'private';
  if (p[0] === 192 && p[1] === 168) return 'private';
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return 'private';
  return 'public';
}


/**
 * The IPv6 equivalent. The vocabulary is different because IPv6 has no NAT to
 * speak of: an address is either globally routable or it is not, and there is
 * no "external address" that differs from the host's own.
 *
 *   'public'     2000::/3 global unicast — reachable, needs only a pinhole
 *   'ula'        fc00::/7 unique local — the closest thing v6 has to RFC 1918,
 *                and not routable on the internet
 *   'linklocal'  fe80::/10 — valid only on one segment
 *   'loopback' / 'unspecified' / 'multicast'
 */
function classify_ipv6_address(ip) {
  var text = String(ip).split('%')[0].toLowerCase();

  if (text === '::') return 'unspecified';
  if (text === '::1') return 'loopback';

  // An IPv4-mapped address is really an IPv4 address wearing a costume
  if (text.indexOf('::ffff:') === 0) {
    var tail = text.slice(7);
    if (tail.indexOf('.') !== -1) return classify_external_address(tail);
  }

  var head = parseInt(text.split(':')[0] || '0', 16);
  if (isNaN(head)) return 'unknown';

  if ((head & 0xFF00) === 0xFF00) return 'multicast';          // ff00::/8
  if ((head & 0xFFC0) === 0xFE80) return 'linklocal';          // fe80::/10
  if ((head & 0xFE00) === 0xFC00) return 'ula';                // fc00::/7
  if ((head & 0xE000) === 0x2000) return 'public';             // 2000::/3
  return 'unknown';
}


/** True when the address cannot be reached from the internet. */
function is_ipv6_local(ip) {
  var kind = classify_ipv6_address(ip);
  return kind === 'ula' || kind === 'linklocal' || kind === 'loopback' ||
         kind === 'unspecified';
}


function is_private_address(ip) {
  if (ip && String(ip).indexOf(':') !== -1) return is_ipv6_local(ip);

  if (!ip || String(ip).indexOf('.') === -1) return false;
  var p = String(ip).split('.').map(function(n) { return parseInt(n, 10); });
  if (p[0] === 10) return true;
  if (p[0] === 192 && p[1] === 168) return true;
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
  if (p[0] === 169 && p[1] === 254) return true;
  if (p[0] === 127) return true;
  return false;
}


/* ============================ Nonce ============================ */

/**
 * RFC 6887 §11.1 — every MAP request carries a 96-bit nonce chosen by the
 * client, which ties renewals to the original mapping and stops other hosts
 * on the LAN from deleting or hijacking it. Because it must be unpredictable
 * it is generated in the session layer (like the DHCP xid), not here.
 * These helpers are the deterministic half.
 */
function nonce_to_hex(nonce) {
  var s = '';
  for (var i = 0; i < nonce.length; i++) {
    var h = nonce[i].toString(16);
    s += (h.length === 1 ? '0' : '') + h;
  }
  return s;
}


function nonce_from_hex(hex) {
  var out = new Uint8Array(12);
  for (var i = 0; i < 12; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16) || 0;
  return out;
}


function nonce_equal(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}


/* ========================= NAT-PMP encode/decode ========================= */

/**
 * RFC 6886 §3.2 — external address request. Two bytes, no payload.
 */
function encode_natpmp_address_request() {
  var buf = new Uint8Array(2);
  buf[0] = VERSION.NATPMP;
  buf[1] = NATPMP_OP.EXTERNAL_ADDRESS;
  return buf;
}


/**
 * RFC 6886 §3.3 — mapping request (12 bytes).
 *
 *   msg = { protocol, internalPort, externalPort, lifetime }
 *
 * RFC 6886 §3.4 — lifetime 0 deletes. The suggested external port MUST then
 * be zero, and internalPort 0 as well deletes every mapping of that
 * protocol for this client.
 *
 * On renewal the caller should pass the external port the gateway actually
 * assigned, not the one originally wanted (§3.3): a rebooted gateway sees
 * the renewal as a fresh request and is likely to grant the same port back.
 */
function encode_natpmp_map_request(msg) {
  var proto = proto_number(msg.protocol);
  if (proto !== PROTO.TCP && proto !== PROTO.UDP) {
    throw new Error('NAT-PMP supports only TCP and UDP');
  }

  if (typeof msg.lifetime !== 'number') throw new Error('lifetime required (seconds; 0 deletes)');
  var lifetime = msg.lifetime;
  var external = msg.externalPort || 0;
  if (lifetime === 0) external = 0;             // §3.4 — MUST be zero on delete

  var buf = new Uint8Array(12);
  var off = 0;
  off = w_u8(buf, off, VERSION.NATPMP);
  off = w_u8(buf, off, proto === PROTO.UDP ? NATPMP_OP.MAP_UDP : NATPMP_OP.MAP_TCP);
  off = w_u16(buf, off, 0);                                   // reserved
  off = w_u16(buf, off, msg.internalPort || 0);
  off = w_u16(buf, off, external);                            // suggested
  off = w_u32(buf, off, lifetime);
  return buf;
}


/**
 * Decode any NAT-PMP response. Returns a shape-tagged object:
 *   { version, opcode, kind: 'address' | 'map', resultCode, epoch, ... }
 *
 * RFC 6886 §3.5 carve-out: the "Unsupported Version" reply is sent with
 * OP = 0 rather than 128 + op, and is only 8 bytes long. It is the fast
 * fail-over signal a NAT-PMP-only gateway returns to a PCP request (§1.1),
 * so it must decode rather than throw. Some gateways set the response bit
 * anyway; both forms are accepted.
 */
function decode_natpmp_response(buf) {
  if (buf.length < 4) throw new Error('NAT-PMP response too short: ' + buf.length + ' bytes');

  var version = buf[0];
  if (version !== VERSION.NATPMP) {
    throw new Error('Not a NAT-PMP response (version ' + version + ')');
  }

  var raw_op = buf[1];
  var result = (buf[2] << 8) | buf[3];

  var opcode;
  if (raw_op >= 128) {
    opcode = raw_op - 128;
  } else if (result === NATPMP_RESULT.UNSUPPORTED_VERSION) {
    opcode = raw_op;                       // §3.5 form — no response bit
  } else {
    throw new Error('NAT-PMP opcode ' + raw_op + ' is not a response');
  }

  var off = 4;
  var pair = r_u32(buf, off);
  var epoch = pair[0];
  off = pair[1];

  var msg = {
    version:    version,
    opcode:     opcode,
    resultCode: result,
    resultName: natpmp_result_name(result),
    epoch:      epoch,
    // §1.1 — the client should immediately retry in NAT-PMP format rather
    // than remembering that this gateway "only speaks NAT-PMP"
    unsupportedVersion: result === NATPMP_RESULT.UNSUPPORTED_VERSION
  };

  if (opcode === NATPMP_OP.EXTERNAL_ADDRESS) {
    msg.kind = 'address';
    // §3.2 — on a non-zero result the address field is undefined
    if (result === NATPMP_RESULT.SUCCESS) {
      if (buf.length < 12) throw new Error('NAT-PMP address response too short');
      msg.externalIp = decode_ip4(buf, off);
    }
    return msg;
  }

  if (opcode === NATPMP_OP.MAP_UDP || opcode === NATPMP_OP.MAP_TCP) {
    msg.kind = 'map';
    msg.protocol = opcode === NATPMP_OP.MAP_UDP ? 'udp' : 'tcp';

    // §3.5 — error responses still carry the internal port, which is how the
    // client tells which request failed. Parse whenever the bytes are there.
    if (buf.length >= 16) {
      pair = r_u16(buf, off); msg.internalPort = pair[0]; off = pair[1];
      pair = r_u16(buf, off); msg.externalPort = pair[0]; off = pair[1];
      pair = r_u32(buf, off); msg.lifetime     = pair[0]; off = pair[1];
    } else if (result === NATPMP_RESULT.SUCCESS) {
      throw new Error('NAT-PMP map response too short');
    }
    return msg;
  }

  throw new Error('Unknown NAT-PMP opcode: ' + opcode);
}


/* =========================== PCP encode/decode =========================== */

/**
 * RFC 6887 §7.1 — common request header, 24 bytes:
 *
 *   0                   1                   2                   3
 *   +-------+-+---------+---------------+-------------------------------+
 *   | Ver=2 |R| Opcode  |   Reserved    |                               |
 *   +-------+-+---------+---------------+                               |
 *   |                     Requested Lifetime (32 bits)                  |
 *   +-------------------------------------------------------------------+
 *   |            PCP Client's IP Address (128 bits)                     |
 *   +-------------------------------------------------------------------+
 *
 * The client address is echoed back by the server; a mismatch means a NAT
 * sits between us and the PCP server (result 12, ADDRESS_MISMATCH).
 */
function encode_pcp_header(opcode, lifetime, client_ip) {
  var buf = new Uint8Array(24);
  var off = 0;
  off = w_u8(buf, off, VERSION.PCP);
  off = w_u8(buf, off, opcode & 0x7F);          // R = 0 for requests
  off = w_u16(buf, off, 0);                     // reserved
  off = w_u32(buf, off, lifetime >>> 0);
  w_bytes(buf, off, encode_ip(client_ip));
  return buf;
}


/**
 * RFC 6887 §13 — option framing: code(1) reserved(1) length(2) then the
 * payload padded to a 4-byte boundary. The length field counts the payload
 * only, not the padding.
 */
function encode_pcp_options(options) {
  if (!options || options.length === 0) return new Uint8Array(0);

  var total = 0;
  var i;
  for (i = 0; i < options.length; i++) {
    var len = options[i].data ? options[i].data.length : 0;
    total += 4 + len + ((4 - (len % 4)) % 4);
  }

  var buf = new Uint8Array(total);
  var off = 0;
  for (i = 0; i < options.length; i++) {
    var opt = options[i];
    var data = opt.data || new Uint8Array(0);
    off = w_u8(buf, off, opt.code);
    off = w_u8(buf, off, 0);                    // reserved
    off = w_u16(buf, off, data.length);
    off = w_bytes(buf, off, data);
    var pad = (4 - (data.length % 4)) % 4;
    off += pad;                                 // buffer is already zeroed
  }
  return buf;
}


function decode_pcp_options(buf, off, end) {
  var options = [];
  while (off + 4 <= end) {
    var code = buf[off];
    var len  = (buf[off + 2] << 8) | buf[off + 3];
    off += 4;
    if (off + len > end) throw new Error('Malformed PCP option: length overruns packet');
    var data = r_bytes(buf, off, len)[0];
    options.push({ code: code, data: data });
    off += len + ((4 - (len % 4)) % 4);
  }
  return options;
}


/**
 * RFC 6887 §11.1 — MAP opcode payload, 36 bytes:
 *
 *   +-------------------------------------------------------------------+
 *   |                 Mapping Nonce (96 bits)                           |
 *   +---------------+---------------------------------------------------+
 *   |   Protocol    |          Reserved (24 bits)                       |
 *   +---------------+-----------------------+---------------------------+
 *   |        Internal Port                  |  Suggested External Port  |
 *   +---------------------------------------+---------------------------+
 *   |           Suggested External IP Address (128 bits)                |
 *   +-------------------------------------------------------------------+
 *
 * msg = { nonce, protocol, internalPort, externalPort, externalIp,
 *         lifetime, clientIp, options }
 *
 * lifetime 0 deletes the mapping (§15).
 */
function encode_pcp_map_request(msg) {
  if (!msg.clientIp) throw new Error('clientIp required — PCP echoes it back to detect double NAT');
  if (!msg.nonce || msg.nonce.length !== 12) {
    throw new Error('nonce required (12 bytes) — generate it in the session, not the encoder');
  }

  if (typeof msg.lifetime !== 'number') throw new Error('lifetime required (seconds; 0 deletes)');
  var header  = encode_pcp_header(PCP_OP.MAP, msg.lifetime, msg.clientIp);
  var options = encode_pcp_options(msg.options);

  var body = new Uint8Array(36);
  var off = 0;
  off = w_bytes(body, off, msg.nonce);
  off = w_u8(body, off, proto_number(msg.protocol === undefined ? PROTO.ALL : msg.protocol));
  off = w_u8(body, off, 0);
  off = w_u16(body, off, 0);                                  // reserved (24 bits total)
  off = w_u16(body, off, msg.internalPort || 0);
  off = w_u16(body, off, msg.externalPort || 0);              // suggested
  w_bytes(body, off, encode_ip(msg.externalIp || '::'));      // suggested, :: = "you choose"

  var out = new Uint8Array(header.length + body.length + options.length);
  out.set(header, 0);
  out.set(body, header.length);
  out.set(options, header.length + body.length);

  if (out.length > MAX_PACKET_SIZE) {
    throw new Error('PCP message exceeds ' + MAX_PACKET_SIZE + ' bytes');
  }
  return out;
}


/**
 * RFC 6887 §13.2 — PREFER_FAILURE.
 *
 * Without it, a MAP request means "give me a port, ideally this one"; with it,
 * it means "give me exactly this port or fail". That is the difference between
 * NAT-PMP semantics and IGD's AddPortMapping, and RFC 6970 §5 notes that
 * AddPortMapping cannot be implemented over PCP without it. Carries no data.
 */
function pcp_option_prefer_failure() {
  return { code: PCP_OPTION.PREFER_FAILURE, data: new Uint8Array(0) };
}


/**
 * RFC 6887 §13.1 — THIRD_PARTY: map on behalf of another host.
 *
 * A PCP server rejects this unless it has been configured to allow it, which
 * is the point: the address is stated explicitly rather than inferred from the
 * packet, so granting it is a deliberate act.
 */
function pcp_option_third_party(internal_ip) {
  return { code: PCP_OPTION.THIRD_PARTY, data: encode_ip(internal_ip) };
}


/**
 * RFC 6887 §13.3 — FILTER: accept inbound traffic only from one remote prefix.
 *
 *   reserved(8) prefix-length(8) remote-port(16) remote-address(128)
 *
 * A prefix length of 0 with a zero address would allow everything, which is
 * what omitting the option already does, so callers pass a real prefix.
 */
function pcp_option_filter(remote_ip, remote_port, prefix_length) {
  var data = new Uint8Array(20);
  var off = 0;
  off = w_u8(data, off, 0);                                   // reserved
  off = w_u8(data, off, prefix_length === undefined ? 128 : prefix_length);
  off = w_u16(data, off, remote_port || 0);
  w_bytes(data, off, encode_ip(remote_ip || '::'));
  return { code: PCP_OPTION.FILTER, data: data };
}


/**
 * RFC 6887 §12.1 — PEER opcode payload, 56 bytes.
 *
 *   +-------------------------------------------------------------------+
 *   |                 Mapping Nonce (96 bits)                           |
 *   +---------------+---------------------------------------------------+
 *   |   Protocol    |          Reserved (24 bits)                       |
 *   +---------------+-----------------------+---------------------------+
 *   |        Internal Port                  |  Suggested External Port  |
 *   +---------------------------------------+---------------------------+
 *   |           Suggested External IP Address (128 bits)                |
 *   +---------------------------------------+---------------------------+
 *   |        Remote Peer Port               |        Reserved           |
 *   +---------------------------------------+---------------------------+
 *   |              Remote Peer IP Address (128 bits)                    |
 *   +-------------------------------------------------------------------+
 *
 * PEER does not open a hole for unsolicited traffic. It names an existing
 * outbound flow so the client can learn the external address and port the NAT
 * gave it, and control how long that binding is kept alive — which lets an
 * application replace frequent keepalive packets with one explicit lifetime.
 */
function encode_pcp_peer_request(msg) {
  if (!msg.clientIp) throw new Error('clientIp required');
  if (!msg.nonce || msg.nonce.length !== 12) throw new Error('nonce required (12 bytes)');
  if (typeof msg.lifetime !== 'number') throw new Error('lifetime required (seconds; 0 deletes)');
  if (!msg.remoteIp) throw new Error('remoteIp required — PEER describes an existing flow');

  var header  = encode_pcp_header(PCP_OP.PEER, msg.lifetime, msg.clientIp);
  var options = encode_pcp_options(msg.options);

  var body = new Uint8Array(56);
  var off = 0;
  off = w_bytes(body, off, msg.nonce);
  off = w_u8(body, off, proto_number(msg.protocol === undefined ? PROTO.TCP : msg.protocol));
  off = w_u8(body, off, 0);
  off = w_u16(body, off, 0);                                  // reserved
  off = w_u16(body, off, msg.internalPort || 0);
  off = w_u16(body, off, msg.externalPort || 0);
  off = w_bytes(body, off, encode_ip(msg.externalIp || '::'));
  off = w_u16(body, off, msg.remotePort || 0);
  off = w_u16(body, off, 0);                                  // reserved
  w_bytes(body, off, encode_ip(msg.remoteIp));

  var out = new Uint8Array(header.length + body.length + options.length);
  out.set(header, 0);
  out.set(body, header.length);
  out.set(options, header.length + body.length);

  if (out.length > MAX_PACKET_SIZE) {
    throw new Error('PCP message exceeds ' + MAX_PACKET_SIZE + ' bytes');
  }
  return out;
}


/**
 * RFC 6887 §14.1 — ANNOUNCE request: header only, lifetime must be 0.
 * Used as a cheap "are you there, and do you speak PCP?" probe.
 */
function encode_pcp_announce_request(client_ip) {
  return encode_pcp_header(PCP_OP.ANNOUNCE, 0, client_ip);
}


/**
 * RFC 6887 §7.2 — common response header, 24 bytes:
 *
 *   +-------+-+---------+---------------+---------------+---------------+
 *   | Ver=2 |R| Opcode  |   Reserved    |  Result Code  |               |
 *   +-------+-+---------+---------------+---------------+               |
 *   |                      Lifetime (32 bits)                           |
 *   +-------------------------------------------------------------------+
 *   |                   Epoch Time (32 bits)                            |
 *   +-------------------------------------------------------------------+
 *   |                   Reserved (96 bits)                              |
 *   +-------------------------------------------------------------------+
 *
 * Epoch Time is the key to detecting a rebooted gateway: if it jumps
 * backwards or grows more slowly than wall-clock time, every mapping the
 * gateway held is gone and must be re-created (§8.5).
 */
function decode_pcp_response(buf) {
  if (buf.length < 24) throw new Error('PCP response too short: ' + buf.length + ' bytes');
  if (buf.length > MAX_PACKET_SIZE) throw new Error('PCP response exceeds ' + MAX_PACKET_SIZE + ' bytes');

  var version = buf[0];
  if (version !== VERSION.PCP) throw new Error('Not a PCP response (version ' + version + ')');
  if ((buf[1] & RESPONSE_BIT) === 0) throw new Error('PCP message is a request, not a response');

  var opcode = buf[1] & 0x7F;
  var msg = {
    version:    version,
    opcode:     opcode,
    opcodeName: pcp_opcode_name(opcode),
    resultCode: buf[3],
    resultName: pcp_result_name(buf[3])
  };

  var off = 4;
  var pair = r_u32(buf, off); msg.lifetime = pair[0]; off = pair[1];
  pair = r_u32(buf, off);     msg.epoch    = pair[0]; off = pair[1];
  off += 12;                                          // reserved

  if (opcode === PCP_OP.ANNOUNCE) {
    msg.options = decode_pcp_options(buf, off, buf.length);
    return msg;
  }

  if (opcode === PCP_OP.MAP) {
    // A failed MAP response still carries the opcode payload (§7.2), so the
    // client can match it to the request by nonce.
    if (buf.length < off + 36) {
      if (msg.resultCode === PCP_RESULT.SUCCESS) throw new Error('PCP MAP response truncated');
      return msg;
    }
    pair = r_bytes(buf, off, 12); msg.nonce = pair[0]; off = pair[1];
    msg.nonceHex = nonce_to_hex(msg.nonce);
    pair = r_u8(buf, off); msg.protocol = proto_name(pair[0]); off = pair[1];
    off += 3;                                         // reserved
    pair = r_u16(buf, off); msg.internalPort = pair[0]; off = pair[1];
    pair = r_u16(buf, off); msg.externalPort = pair[0]; off = pair[1];
    msg.externalIp = decode_ip(buf, off);
    off += 16;
    msg.options = decode_pcp_options(buf, off, buf.length);
    return msg;
  }

  if (opcode === PCP_OP.PEER) {
    if (buf.length < off + 56) {
      if (msg.resultCode === PCP_RESULT.SUCCESS) throw new Error('PCP PEER response truncated');
      return msg;
    }
    pair = r_bytes(buf, off, 12); msg.nonce = pair[0]; off = pair[1];
    msg.nonceHex = nonce_to_hex(msg.nonce);
    pair = r_u8(buf, off); msg.protocol = proto_name(pair[0]); off = pair[1];
    off += 3;
    pair = r_u16(buf, off); msg.internalPort = pair[0]; off = pair[1];
    pair = r_u16(buf, off); msg.externalPort = pair[0]; off = pair[1];
    msg.externalIp = decode_ip(buf, off); off += 16;
    pair = r_u16(buf, off); msg.remotePort = pair[0]; off = pair[1];
    off += 2;
    msg.remoteIp = decode_ip(buf, off); off += 16;
    msg.options = decode_pcp_options(buf, off, buf.length);
    return msg;
  }

  msg.options = [];
  return msg;
}


/* ===================== Server side: requests in ===================== */

/**
 * Decode a NAT-PMP request (the gateway's view).
 *
 * RFC 6886 §3.5 — opcodes 128 and above are responses, not requests, and a
 * server must silently ignore them; that is reported here as kind 'response'
 * so the caller can drop it rather than answer.
 */
function decode_natpmp_request(buf) {
  if (buf.length < 2) throw new Error('NAT-PMP request too short: ' + buf.length + ' bytes');

  var version = buf[0];
  var opcode  = buf[1];

  var msg = { version: version, opcode: opcode };

  if (opcode >= 128) { msg.kind = 'response'; return msg; }

  // §3 — any version other than 0 must be answered with result 1, whatever
  // the opcode claims to be
  if (version !== VERSION.NATPMP) { msg.kind = 'unsupported-version'; return msg; }

  if (opcode === NATPMP_OP.EXTERNAL_ADDRESS) { msg.kind = 'address'; return msg; }

  if (opcode === NATPMP_OP.MAP_UDP || opcode === NATPMP_OP.MAP_TCP) {
    if (buf.length < 12) throw new Error('NAT-PMP map request too short');
    msg.kind = 'map';
    msg.protocol = opcode === NATPMP_OP.MAP_UDP ? 'udp' : 'tcp';
    var off = 4;                                   // skip version, opcode, reserved
    var pair = r_u16(buf, off); msg.internalPort = pair[0]; off = pair[1];
    pair = r_u16(buf, off);     msg.externalPort = pair[0]; off = pair[1];
    pair = r_u32(buf, off);     msg.lifetime     = pair[0];
    return msg;
  }

  msg.kind = 'unsupported-opcode';
  return msg;
}


/**
 * RFC 6886 §3.2 — external address response, 12 bytes.
 */
function encode_natpmp_address_response(msg) {
  var buf = new Uint8Array(12);
  var off = 0;
  off = w_u8(buf, off, VERSION.NATPMP);
  off = w_u8(buf, off, 128 + NATPMP_OP.EXTERNAL_ADDRESS);
  off = w_u16(buf, off, msg.resultCode || 0);
  off = w_u32(buf, off, msg.epoch || 0);
  // §3.2 — on a non-zero result the address field is undefined and must be
  // transmitted as zero
  if (!msg.resultCode && msg.externalIp) w_bytes(buf, off, encode_ip4(msg.externalIp));
  return buf;
}


/**
 * RFC 6886 §3.3 — mapping response, 16 bytes.
 *
 * §3.5 requires the internal port to be echoed even on failure: it is how the
 * client works out which of its requests failed, since the protocol carries
 * no transaction identifier.
 */
function encode_natpmp_map_response(msg) {
  var proto = proto_number(msg.protocol);
  var buf = new Uint8Array(16);
  var off = 0;
  off = w_u8(buf, off, VERSION.NATPMP);
  off = w_u8(buf, off, 128 + (proto === PROTO.UDP ? NATPMP_OP.MAP_UDP : NATPMP_OP.MAP_TCP));
  off = w_u16(buf, off, msg.resultCode || 0);
  off = w_u32(buf, off, msg.epoch || 0);
  off = w_u16(buf, off, msg.internalPort || 0);
  off = w_u16(buf, off, msg.externalPort || 0);
  off = w_u32(buf, off, msg.lifetime || 0);
  return buf;
}


/**
 * RFC 6886 §3.5 — the Unsupported Version reply is only 8 bytes and carries
 * OP = 0 rather than 128 + op.
 */
function encode_natpmp_unsupported_version(epoch) {
  var buf = new Uint8Array(8);
  buf[1] = 0;
  w_u16(buf, 2, NATPMP_RESULT.UNSUPPORTED_VERSION);
  w_u32(buf, 4, epoch || 0);
  return buf;
}


/**
 * RFC 6886 §3.5 — an unsupported opcode is answered by returning the whole
 * request with the response bit set and result 5.
 */
function encode_natpmp_unsupported_opcode(request_buf, epoch) {
  var buf = new Uint8Array(request_buf.length < 8 ? 8 : request_buf.length);
  buf.set(request_buf.subarray(0, request_buf.length));
  buf[1] = request_buf[1] | 128;
  w_u16(buf, 2, NATPMP_RESULT.UNSUPPORTED_OPCODE);
  w_u32(buf, 4, epoch || 0);
  return buf;
}


/**
 * Decode a PCP request (the gateway's view). RFC 6887 §7.1.
 */
function decode_pcp_request(buf) {
  if (buf.length < 24) throw new Error('PCP request too short: ' + buf.length + ' bytes');
  if (buf.length > MAX_PACKET_SIZE) throw new Error('PCP request exceeds ' + MAX_PACKET_SIZE + ' bytes');

  var version = buf[0];
  if ((buf[1] & RESPONSE_BIT) !== 0) return { version: version, kind: 'response' };

  var opcode = buf[1] & 0x7F;
  var msg = {
    version:    version,
    opcode:     opcode,
    opcodeName: pcp_opcode_name(opcode)
  };

  if (version !== VERSION.PCP) { msg.kind = 'unsupported-version'; return msg; }

  var off = 4;
  var pair = r_u32(buf, off); msg.lifetime = pair[0]; off = pair[1];
  // §8.1 — the client's own address, echoed back so a NAT on the path can be
  // detected by comparing it with the packet's real source
  msg.clientIp = decode_ip(buf, off);
  off += 16;

  if (opcode === PCP_OP.ANNOUNCE) {
    msg.kind = 'announce';
    msg.options = decode_pcp_options(buf, off, buf.length);
    return msg;
  }

  if (opcode === PCP_OP.MAP) {
    if (buf.length < off + 36) throw new Error('PCP MAP request truncated');
    msg.kind = 'map';
    pair = r_bytes(buf, off, 12); msg.nonce = pair[0]; off = pair[1];
    msg.nonceHex = nonce_to_hex(msg.nonce);
    pair = r_u8(buf, off); msg.protocol = proto_name(pair[0]); msg.protocolNumber = pair[0]; off = pair[1];
    off += 3;                                        // reserved
    pair = r_u16(buf, off); msg.internalPort = pair[0]; off = pair[1];
    pair = r_u16(buf, off); msg.externalPort = pair[0]; off = pair[1];
    msg.externalIp = decode_ip(buf, off);
    off += 16;
    msg.options = decode_pcp_options(buf, off, buf.length);
    return msg;
  }

  msg.kind = 'unsupported-opcode';
  return msg;
}


/**
 * RFC 6887 §7.2 — common response header, 24 bytes, plus opcode data.
 */
function encode_pcp_response(msg) {
  var body = new Uint8Array(0);

  var boff = 0;

  if (msg.opcode === PCP_OP.MAP) {
    body = new Uint8Array(36);
    boff = w_bytes(body, boff, msg.nonce || new Uint8Array(12));
    boff = w_u8(body, boff, proto_number(msg.protocol === undefined ? PROTO.ALL : msg.protocol));
    boff = w_u8(body, boff, 0);
    boff = w_u16(body, boff, 0);                     // reserved
    boff = w_u16(body, boff, msg.internalPort || 0);
    boff = w_u16(body, boff, msg.externalPort || 0);
    w_bytes(body, boff, encode_ip(msg.externalIp || '::'));
  } else if (msg.opcode === PCP_OP.PEER) {
    // §12.2 — a PEER response repeats the whole request payload, including the
    // remote peer, so the client can match it to the flow it asked about
    body = new Uint8Array(56);
    boff = w_bytes(body, boff, msg.nonce || new Uint8Array(12));
    boff = w_u8(body, boff, proto_number(msg.protocol === undefined ? PROTO.TCP : msg.protocol));
    boff = w_u8(body, boff, 0);
    boff = w_u16(body, boff, 0);                     // reserved
    boff = w_u16(body, boff, msg.internalPort || 0);
    boff = w_u16(body, boff, msg.externalPort || 0);
    boff = w_bytes(body, boff, encode_ip(msg.externalIp || '::'));
    boff = w_u16(body, boff, msg.remotePort || 0);
    boff = w_u16(body, boff, 0);                     // reserved
    w_bytes(body, boff, encode_ip(msg.remoteIp || '::'));
  }

  var options = encode_pcp_options(msg.options);
  var out = new Uint8Array(24 + body.length + options.length);

  var off = 0;
  off = w_u8(out, off, VERSION.PCP);
  off = w_u8(out, off, RESPONSE_BIT | (msg.opcode & 0x7F));
  off = w_u8(out, off, 0);                           // reserved
  off = w_u8(out, off, msg.resultCode || 0);
  off = w_u32(out, off, msg.lifetime >>> 0);
  off = w_u32(out, off, (msg.epoch || 0) >>> 0);
  off += 12;                                         // reserved

  out.set(body, off);
  out.set(options, off + body.length);
  return out;
}


/**
 * Peek at the version byte to route an incoming datagram to the right
 * decoder. Both protocols share port 5351, so this runs on every packet.
 */
function detect_protocol(buf) {
  if (!buf || buf.length < 2) return null;
  if (buf[0] === VERSION.PCP) return 'pcp';
  if (buf[0] === VERSION.NATPMP) return 'natpmp';
  return null;
}


export {
  // Constants
  SERVER_PORT,
  CLIENT_PORT,
  NATPMP_MULTICAST,
  PCP_MULTICAST_V4,
  PCP_MULTICAST_V6,
  MAX_PACKET_SIZE,
  VERSION,
  NATPMP_OP,
  NATPMP_RESULT,
  PCP_OP,
  PCP_RESULT,
  PCP_OPTION,
  PROTO,

  // Naming
  natpmp_result_name,
  pcp_result_name,
  pcp_opcode_name,
  proto_name,
  proto_number,

  // Addresses
  encode_ip,
  decode_ip,
  encode_ip4,
  decode_ip4,
  is_ipv4_mapped,
  is_cgnat_address,
  is_private_address,
  classify_external_address,
  classify_ipv6_address,
  is_ipv6_local,

  // Nonce
  nonce_to_hex,
  nonce_from_hex,
  nonce_equal,

  // NAT-PMP
  encode_natpmp_address_request,
  encode_natpmp_map_request,
  decode_natpmp_response,

  // PCP
  encode_pcp_header,
  encode_pcp_options,
  decode_pcp_options,
  encode_pcp_map_request,
  encode_pcp_peer_request,
  encode_pcp_announce_request,
  pcp_option_prefer_failure,
  pcp_option_third_party,
  pcp_option_filter,
  decode_pcp_response,

  // Server side
  decode_natpmp_request,
  encode_natpmp_address_response,
  encode_natpmp_map_response,
  encode_natpmp_unsupported_version,
  encode_natpmp_unsupported_opcode,
  decode_pcp_request,
  encode_pcp_response,

  // Dispatch
  detect_protocol
};
