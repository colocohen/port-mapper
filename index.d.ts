/**
 * port-mapper — TypeScript definitions.
 *
 * The public surface is callback-style throughout, no promises, no async. It
 * mirrors what the code actually does rather than what a TypeScript
 * conversion might have produced: options are plain objects, results are
 * plain objects, and events are typed by name.
 *
 * Everything a caller needs sits on Mapper, PortMapServer, or the top-level
 * open(). The engine classes and helper modules are exported for the small
 * number of cases where a caller wants a specific protocol only, or the
 * pieces without the transport, and are typed thinly on purpose — they are
 * for people who have read the source.
 */

import { EventEmitter } from 'node:events';


/* ============================ Callbacks ============================ */

/**
 * Node-style callback used throughout. `err` is a real Error subclass when
 * present, not a string; every operation that can fail has one, and every one
 * that can succeed hands back its result as the second argument.
 */
export type Callback<T = void> = (err: Error | null, result?: T) => void;

/**
 * Handle returned by any operation that may still be in flight when the caller
 * changes its mind. Cancelling before the answer arrives short-circuits the
 * retransmission schedule and delivers the callback with an abort error —
 * NAT-PMP alone waits 64 seconds on its last retry, so this is not optional.
 */
export interface CancelHandle {
  /** Returns true if the operation was still in flight and was stopped. */
  cancel(reason?: string): boolean;
}


/* ============================ Errors ============================ */

export class PortMapError extends Error {
  code?: string | number;
  protocol?: 'pcp' | 'natpmp' | 'upnp';
}

/** A caller-supplied value did not meet the shape a call required. */
export class PortMapValidationError extends PortMapError {
  field?: string;
}

/** Something on the network refused, timed out, or would not connect. */
export class PortMapNetworkError extends PortMapError {}

/**
 * The protocol answered with an error. `code` is the code the gateway
 * returned — 606 or 718 for UPnP, an RFC 6887 result code for PCP, an
 * RFC 6886 result code for NAT-PMP.
 */
export class PortMapProtocolError extends PortMapError {
  code?: number;
}

/**
 * No answer within the deadline. Distinct from a network error on purpose:
 * a gateway that never answers is a different situation from one that
 * refused, and a caller deciding whether to retry needs to tell them apart.
 */
export class PortMapTimeoutError extends PortMapError {
  timeout?: number;
}

/** A method was called at the wrong point in the lifecycle. */
export class PortMapStateError extends PortMapError {
  state?: string;
}

/** No gateway on this network answered any of the three protocols. */
export class NoGatewayError extends PortMapError {}

/**
 * The gateway holds a CGNAT address (100.64.0.0/10). Mappings there are
 * impossible in principle: the ISP is translating, so a client cannot reach
 * this address from outside no matter what the router agrees to.
 */
export class CGNATError extends PortMapError {
  address?: string;
}


/* ============================ Shared types ============================ */

export type Protocol = 'tcp' | 'udp';
export type Family = 'ipv4' | 'ipv6';
export type Via = 'pcp' | 'natpmp' | 'upnp' | 'upnp-pinhole';

export interface Mapping {
  protocol: Protocol;
  internalIp: string;
  internalPort: number;
  externalIp: string | null;
  externalPort: number;
  lifetime: number;
  expiresAt?: Date;
  description?: string;
  via: Via;
  state: 'ACTIVE' | 'RENEWING' | 'LOST';
  nonceHex?: string;
  key?: string;
}

export interface Pinhole {
  uniqueId: number;
  protocol: Protocol;
  internalIp: string;
  internalPort: number;
  remoteHost?: string;
  remotePort?: number;
  leaseTime: number;
  expiresAt?: Date;
}


/* ============================ open() ============================ */

/**
 * Options for the one-line entry point. The two flags follow the shape
 * mdns-local uses — turning IPv6 off is `ipv6: false`, not a family string —
 * because a developer opening a port wants it open, not a decision about IP
 * versions. Both are on by default: a failure in one family is not a failure
 * of the call, since carrier-grade NAT increasingly ruins IPv4 while walking
 * straight past IPv6, and IGD:2 pinholes are missing from most consumer
 * hardware in the opposite direction.
 */
export interface OpenOptions {
  ipv4?: boolean;
  ipv6?: boolean;
  protocol?: Protocol;
  externalPort?: number;
  exact?: boolean;
  onConflict?: 'increment' | 'any' | 'fail';
  lifetime?: number;
  description?: string;
  remoteHost?: string;
  remotePort?: number;

  /** Passed through to createMapper for full control. */
  gateway?: string;
  protocols?: Array<'pcp' | 'natpmp' | 'upnp'>;
  negotiateTimeout?: number;
  announcements?: boolean;
  cleanupOnExit?: boolean;
}

/**
 * A successful mapping. `address` is the one line most callers should read:
 * it is IPv4 when IPv4 worked, IPv6 when only that did, and formatted the way
 * a URL expects — `81.2.3.4:49152` or `[2001:db8::1]:8080`. Without it, code
 * that reads externalIp directly prints "null:null" on a host where only IPv6
 * worked, through no fault of its own.
 */
export interface OpenResult extends Mapping {
  address: string;
  addresses: string[];
  families: Family[];
  ipv4: Mapping | null;
  ipv6: Mapping | null;
  failures: Array<{ family: Family; error: Error }>;
  mapper: Mapper;
  mappers: { ipv4: Mapper | null; ipv6: Mapper | null };

  close(cb?: Callback): void;
  diagnose(cb: Callback<CombinedDiagnosis>): void;
}

export interface CombinedDiagnosis {
  reachable: boolean;
  reason: string | null;
  detail: string | null;
  suggestion: string | null;
  ipv4: DiagnosisReport | null;
  ipv6: DiagnosisReport | null;
}

/**
 * Map a port on both families at once.
 *
 * `err` is only present when both families failed. One succeeding is a
 * success, and the other appears in `failures` — the common case of a
 * consumer gateway without pinholes is not an error, it is a fact.
 */
export function open(port: number, cb: Callback<OpenResult>): CancelHandle;
export function open(port: number, options: OpenOptions, cb: Callback<OpenResult>): CancelHandle;


/* ============================ createMapper ============================ */

export interface MapperOptions {
  /** Which address family this Mapper handles. One Mapper handles one. */
  family?: Family;

  /** Router address, or 'auto' to detect. */
  gateway?: string | 'auto';

  /** Local address or interface name to use, or 'auto' to pick the best. */
  interface?: string | 'auto';

  /**
   * Which protocols to try. Ordered by preference here rather than in the
   * negotiation itself: all three run concurrently and the first to answer
   * wins, and this only limits the field.
   */
  protocols?: Array<'pcp' | 'natpmp' | 'upnp'>;

  lifetime?: number;
  description?: string;

  /**
   * How long to wait for any of the three protocols to answer before giving
   * up. Longer than a single retransmission schedule, because it covers all
   * of them running side by side.
   */
  negotiateTimeout?: number;

  /** NAT-PMP/PCP retries (RFC 6886 §3.1). Nine is a full RFC schedule. */
  retransmitAttempts?: number;

  /** SSDP search window. */
  searchTimeout?: number;

  /** MX header value; the window widens to cover it. */
  searchMx?: number;

  /** Send M-SEARCH to one address instead of the multicast group. */
  searchUnicast?: string;

  /**
   * Accept an IGD that is not the default gateway. Off by default because
   * an off-path device answering SSDP is either misconfigured or malicious.
   */
  allowOffPath?: boolean;

  /** Listen for gateway announcements. */
  announcements?: boolean;

  /**
   * Warn when nothing is listening on the internal port. Advisory only, since
   * a service bound to one specific address can be invisible to the check.
   */
  checkLocalPort?: boolean;

  /** Remove mappings on exit and on SIGINT/SIGTERM. Catches Ctrl+C but not a crash. */
  cleanupOnExit?: boolean;

  /** Periodic verification against the gateway. Off by default. */
  watchdog?: boolean | WatchdogOptions;

  /**
   * STUN provider used by diagnose(). Defaults to turn-server when installed,
   * `false` to disable, or a function that reports the public address.
   */
  stun?: false | ((cb: Callback<{ address: string; port?: number }>) => void);

  /** Per-request timeout for SOAP. */
  httpTimeout?: number;

  /** Local address to bind sockets to. */
  bindAddress?: string;

  /**
   * Override the HTTP client used by the UPnP engine. Provided for testing;
   * a real caller has no reason to touch this.
   */
  http?: HttpClient;
}

export interface WatchdogOptions {
  /** Milliseconds between checks. Default 300000 (five minutes). */
  interval?: number;
  /** Recreate a mapping that has vanished, rather than only reporting it. */
  restore?: boolean;
}

export interface StartInfo {
  family: Family;
  gateway: string;
  interface: string;
  localIp: string;
  protocol: 'pcp' | 'natpmp' | 'upnp';
  externalIp: string | null;
  addressKind?: string;
  device?: DeviceInfo;
  results?: NegotiationResults;
}

export interface DeviceInfo {
  friendlyName?: string;
  manufacturer?: string;
  modelName?: string;
  modelNumber?: string;
  serialNumber?: string;
  udn?: string;
  igdVersion?: 1 | 2;
  supportsPinholes?: boolean;
  quirks?: string[];
}

export interface NegotiationResults {
  pcp?: NegotiationResult;
  natpmp?: NegotiationResult;
  upnp?: NegotiationResult;
}

export interface NegotiationResult {
  available: boolean;
  reason?: string;
  externalIp?: string;
  device?: DeviceInfo;
}

/** Options for a single map() call. */
export interface MapOptions {
  internalPort: number;
  externalPort?: number;
  protocol?: Protocol;
  lifetime?: number;
  description?: string;

  /** This port or nothing. See PREFER_FAILURE in RFC 6887 §13.2. */
  exact?: boolean;

  /**
   * What to do when the requested port is taken:
   *   'increment' — try 81, 82, 83, then ask the gateway to choose (default)
   *   'any'       — ask the gateway to choose from the start
   *   'fail'      — equivalent to exact: true
   */
  onConflict?: 'increment' | 'any' | 'fail';

  remoteHost?: string;
  remotePort?: number;
}

export interface UnmapOptions {
  internalPort: number;
  protocol?: Protocol;
}

/**
 * Advice returned by diagnose() when a mapping is not reachable.
 *
 *   OK             The gateway holds a globally routable address
 *   CGNAT          100.64.0.0/10 — the ISP is translating too
 *   DOUBLE_NAT     The gateway's own external address is RFC 1918
 *   UPSTREAM_NAT   Public address on the gateway, but STUN sees a different one
 *   NO_GATEWAY     Nothing on the network answered any of the three protocols
 *   UNKNOWN        The gateway refused to report its external address
 *   NOT_CONNECTED  The router has no upstream link yet
 */
export type DiagnosisReason =
  | 'OK'
  | 'CGNAT'
  | 'DOUBLE_NAT'
  | 'UPSTREAM_NAT'
  | 'NO_GATEWAY'
  | 'UNKNOWN'
  | 'LOOPBACK'
  | 'LINKLOCAL'
  | 'UNSPECIFIED';

export interface DiagnosisReport {
  reachable: boolean;
  reason: DiagnosisReason;
  detail: string;
  suggestion: string | null;

  /** 'inferred' from address classification, 'verified' against STUN. */
  method: 'inferred' | 'verified';

  gateway: string;
  localIp: string;
  externalIp: string | null;
  publicAddress?: string | null;
  natType?: string | null;
  natDetail?: NATDetail | null;

  protocol: 'pcp' | 'natpmp' | 'upnp' | null;
  device?: DeviceInfo | null;
  protocols?: NegotiationResults | null;
  behindNat: boolean;

  /** A ready-made error for CGNAT. Not attached for DOUBLE_NAT on purpose. */
  error?: CGNATError;
}

export interface NATDetail {
  type: string;
  filteringBehavior?: string;
  mappingBehavior?: string;
  hairpinning?: boolean;
}

export interface VerifyReport {
  checked: number;
  present: Mapping[];
  vanished: Mapping[];
  stolen: Mapping[];
  unknown: Mapping[];
}

export interface ImportReport {
  adopted: Mapping[];
  expired: Mapping[];
  vanished: Mapping[];
  stolen: Mapping[];
  foreign: Mapping[];
}

export interface ExportedState {
  version: 1;
  savedAt: string;
  gateway: string;
  localIp: string;
  protocol: 'pcp' | 'natpmp' | 'upnp' | null;
  externalIp: string | null;
  mappings: Array<Partial<Mapping> & { protocol: Protocol; internalPort: number }>;
}

export interface Candidate {
  uuid: string;
  location: string;
  address: string;
  server: string;
  st: string;
  onPath: boolean;
  chosen?: boolean;
  bootId?: number | null;
  searchPort?: number | null;
  nextBootId?: number;
}

export interface QuirkInfo {
  id: string;
  note: string;
  source: string;
  effects?: QuirkEffects;
}

export interface QuirkEffects {
  renewByRecreate?: boolean;
  conflictMayMeanRefusal?: boolean;
  failsBehindDoubleNat?: boolean;
  minimumLease?: number;
  maximumLease?: number;
  reclaimsIdleMappings?: boolean;
  noPcp?: boolean;
  noNatPmp?: boolean;
  doubleNatByDefault?: boolean;
  refusesPrivilegedPorts?: boolean;
  unicastSearchUnreliable?: boolean;
  [key: string]: boolean | number | undefined;
}

export interface Subscription {
  sid: string;
  timeout: number;
  service: string;
  eventSubUrl: string;
  lastSeq?: number;
}

export interface HttpRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: Uint8Array | string;
}

export interface HttpResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: Uint8Array | string;
}

export type HttpClient = (req: HttpRequest, cb: Callback<HttpResponse>) => void;


/** Every event the Mapper emits, typed by name. */
export interface MapperEvents {
  ready:                  (info: StartInfo) => void;
  mapped:                 (mapping: Mapping) => void;
  renewed:                (mapping: Mapping) => void;
  lost:                   (mapping: Mapping, reason: string) => void;
  remapped:               (mapping: Mapping, oldExternalPort: number) => void;
  unmapped:               (mapping: Mapping) => void;
  conflict:               (info: { externalPort: number; attempt: number }) => void;
  'empty-port':           (info: { protocol: Protocol; internalPort: number }) => void;
  'gateway-reboot':       (info: { previousEpoch: number; newEpoch: number }) => void;
  'gateway-restarted':    (info: { uuid: string; from: number; to: number }) => void;
  'gateway-updated':      (info: { uuid: string; bootId: number; nextBootId?: number }) => void;
  'gateway-gone':         (info: { uuid: string }) => void;
  'external-ip-changed':  (change: { from: string; to: string }) => void;
  degraded:               (info: { from: string; to: string; reason: string }) => void;
  device:                 (info: DeviceInfo) => void;
  quirks:                 (list: QuirkInfo[]) => void;
  'service-described':    (info: { type: string; actions: number }) => void;
  subscribed:             (sub: Subscription) => void;
  unsubscribed:           (sub: Subscription) => void;
  event:                  (info: { sid: string; properties: Record<string, string> }) => void;
  'events-missed':        (info: { sid: string; expected: number; received: number; note: string }) => void;
  pinhole:                (pinhole: Pinhole) => void;
  'pinhole-closed':       (pinhole: Pinhole) => void;
  'stale-removed':        (mapping: Mapping) => void;
  adopted:                (mapping: Mapping) => void;
  verified:               (report: VerifyReport) => void;
  'mapping-vanished':     (mapping: Mapping, reason?: string) => void;
  'mapping-stolen':       (mapping: Mapping, reason?: string) => void;
  warning:                (message: string) => void;
}


/* ============================ Mapper class ============================ */

/**
 * The client. One Mapper handles one address family — createMapper twice for
 * both — and speaks whichever of PCP, NAT-PMP or UPnP the gateway does.
 *
 * The high-level entry point `open()` composes two of these and hides the
 * split. This class is what a caller reaches when they want more.
 */
export declare class Mapper {
  constructor(options?: MapperOptions);

  /* --- lifecycle --- */

  start(cb?: Callback<StartInfo>): CancelHandle;
  stop(cb?: Callback): void;
  close(cb?: Callback): void;
  destroy(): void;

  /* --- mapping --- */

  map(options: MapOptions, cb?: Callback<Mapping>): CancelHandle;
  unmap(options: UnmapOptions, cb?: Callback): void;
  cancelAll(reason?: string): number;

  /* --- IPv6 pinholes --- */

  addPinhole(options: {
    internalPort: number;
    protocol?: Protocol;
    internalIp?: string;
    remoteHost?: string;
    remotePort?: number;
    lifetime?: number;
  }, cb?: Callback<Pinhole>): void;
  updatePinhole(uniqueId: number, leaseTime: number, cb?: Callback<Pinhole>): void;
  deletePinhole(uniqueId: number, cb?: Callback): void;
  checkPinholeWorking(uniqueId: number, cb?: Callback<{ isWorking: boolean }>): void;
  getFirewallStatus(cb?: Callback<{ firewallEnabled: boolean; inboundPinholeAllowed: boolean }>): void;
  getPinholes(): Pinhole[];
  getOutboundPinholeTimeout(protocol: Protocol, cb?: Callback<{ timeout: number }>): void;

  /* --- inspecting --- */

  getMappings(): Mapping[];
  getRouterMappings(cb: Callback<Mapping[]>): void;
  getExternalIp(cb: Callback<{ externalIp: string | null }>): void;
  getProtocol(): 'pcp' | 'natpmp' | 'upnp' | null;
  getConfig(): {
    family: Family;
    gateway: string;
    interface: string;
    localIp: string;
    description: string;
    lifetime: number;
    protocols: string[];
  };
  getStats(): Record<string, number>;
  getInterfaces(): InterfaceCandidate[];
  getCandidates(): Candidate[];
  getQuirks(): QuirkInfo[];
  getQuirkEffects(): QuirkEffects;
  getSubscriptions(): Subscription[];

  /* --- gateway information (UPnP only) --- */

  getStatus(cb: Callback<{ connectionStatus: string; uptime: number; lastError: string }>): void;
  getConnectionType(cb: Callback<{ type: string; routed: boolean }>): void;
  getLinkProperties(cb: Callback<{ accessType: string; maxBitRateUp: number; maxBitRateDown: number; linkUp: boolean }>): void;
  getTrafficCounters(cb: Callback<{ bytesSent: number; bytesReceived: number; packetsSent: number; packetsReceived: number }>): void;
  getMappingCount(cb: Callback<{ count: number }>): void;

  /* --- service description (UPnP only) --- */

  loadServiceDescription(service: any, cb: Callback<{ actions: Record<string, unknown>; variables: Record<string, unknown> }>): void;
  supportsAction(action: string, cb: Callback<boolean | null>): void;

  /**
   * Escape hatch: call any SOAP action on the connection service. IGD is an
   * extensible service and vendors add actions to it, so a library that only
   * exposed what it knew about would force a fork for anything it had not
   * anticipated.
   */
  call(action: string, args: Record<string, unknown>, cb: Callback<Record<string, string>>): void;

  /* --- bulk table operations (IGD:2 only) --- */

  getListOfPortMappings(options: {
    startPort?: number;
    endPort?: number;
    protocol?: Protocol;
    manage?: boolean;
    number?: number;
  }, cb: Callback<Mapping[]>): void;

  deletePortMappingRange(options: {
    startPort: number;
    endPort: number;
    protocol: Protocol;
    manage?: boolean;
  }, cb?: Callback): void;

  /* --- eventing --- */

  subscribe(options?: { timeout?: number; port?: number }, cb?: Callback<Subscription>): void;
  subscribe(cb: Callback<Subscription>): void;
  unsubscribe(sid: string, cb?: Callback): void;
  renewSubscription(sid: string, options: { timeout?: number }, cb?: Callback<Subscription>): void;

  /* --- persistence and verification --- */

  exportMappings(): ExportedState;
  importMappings(saved: ExportedState, cb?: Callback<ImportReport>): void;
  verifyMappings(cb?: Callback<VerifyReport>): void;
  startWatchdog(options?: WatchdogOptions): { stop(): void };
  stopWatchdog(): void;

  /* --- diagnosis --- */

  diagnose(cb: Callback<DiagnosisReport>): void;
  diagnostics(cb: Callback<{ available: boolean; getPublicIP: boolean; detectNAT: boolean; reason: string | null }>): void;
  cleanup(options: { dryRun?: boolean }, cb?: Callback<{ found: Mapping[]; removed: Mapping[] }>): void;
  cleanup(cb: Callback<{ found: Mapping[]; removed: Mapping[] }>): void;

  /* --- events --- */

  on<K extends keyof MapperEvents>(event: K, listener: MapperEvents[K]): this;
  once<K extends keyof MapperEvents>(event: K, listener: MapperEvents[K]): this;
  off<K extends keyof MapperEvents>(event: K, listener: MapperEvents[K]): this;
}

export function createMapper(options?: MapperOptions): Mapper;


/* ============================ Interfaces ============================ */

/**
 * A local address, ranked. Docker bridges, VPN tunnels and hypervisor
 * interfaces are recognised by name and demoted; the one sharing a subnet
 * with the default gateway wins.
 */
export interface InterfaceCandidate {
  name: string;
  address: string;
  netmask: string;
  family: Family;
  mac: string;
  prefix: number | null;
  virtual: boolean;
  onDefaultRoute: boolean;
  score: number;
  reason: string[];
}


/* ============================ Gateway ============================ */

export type EnforceAdapter = {
  name: string;
  capabilities: {
    preservesSourceIp: boolean;
    handlesHairpin: boolean;
    persistsAcrossExit: boolean;
    supportsUdp: boolean;
    requiresRoot?: boolean;
    platforms?: string[];
    throughput?: 'wire' | 'medium' | 'none';
  };
  check(cb: Callback<{ ok: boolean; reason?: string }>): void;
  init(config: any, cb: Callback): void;
  add(mapping: Mapping, cb?: Callback): void;
  remove(mapping: Mapping, cb?: Callback): void;
  list(cb: Callback<Mapping[]>): void;
  destroy(cb?: Callback): void;
};

export interface ServerOptions {
  externalIp?: string;
  policy?: 'deny-all' | 'allow-all';
  enforce?: EnforceAdapter | EnforceAdapter[];
  require?: Partial<EnforceAdapter['capabilities']>;

  protocols?: Array<'pcp' | 'natpmp' | 'upnp'>;
  family?: Family;
  igdVersion?: 1 | 2;

  /** Advertised as the device UDN. Derived from the MAC by default and stable. */
  udn?: string;
  friendlyName?: string;
  manufacturer?: string;
  modelName?: string;
  modelNumber?: string;

  /**
   * Let a host map on behalf of another. Off by default because IGD:1 gives
   * clients the field to do it, and that is how one host on a LAN exposes
   * another — a neighbour's camera, a NAS, the admin page of the router
   * itself. NAT-PMP has no such field at all (RFC 6886 §3.3).
   */
  allowThirdPartyMappings?: boolean;

  maxLifetime?: number;
  maxMappings?: number;
  maxPerClient?: number;

  /** How long to wait for an async request handler before proceeding. */
  controlTimeout?: number;

  httpPort?: number;
  wanInterface?: string;
  lanInterface?: string;

  connectionType?: string;
  wanAccessType?: string;
  upstreamBitRate?: number;
  downstreamBitRate?: number;

  searchPort?: number;
  bootId?: number;
  configId?: number;

  /**
   * The URL of the device description advertised to a client. A string is
   * used as-is; a function receives the client's address and returns a URL,
   * for a gateway with more than one LAN interface — a control point cannot
   * reach a LOCATION on a network it is not attached to.
   */
  location?: string | ((clientAddress: string) => string);
}

export interface PortRequest {
  via: 'pcp' | 'natpmp' | 'upnp';
  protocol: Protocol;
  internalIp: string;
  internalPort: number;
  externalPort: number;
  leaseDuration: number;
  description?: string;
  remote: { address: string; port: number };
  nonce?: Uint8Array;
}

/**
 * Handed to every port-request handler. A gateway does not care whether a
 * request arrived as PCP or as a SOAP envelope; the decision is the same, and
 * one handler covers every protocol.
 */
export interface Control {
  /**
   * The external port the engine intends to assign. Assign to change it —
   * a handler that only wants to approve does not have to restate it.
   */
  externalPort: number;
  maxTtl: number;

  allow(): void;
  /**
   * Refuse the request. A number sends a specific protocol code back —
   * 606 for a refusal, 718 for a conflict.
   */
  reject(code?: number): void;
  /**
   * Answer nothing at all. Distinct from rejecting: a client that is refused
   * knows where it stands, while one that is ignored retransmits and gives
   * up, which is what a gateway wants for traffic it does not want to admit
   * hearing.
   */
  ignore(): void;
}

export interface ServerEvents {
  listening:            (info: { udn: string; location: string; httpPort: number }) => void;
  'port-request':       (request: PortRequest, control: Control, done?: () => void) => void;
  'port-mapped':        (mapping: Mapping) => void;
  'port-renewed':       (mapping: Mapping) => void;
  'port-unmapped':      (mapping: Mapping) => void;
  'port-expired':       (mapping: Mapping) => void;
  'port-rejected':      (info: { request: PortRequest; code: number | null }) => void;
  'third-party-blocked':(request: PortRequest) => void;
  'quota-exceeded':     (info: { scope: 'per-client' | 'per-gateway'; client?: string }) => void;
  'enforce-selected':   (info: { chosen: string; rejected: Array<{ name: string; reason: string }> }) => void;
  'enforce-failed':     (info: { mapping: Mapping; error: Error }) => void;
  reconciled:           (info: { pruned: number }) => void;
  'address-mismatch':   (info: { reported: string; observed: string }) => void;
  discovered:           (info: { from: string; st: string }) => void;
  subscribed:           (info: { sid: string; callback: string; from: string }) => void;
  unsubscribed:         (info: { sid: string }) => void;
  updated:              (info: { bootId: number; configId: number }) => void;
  notify:               (messages: Array<{ url: string; headers: Record<string, string>; body: string }>) => void;
  'epoch-reset':        (info: { epoch: number }) => void;
  'external-ip':        (ip: string) => void;
  warning:              (message: string) => void;
}

/**
 * The gateway. Answers PCP and NAT-PMP on UDP 5351, SSDP on 1900, and serves
 * SOAP over HTTP. Nothing is granted and nothing is enforced by default —
 * both are explicit opt-ins, because a gateway that grants what it was not
 * asked to grant is the failure mode this whole layer exists to prevent.
 */
export declare class PortMapServer {
  constructor(options?: ServerOptions);

  listen(cb?: Callback<{ udn: string; location: string; httpPort: number }>): void;
  close(cb?: Callback): void;
  destroy(): void;

  getConfig(): {
    udn: string;
    externalIp: string;
    location: string;
    igdVersion: 1 | 2;
    policy: string;
  };
  getMappings(): Mapping[];
  getStats(): Record<string, number>;
  getEnforcer(): EnforceAdapter | null;

  revoke(protocol: Protocol, externalPort: number): boolean;
  setExternalIp(ip: string): void;
  resetEpoch(): void;
  reconcile(cb?: Callback<{ pruned: number }>): void;

  on<K extends keyof ServerEvents>(event: K, listener: ServerEvents[K]): this;
  once<K extends keyof ServerEvents>(event: K, listener: ServerEvents[K]): this;
  off<K extends keyof ServerEvents>(event: K, listener: ServerEvents[K]): this;
}

export function createServer(options?: ServerOptions): PortMapServer;


/* ============================ Enforcement ============================ */

export namespace enforce {
  interface AdapterOptions {
    wanInterface?: string;
    lanInterface?: string;
    table?: string;
    chain?: string;
    dryRun?: boolean;
    exec?: (command: string, args: string[], options: any, cb: Callback<{ stdout: string; stderr: string }>) => void;
  }

  interface RelayOptions extends AdapterOptions {
    /**
     * Prepend a PROXY-protocol line to each TCP connection, so the internal
     * service sees the real client address. Understood by nginx, HAProxy and
     * others — but the inner service must be configured to expect it, or it
     * will read the header as garbage.
     */
    proxyProtocol?: boolean;
  }

  function nftables(options?: AdapterOptions): EnforceAdapter;
  function iptables(options?: AdapterOptions): EnforceAdapter;
  function pf(options?: AdapterOptions): EnforceAdapter;
  function relay(options?: RelayOptions): EnforceAdapter;
  function noop(): EnforceAdapter;

  /**
   * Return the first adapter that will run on this host. Ordered by
   * capability: source-preserving kernel adapters before the userspace relay.
   */
  function all(): EnforceAdapter[];

  function select(
    adapters: EnforceAdapter[],
    require?: Partial<EnforceAdapter['capabilities']>,
    cb?: Callback<{ chosen: EnforceAdapter | null; rejected: Array<{ name: string; reason: string }> }>
  ): void;

  function capabilities_of(adapter: EnforceAdapter): EnforceAdapter['capabilities'];
  function satisfies(adapter: EnforceAdapter, require: Partial<EnforceAdapter['capabilities']>): boolean;
  function warnings_for(adapter: EnforceAdapter): string[];

  function conformance(
    adapter: EnforceAdapter,
    options: { name?: string; skip?: string[] },
    cb: Callback<{ passed: number; total: number; results: Array<{ name: string; passed: boolean; reason?: string }> }>
  ): void;

  const CAPABILITY_DEFAULTS: EnforceAdapter['capabilities'];
  const PREFERENCE: string[];
}


/* ============================ Testing ============================ */

export interface TestPairOptions {
  server?: Partial<ServerOptions>;
  client?: Partial<MapperOptions>;
  latency?: number;
  /**
   * Called for every packet in either direction. Return `false` to drop it —
   * a return of anything else lets it through. Used for loss and reordering
   * scenarios that a real network cannot be made to produce reliably.
   */
  intercept?: (direction: 'client->server' | 'server->client', buf: Uint8Array) => boolean | void;
}

export interface TestPair {
  server: PMPServerSession;
  client: PMPSession;
  gateway: string;
  location: string;
  addClient(options?: Partial<MapperOptions>): PMPSession;
  destroy(): void;
}

export interface UPnPTestPair {
  server: UPnPServerSession;
  client: UPnPSession;
  gateway: string;
  location: string;
  addClient(options?: Partial<MapperOptions>): UPnPSession;
  destroy(): void;
}

/**
 * A PCP + NAT-PMP client engine joined to a matching gateway engine, in
 * memory. Real code, no sockets, no root, no router — the same object graph
 * that runs against a live gateway.
 */
export function createTestPair(options?: TestPairOptions): TestPair;

/** The UPnP counterpart, with SSDP and SOAP going through the same shim. */
export function createUPnPTestPair(options?: TestPairOptions): UPnPTestPair;


/* ============================ Session engines ============================ */

/**
 * The engine classes are exported for the small number of cases where a
 * caller wants a specific protocol without the transport wrapper. They are
 * typed thinly on purpose — a caller that needs one has already read the
 * source of that file, and a thick typing would go stale faster than it would
 * help.
 */
export declare class PMPSession extends EventEmitter {
  constructor(options: any);
  discover(cb: Callback): void;
  probe(cb: Callback): void;
  map(options: MapOptions, cb: Callback<Mapping>): CancelHandle;
  unmap(options: UnmapOptions, cb?: Callback): void;
  verify(options: any, cb: Callback): void;
  process_packet(buf: Uint8Array, rinfo: { address: string; port: number }): void;
  getMappings(): Mapping[];
  getConfig(): any;
  getStats(): Record<string, number>;
  destroy(): void;
}

export declare class UPnPSession extends EventEmitter {
  constructor(options: any);
  discover(cb: Callback): void;
  map(options: MapOptions, cb: Callback<Mapping>): CancelHandle;
  unmap(options: UnmapOptions, cb?: Callback): void;
  verify(options: any, cb: Callback): void;
  addPinhole(options: any, cb: Callback<Pinhole>): void;
  updatePinhole(uniqueId: number, leaseTime: number, cb?: Callback<Pinhole>): void;
  deletePinhole(uniqueId: number, cb?: Callback): void;
  loadServiceDescription(service: any, cb: Callback): void;
  supportsAction(action: string, cb: Callback<boolean | null>): void;
  subscribe(options: any, cb: Callback<Subscription>): void;
  unsubscribe(sid: string, cb?: Callback): void;
  handle_notify(headers: Record<string, string>, body: Uint8Array | string): void;
  process_packet(buf: Uint8Array, rinfo: { address: string; port: number }): void;
  call(action: string, args: Record<string, unknown>, cb: Callback<Record<string, string>>): void;
  getMappings(): Mapping[];
  getPinholes(): Pinhole[];
  getCandidates(): Candidate[];
  getSubscriptions(): Subscription[];
  getStats(): Record<string, number>;
  destroy(): void;
}

export declare class PMPServerSession extends EventEmitter {
  constructor(options: any);
  listening(): void;
  process_packet(buf: Uint8Array, rinfo: { address: string; port: number }): void;
  getMappings(): Mapping[];
  getConfig(): any;
  getStats(): Record<string, number>;
  setExternalIp(ip: string): void;
  resetEpoch(): void;
  revoke(protocol: Protocol, externalPort: number): boolean;
  destroy(): void;
}

export declare class UPnPServerSession extends EventEmitter {
  constructor(options: any);
  listening(): void;
  handle_http(req: any, cb: Callback<HttpResponse>): void;
  process_packet(buf: Uint8Array, rinfo: { address: string; port: number }): void;
  advertise(nts?: 'ssdp:alive' | 'ssdp:byebye' | 'ssdp:update'): void;
  update(options?: { bootId?: number; configChanged?: boolean }): { bootId: number; configId: number };
  notify(properties: Record<string, string>): any[];
  setExternalIp(ip: string): void;
  revoke(protocol: Protocol, externalPort: number): boolean;
  getMappings(): Mapping[];
  getPinholes(): Pinhole[];
  getSubscribers(): Array<{ sid: string; callback: string; seq: number; expiresAt: number }>;
  getConfig(): any;
  getStats(): Record<string, number>;
  destroy(): void;
}


/* ============================ Helper modules ============================ */

/**
 * The router quirks database — known misbehaviours, matched on the SERVER
 * header or the device description. Data, not code, so a user report is one
 * new row rather than a special case buried somewhere.
 */
export namespace quirks {
  const QUIRKS: QuirkInfo[];

  function match(
    device: { server?: string; manufacturer?: string; modelName?: string; friendlyName?: string },
    options?: { includeInformational?: boolean }
  ): QuirkInfo[];

  function effects_of(quirks: QuirkInfo[]): QuirkEffects;
  function clamp_lease(lifetime: number, effects: QuirkEffects | null): number;
  function all(): QuirkInfo[];
}

export namespace interfaces {
  const VIRTUAL_PATTERNS: RegExp[];

  function candidates(options?: {
    family?: Family;
    gateway?: string;
  }): InterfaceCandidate[];

  function select(options?: {
    family?: Family;
    gateway?: string;
    preferred?: string;
  }): InterfaceCandidate | null;

  function is_virtual(name: string): boolean;
  function same_subnet(a: string, b: string, netmask: string): boolean;
  function mask_to_prefix(netmask: string): number | null;

  function port_in_use(
    options: { port: number; protocol?: Protocol; address?: string },
    cb: Callback<{ inUse: boolean | null; reason?: string }>
  ): void;
}

export namespace reachability {
  function verify(
    gatewayExternalIp: string | null,
    options: { stun?: false | ((cb: Callback<any>) => void); stunServer?: string },
    cb: Callback<{
      method: 'inferred' | 'verified';
      publicAddress: string | null;
      agrees: boolean | null;
      natType: string | null;
      natDetail?: NATDetail | null;
      advice: string | null;
    }>
  ): void;

  function public_address(
    options: { stun?: false | ((cb: Callback<any>) => void); stunServer?: string },
    cb: Callback<{ address: string; port: number | null; source: string } | null>
  ): void;

  function nat_type(
    options: { stun?: false; stunServer?: string },
    cb: Callback<NATDetail | null>
  ): void;

  function traversal_advice(nat: NATDetail | null): string;

  function available(cb: Callback<{
    available: boolean;
    getPublicIP: boolean;
    detectNAT: boolean;
    reason: string | null;
  }>): void;
}


/* ============================ Low-level modules ============================ */

/**
 * Wire-level modules. Exported so a caller can build something the transport
 * layer does not: a probe that never keeps state, a custom transport, a
 * fuzzing harness. Typed as `any` because a caller reaching into them has
 * already read the file — and a thick typing here would drift the moment the
 * source changes, since these modules move faster than the public API.
 */
export const wire: any;
export const ssdp: any;
export const soap: any;
export const lifecycle: any;
export const negotiate: any;
export const errors: any;

declare const _default: {
  open: typeof open;
  createMapper: typeof createMapper;
  createServer: typeof createServer;
  createTestPair: typeof createTestPair;
  createUPnPTestPair: typeof createUPnPTestPair;
  enforce: typeof enforce;
  quirks: typeof quirks;
  interfaces: typeof interfaces;
  reachability: typeof reachability;
  wire: typeof wire;
  ssdp: typeof ssdp;
  soap: typeof soap;
  Mapper: typeof Mapper;
  PortMapServer: typeof PortMapServer;
  PortMapError: typeof PortMapError;
  PortMapValidationError: typeof PortMapValidationError;
  PortMapNetworkError: typeof PortMapNetworkError;
  PortMapProtocolError: typeof PortMapProtocolError;
  PortMapTimeoutError: typeof PortMapTimeoutError;
  PortMapStateError: typeof PortMapStateError;
  NoGatewayError: typeof NoGatewayError;
  CGNATError: typeof CGNATError;
};

export default _default;
