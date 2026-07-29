<p align="center">
  <img src="https://github.com/colocohen/port-mapper/raw/main/port-mapper.svg" width="450" alt="port-mapper"/>
</p>

<h1 align="center">port-mapper</h1>
<p align="center">
  <em>Complete UPnP-IGD, NAT-PMP and PCP stack for Node.js — client and gateway</em>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/port-mapper">
    <img src="https://img.shields.io/npm/v/port-mapper?color=blue" alt="npm">
  </a>
  <img src="https://img.shields.io/github/license/colocohen/port-mapper?color=brightgreen" alt="license">
</p>

---

> **⚠️ Project status: Active development.**
> APIs may change before v1.0. Use at your own risk and please report issues!

---

## Table of Contents

1. [What is port mapping?](#-what-is-port-mapping)
2. [Why port-mapper?](#-why-port-mapper)
3. [Quick Start](#-quick-start)
4. [Features](#-features)
5. [Client API](#-client-api)
6. [Diagnostics](#-diagnostics)
7. [Gateway API](#-gateway-api)
8. [Enforcement adapters](#-enforcement-adapters)
9. [Testing](#-testing)
10. [Use cases](#-use-cases)
11. [Comparison](#-comparison)
12. [Router quirks](#-router-quirks)
13. [Troubleshooting](#-troubleshooting)
14. [Project structure](#-project-structure)
15. [Roadmap](#-roadmap)
16. [License](#-license)


## ⚡ What is port mapping?

Almost every device on the internet sits behind a NAT. Outbound connections
work fine; inbound ones have nowhere to go, because the router has no idea
which machine on the inside a packet arriving from outside is meant for.

Port mapping is how a program tells the router: *when something arrives on this
external port, send it to me.* Three protocols do this, and a gateway may speak
any combination of them:

- **UPnP-IGD** — the oldest and by far the most widely implemented. Discovery
  over SSDP multicast, control over HTTP and SOAP. Verbose, and inconsistently
  implemented, but almost everything supports it.
- **NAT-PMP** — Apple's answer: a fixed 12-byte binary request on UDP 5351.
  Simple enough to implement in an afternoon, IPv4 only.
- **PCP** — the IETF successor to NAT-PMP (RFC 6887). Same port, wider
  protocol: IPv6, longer lifetimes, third-party mappings, and a nonce that
  proves a mapping belongs to you.

Every BitTorrent client, game server, video call and self-hosted service
depends on one of these working. When they do not, the usual symptom is a
program that reports success and is then unreachable — because the router did
exactly what it was asked, and something else in the path is the problem.

**port-mapper** implements all three, on both sides of the conversation.


## 🧠 Why port-mapper?

The existing Node options are thin wrappers. `nat-upnp` and its forks speak
UPnP only. `nat-api` and `@achingbrain/nat-port-mapper` add NAT-PMP. None of
them implement PCP, none of them use the epoch field to notice a gateway
reboot, none of them fetch a service description to find out what the gateway
actually supports, and none of them can act as a gateway.

More importantly, none of them tell you *why* a mapping did not work — which
is the question people actually have.

**What this means for you:**

- **All three protocols**, negotiated concurrently, best one wins
- **Client and gateway** — the same library runs an IGD, not just talks to one
- **It explains failures** — CGNAT, double NAT, bridged router, no upstream
  link, a port with nothing listening on it, all diagnosed by name
- **`npm install` and go** — one small dependency for XML, no native code
- **Testable without a router** — `createTestPair()` runs a real client against
  a real gateway entirely in memory
- **Debuggable** — every packet, every state transition, every retry is
  JavaScript you can step through


## 📦 Quick Start

```bash
npm install port-mapper
```

> **Dependencies.** One: [`@rgrove/parse-xml`](https://www.npmjs.com/package/@rgrove/parse-xml)
> (ISC, no transitive dependencies) for the UPnP XML documents. Everything else
> — the binary protocols, SSDP, SOAP, the gateway, the enforcement layer — is
> plain JavaScript on `node:dgram`, `node:net` and `node:http`.
>
> [`turn-server`](https://www.npmjs.com/package/turn-server) is an
> `optionalDependency`. Install it and diagnostics gain STUN verification and
> NAT-type detection; without it they still work, from address classification
> alone.

### Open a port

```js
import { open } from 'port-mapper'

open(8080, (err, mapping) => {
  if (err) return console.error(err.message)

  console.log('Reachable at ' + mapping.address)
  //          Reachable at 81.2.3.4:8080

  // ...later
  mapping.close(() => {})
})
```

That is the whole thing for most callers. It discovers the gateway, tries PCP,
NAT-PMP and UPnP concurrently, uses whichever answers first, maps the port on
both IPv4 and IPv6, renews the lease automatically, and removes the mapping
when the process exits.

### Find out why it did not work

```js
open(8080, (err, mapping) => {
  if (err) return console.error(err.message)

  mapping.diagnose((_, d) => {
    if (d.reachable) return console.log('Open at ' + mapping.address)
    console.log(d.detail)
    console.log('→ ' + d.suggestion)
  })
})
```

```
The gateway reports 192.168.0.7 as its external address, which is a private
RFC 1918 address. This router is itself behind another NAT, so a mapping made
here is only reachable from that upstream network, not from the internet.
→ Put the upstream device in bridge mode, or add a matching forward on it to
  192.168.0.7.
```

### Run a gateway

```js
import { createServer, enforce } from 'port-mapper'

const igd = createServer({
  externalIp: '81.2.3.4',
  enforce: enforce.all()          // nftables → iptables → pf → relay
})

igd.on('port-request', (request, control) => {
  if (request.externalPort < 1024) return control.reject()
  control.allow()
})

igd.listen((err, info) => {
  console.log('IGD listening as ' + info.udn)
})
```

Answers PCP and NAT-PMP on UDP 5351, SSDP on 1900, serves the device
description and SOAP control over HTTP, and hands approved mappings to a
kernel NAT adapter. Nothing is granted and nothing is enforced by default —
both are explicit opt-ins.

### Diagnose from the command line

```bash
node bin/probe.mjs
node bin/probe.mjs --ipv6
node bin/probe.mjs 192.168.1.1      # force a gateway
```

Or through the package script:

```bash
npm run probe
```

```
Environment  (ipv4)
  interface           eth0
  local address       192.168.1.42
  detected gateway    192.168.1.1

Negotiation
  chosen              natpmp
  pcp                 rejected (UNSUPPORTED_VERSION)
  natpmp              available
  upnp                available (IGD:1, E4R by TP-LINK)

Diagnosis
  external IP         192.168.0.7
  address kind        private
  method              inferred
  reason              DOUBLE_NAT
  → Put the upstream device in bridge mode
```


## ✨ Features

**Protocols**

- PCP (RFC 6887) — MAP and PEER opcodes, ANNOUNCE, `PREFER_FAILURE`,
  `THIRD_PARTY` and `FILTER` options, nonce-bound mappings, IPv6
- NAT-PMP (RFC 6886) — full client and gateway, including the announcement
  sequence and the conservative epoch test
- UPnP-IGD:1 and IGD:2 — `AddPortMapping`, `AddAnyPortMapping`,
  `DeletePortMapping`, `DeletePortMappingRange`, `GetListOfPortMappings`,
  `GetGenericPortMappingEntry`, `GetSpecificPortMappingEntry`,
  `GetPortMappingNumberOfEntries`, `GetExternalIPAddress`, `GetStatusInfo`,
  `GetConnectionTypeInfo`
- `WANIPv6FirewallControl:1` — pinholes, packet counters, firewall status
- `WANCommonInterfaceConfig:1` — link type, line rate, traffic counters

**Discovery and eventing**

- SSDP over IPv4 and IPv6, multicast and unicast, with MX reply spreading
- `BOOTID`, `NEXTBOOTID`, `CONFIGID` and `SEARCHPORT`, on both sides
- `ssdp:update` distinguished from a restart, so subscriptions survive it
- GENA subscriptions with automatic renewal and sequence-gap detection
- SCPD fetched and parsed, so capabilities are read rather than assumed
- `LOCATION` validated against the local subnet

**Correctness**

- Epoch tracking on both protocols, with the two different validity tests
- Full UPnP error classification, including the ambiguity of 718 on IGD:1
- 725 → automatic fallback to a permanent lease
- 713 recognised as the end of the table, not as a failure
- Serial request queue, because gateways are small devices
- Overflow-safe timers for lifetimes beyond 24.8 days

**Operations**

- Automatic renewal at half the lease, with jitter
- Mapping verification against the gateway, and an optional watchdog
- Export and import, so a restart adopts its mappings instead of re-requesting
- Cancellation of any in-flight request
- Interface ranking that survives Docker, VPNs and hypervisors
- A local-port check, so mapping a port with nothing behind it is reported
- A quirks database of known gateway misbehaviours

**Gateway**

- PCP, NAT-PMP and UPnP-IGD responder in one process
- One policy handler for every protocol
- Enforcement adapters: nftables, iptables, pf, a userspace relay, and no-op
- Reconciliation of kernel rules left behind by a previous run

**Testing**

- `createTestPair()` — a real client and a real gateway, in memory, no root
- Packet interception, latency injection, and multi-client scenarios


## 📘 Client API

### `open(port, options?, callback)`

The convenience entry point. Creates the mappers, starts them, maps the port,
and returns a single object.

| Option | Default | Description |
|--------|---------|-------------|
| `ipv4` | `true` | Map a port with UPnP-IGD, NAT-PMP or PCP |
| `ipv6` | `true` | Open a pinhole with UPnP-IGD:2 or PCP |
| `protocol` | `'tcp'` | `'tcp'` or `'udp'` |
| `externalPort` | same as `port` | The external port to ask for |
| `exact` | `false` | Fail rather than accept a different external port |
| `onConflict` | `'increment'` | `'increment'`, `'any'` or `'fail'` |
| `lifetime` | `7200` | Lease in seconds; `0` asks for a permanent mapping |
| `description` | `'port-mapper'` | Shown in the router's UI. **Set this.** |
| `remoteHost` | — | Restrict the mapping to one remote address |

All [`createMapper`](#createmapperoptions) options are also accepted and passed
through.

**The mapping object**

```js
mapping.address        // '81.2.3.4:49152' — always usable, whichever family worked
mapping.addresses      // ['81.2.3.4:49152', '[2001:db8::1]:8080']
mapping.externalIp     // IPv4 when there is one
mapping.externalPort   // what was actually assigned, not what was asked for
mapping.protocol       // 'tcp'
mapping.via            // 'pcp' | 'natpmp' | 'upnp' | 'upnp-pinhole'
mapping.lifetime       // seconds
mapping.expiresAt      // Date
mapping.families       // ['ipv4', 'ipv6']
mapping.ipv4           // the IPv4 mapping, or null
mapping.ipv6           // the IPv6 pinhole, or null
mapping.failures       // [{ family: 'ipv6', error }]
mapping.mapper         // the underlying Mapper, for anything else

mapping.close(cb)      // unmap and shut down both families
mapping.diagnose(cb)   // see Diagnostics
```

`err` is only returned when **both** families failed. One family succeeding is
a success, and the other appears in `failures` — IPv6 mapping needs an IGD:2
gateway with `WANIPv6FirewallControl` or a PCP one, and most consumer hardware
has neither.

#### Asking for an exact port

```js
open(80, { exact: true }, (err, mapping) => {
  // err.code 718, or PCP CANNOT_PROVIDE_EXTERNAL, if 80 is not available
})
```

Without `exact`, a suggested port is a preference the gateway may ignore, and
`mapping.externalPort` tells you what you actually got. With it, PCP carries
`PREFER_FAILURE` (RFC 6887 §13.2) and UPnP uses `AddPortMapping` rather than
`AddAnyPortMapping` — the latter exists precisely to substitute a free port.

`onConflict: 'any'` goes further and asks the gateway to choose from the start.
RFC 6886 §9.4 makes the case for this: the gateway knows which ports are free
and the client does not.

---

### `createMapper(options?)`

Full control. One Mapper handles one address family.

| Option | Default | Description |
|--------|---------|-------------|
| `family` | `'ipv4'` | `'ipv4'` or `'ipv6'` |
| `gateway` | `'auto'` | Router address, or `'auto'` to detect |
| `interface` | `'auto'` | Local address or interface name to use |
| `protocols` | `['pcp','natpmp','upnp']` | Which to try |
| `lifetime` | `7200` | Lease in seconds |
| `description` | `'port-mapper'` | Shown in the router's UI |
| `negotiateTimeout` | `10000` | How long to wait for any gateway to answer |
| `retransmitAttempts` | `9` | NAT-PMP/PCP retries (RFC 6886 §3.1) |
| `searchTimeout` | `3000` | SSDP search window |
| `searchMx` | `2` | MX value; the window widens to cover it |
| `searchUnicast` | — | Send M-SEARCH to one address instead of multicast |
| `allowOffPath` | `false` | Accept an IGD that is not the default gateway |
| `announcements` | `true` | Listen for gateway announcements |
| `checkLocalPort` | `true` | Warn when nothing is listening on the internal port |
| `cleanupOnExit` | `true` | Remove mappings on exit and on SIGINT/SIGTERM |
| `watchdog` | `false` | `true` or `{ interval, restore }` |
| `stun` | auto | `false` to disable, or a custom provider function |
| `httpTimeout` | `5000` | Per-request timeout for SOAP |
| `bindAddress` | `'0.0.0.0'` | Local address to bind sockets to |

**Lifecycle**

```js
const mapper = createMapper({ description: 'MyApp' })

mapper.start((err, info) => {
  // info: { protocol, gateway, externalIp, device, family, results }
})

mapper.stop(cb)     // shut down, leaving mappings in place
mapper.close(cb)    // unmap everything first, then shut down
```

**Mapping**

```js
const handle = mapper.map({
  internalPort: 8080,
  externalPort: 8080,       // optional; 0 lets the gateway choose
  protocol: 'tcp',
  lifetime: 7200,
  exact: false,
  description: 'MyApp'
}, (err, mapping) => {})

handle.cancel('user closed the window')   // abandon it if it has not answered

mapper.unmap({ internalPort: 8080, protocol: 'tcp' }, cb)
mapper.cancelAll('shutting down')
```

Cancellation matters more than it looks: the NAT-PMP retransmission schedule
runs to nine attempts and the last wait alone is 64 seconds, so a request
nobody answers holds its callback for over two minutes.

**Inspecting**

```js
mapper.getMappings()          // what this process holds
mapper.getRouterMappings(cb)  // the whole table on the gateway
mapper.getExternalIp(cb)
mapper.getProtocol()          // 'pcp' | 'natpmp' | 'upnp'
mapper.getConfig()
mapper.getStats()
mapper.getInterfaces()        // every local address, ranked, with reasons
mapper.getCandidates()        // every IGD heard from, not just the chosen one
mapper.getQuirks()            // known misbehaviours of this gateway
```

**Gateway information** (UPnP only)

```js
mapper.getStatus(cb)             // { connectionStatus, uptime, lastError }
mapper.getConnectionType(cb)     // { type: 'IP_Routed', routed: true }
mapper.getLinkProperties(cb)     // { accessType, maxBitRateUp, linkUp }
mapper.getTrafficCounters(cb)    // { bytesSent, bytesReceived, ... }
mapper.getMappingCount(cb)
mapper.supportsAction('AddAnyPortMapping', cb)
mapper.call('SomeVendorAction', { arg: 1 }, cb)   // escape hatch
```

`getConnectionType` is worth checking before blaming the protocol: a gateway
in `IP_Bridged` mode accepts a mapping and does nothing with it, because it is
not the device performing translation.

**IPv6 pinholes**

```js
mapper.addPinhole({ internalPort: 3000, protocol: 'udp', lifetime: 3600 }, cb)
mapper.updatePinhole(uniqueId, 7200, cb)
mapper.deletePinhole(uniqueId, cb)
mapper.checkPinholeWorking(uniqueId, cb)
mapper.getFirewallStatus(cb)
mapper.getPinholes()
```

**Persistence**

```js
fs.writeFileSync('mappings.json', JSON.stringify(mapper.exportMappings()))

// after a restart, within the lease
mapper.importMappings(saved, (err, report) => {
  // { adopted, expired, vanished, stolen, foreign }
})
```

The point is to *adopt*, not to recreate. A mapping outlives the process until
its lease expires; what is lost is the renewal schedule. A program that
restarts within the lease picks it up instead of asking the gateway for ports
it already has — which on a gateway with a small table is the difference
between continuing and being refused. Every entry is verified before adoption,
and a file written on another network is refused wholesale.

**Verification and the watchdog**

```js
mapper.verifyMappings((err, report) => {
  // { checked, present, vanished, stolen, unknown }
})

mapper.startWatchdog({ interval: 300000, restore: true })
```

A successful renewal is not proof. Some firmware reclaims a mapping that has
carried no traffic and then answers the next `AddPortMapping` cheerfully,
because from its side that is a new mapping. `GetSpecificPortMappingEntry`
asks rather than asserts. On PCP there is no read operation at all, so
verification is a reassertion — which restores the mapping either way, and
says `verified: 'reasserted'` rather than claiming certainty.

**Eventing**

```js
mapper.subscribe((err, sub) => {})     // opens a listener and subscribes
mapper.on('external-ip-changed', c => updateDNS(c.to))
mapper.unsubscribe(sub.sid, cb)
```

RFC 6886 §9.6 observes that a NAT-PMP gateway multicasts when its external
address changes and that IGD has no equivalent. That is true of SSDP, but
`ExternalIPAddress` is an evented state variable, so a GENA subscription
delivers exactly that notification over HTTP instead.

**Cleanup**

```js
mapper.cleanup({ dryRun: true }, (err, report) => {
  // mappings this host left behind on a previous run
})
```

**Events**

| Event | Payload | When |
|-------|---------|------|
| `mapped` | mapping | A mapping was created |
| `renewed` | mapping | A lease was extended |
| `lost` | mapping, reason | The gateway dropped it |
| `remapped` | mapping, oldPort | It came back on a different port |
| `unmapped` | mapping | Removed |
| `conflict` | info | A port was taken; retrying |
| `empty-port` | info | Nothing is listening on the internal port |
| `gateway-reboot` | info | The epoch moved backwards |
| `gateway-restarted` | info | BOOTID changed without warning |
| `gateway-updated` | info | `ssdp:update`; the same device, changed |
| `gateway-gone` | info | `ssdp:byebye` |
| `external-ip-changed` | `{ from, to }` | Learned from a subscription |
| `degraded` | `{ from, to, reason }` | Fell back from PCP to NAT-PMP |
| `device` | info | An IGD was chosen |
| `quirks` | list | Known misbehaviours of this gateway |
| `events-missed` | info | A GENA notification was lost |
| `mapping-vanished` | mapping | The watchdog found it gone |
| `mapping-stolen` | mapping | The port now belongs to another host |
| `verified` | report | A verification pass finished |
| `adopted` | mapping | An imported mapping was taken back |
| `warning` | string | Something worth saying, not worth failing over |


## 🩺 Diagnostics

A SOAP call returning 200 does not mean a packet from the internet will
arrive. `diagnose()` is the difference between "it failed" and an explanation.

```js
mapper.diagnose((err, d) => {
  d.reachable    // true | false
  d.reason       // 'OK' | 'CGNAT' | 'DOUBLE_NAT' | 'UPSTREAM_NAT' | 'NOT_CONNECTED'
  d.detail       // a sentence explaining what was found
  d.suggestion   // what to do about it
  d.method       // 'inferred' | 'verified'
  d.externalIp   // what the gateway reports
  d.publicAddress// what a STUN server actually sees
  d.natType      // 'symmetric' | 'cone' | ... when turn-server is installed
})
```

| `reason` | Meaning |
|----------|---------|
| `OK` | The gateway holds a globally routable address |
| `CGNAT` | The address is in 100.64.0.0/10 — the ISP is translating too |
| `DOUBLE_NAT` | The gateway's own external address is RFC 1918 |
| `UPSTREAM_NAT` | The gateway looks public but STUN sees a different address |
| `NO_GATEWAY` | Nothing on the network answered any of the three protocols |
| `UNKNOWN` | The gateway refused to report its external address |
| `LOOPBACK`, `LINKLOCAL`, `UNSPECIFIED` | The router has no upstream link yet |

`CGNAT` also carries a ready-made `report.error` (a `CGNATError`), for a caller
that would rather throw than branch on a string. `DOUBLE_NAT` deliberately does
not: an upstream NAT under your own control can be fixed by configuring it,
which carrier-grade NAT cannot, and conflating the two would send people to
their ISP for no reason.

`UPSTREAM_NAT` is the case address classification alone can never catch: a
gateway can hold a perfectly public address and still not be the one the world
sees, because something further up is translating as well. Only the comparison
finds it.

**With `turn-server` installed**, `method` becomes `'verified'` and `natType`
appears. That matters when no mapping is possible, because what to do next
depends on it: a cone NAT can still be traversed by hole punching, a symmetric
one cannot and needs a relay.

```js
mapper.diagnostics((err, a) => {
  // { available: false, reason: 'turn-server is not installed — npm install turn-server' }
})
```


## 🛡 Gateway API

### `createServer(options?)`

| Option | Default | Description |
|--------|---------|-------------|
| `externalIp` | — | The WAN address to report |
| `policy` | `'deny-all'` | `'deny-all'` or `'allow-all'` |
| `enforce` | `[noop()]` | Adapter or array of adapters |
| `require` | — | Capabilities the adapter must have |
| `protocols` | all | `['pcp','natpmp','upnp']` |
| `family` | `'ipv4'` | Address family |
| `igdVersion` | `2` | Advertise IGD:1 or IGD:2 |
| `udn` | derived | Device UDN; derived from the MAC and stable across restarts |
| `friendlyName` | `'Node Router'` | Shown in control points |
| `manufacturer`, `modelName` | — | Description fields |
| `allowThirdPartyMappings` | `false` | Let a host map on behalf of another |
| `maxLifetime` | `86400` | Longest lease granted |
| `maxMappings` | `100` | Table limit |
| `maxPerClient` | `20` | Per-client limit |
| `controlTimeout` | `5000` | How long to wait for an async handler |
| `httpPort` | ephemeral | Port for the description and control endpoint |
| `wanInterface`, `lanInterface` | — | Passed to the enforcement adapter |
| `connectionType` | `'IP_Routed'` | Reported by `GetConnectionTypeInfo` |
| `wanAccessType`, `upstreamBitRate`, `downstreamBitRate` | — | Link properties |

```js
igd.listen(cb)
igd.close(cb)
igd.getMappings()
igd.revoke('tcp', 8080)
igd.setExternalIp('81.2.3.5')     // notifies subscribers
igd.resetEpoch()                  // declare every mapping gone
igd.reconcile(cb)                 // prune kernel rules from a previous run
igd.getEnforcer()
igd.getStats()
```

**The control object**

One handler covers every protocol. A gateway does not care whether a request
arrived as PCP or as a SOAP envelope; the decision is the same.

```js
igd.on('port-request', (request, control) => {
  // request: { via, protocol, internalIp, internalPort, externalPort,
  //            leaseDuration, description, remote }

  control.allow()          // grant it
  control.reject(606)      // refuse, optionally with a specific code
  control.ignore()         // do not answer at all
  control.externalPort = 49152    // grant a different port
  control.maxTtl = 600            // cap the lease
})
```

Declare a third parameter and the gateway waits for you:

```js
igd.on('port-request', (request, control, done) => {
  db.isAllowed(request.internalIp, (err, ok) => {
    ok ? control.allow() : control.reject()
    done()
  })
})
```

**Nothing is granted by default.** RFC 6886 §9.2 explains why this matters more
for IGD than for NAT-PMP: because UPnP IGD exposes every gateway setting rather
than just port mapping, a single piece of malicious web content can reach it
through the browser of anyone on the LAN and make a persistent change without
the user knowing.

**Third-party mappings are refused**, even under `allow-all`. IGD:1 lets a
client name any internal address it likes, which is what allows one host to
expose another — a neighbour's camera, a NAS, the router's own admin page.
NAT-PMP forbids this structurally by having no such field at all (RFC 6886
§3.3); here it is enforced in code, and `allowThirdPartyMappings` lifts it
deliberately.

**Gateway events**

| Event | When |
|-------|------|
| `listening` | Sockets are up |
| `port-mapped`, `port-renewed`, `port-unmapped`, `port-expired` | Table changes |
| `port-rejected` | A request was refused |
| `third-party-blocked` | A host tried to map on another's behalf |
| `quota-exceeded` | Per-client or per-gateway limit hit |
| `enforce-selected` | Which adapter won, and what was rejected |
| `enforce-failed` | A rule could not be installed; the mapping was revoked |
| `reconciled` | Orphaned rules were pruned |


## ⚙️ Enforcement adapters

Deciding a mapping is allowed and *making it happen* are different jobs. The
protocol half is portable JavaScript; enforcement touches the operating system,
usually needs root, and is where a mistake becomes a security problem.

| Adapter | Platform | Root | Source IP | Throughput | Survives exit |
|---------|----------|------|-----------|------------|---------------|
| `nftables` | Linux | yes | preserved | wire-speed | yes |
| `iptables` | Linux | yes | preserved | wire-speed | yes |
| `pf` | BSD, macOS | yes | preserved | wire-speed | no |
| `relay` | everywhere | no | **lost** | medium | no |
| `noop` | everywhere | no | — | none | no |

```js
import { enforce } from 'port-mapper'

createServer({ enforce: enforce.all() })              // best available
createServer({ enforce: [enforce.relay()] })          // userspace only
createServer({ enforce: enforce.all(), require: { preservesSourceIp: true } })
```

`require` refuses to start rather than degrade silently. That matters because
the relay — the only adapter that runs without root, on any platform — cannot
preserve the source address: the internal service sees every connection coming
from the gateway. Anything that logs, rate-limits or filters by client address
is then working with the wrong value, and a rate limiter keyed on it turns
"100 requests per client" into "100 requests for everyone together".

The relay can carry the address in band instead:

```js
enforce.relay({ proxyProtocol: true })
```

One HAProxy PROXY-protocol line before each TCP connection. Understood by
nginx, HAProxy, Postgres and others — but the inner service must be configured
to expect it, or it will read the header as garbage.

**Writing your own**

```js
{
  name, capabilities,
  check(cb), init(config, cb), add(mapping, cb), remove(mapping, cb),
  list(cb), destroy(cb)
}
```

```js
import { enforce } from 'port-mapper'

enforce.conformance(myAdapter, { name: 'mine' }, (err, report) => {
  console.log(report.passed + '/' + report.total)
})
```

The conformance suite runs against every adapter, including the data plane
where the adapter claims to move packets, and skips what cannot apply.


## 🧪 Testing

```js
import { createTestPair, createUPnPTestPair } from 'port-mapper'

const pair = createTestPair({ server: { policy: 'allow-all' } })

pair.client.map({ internalPort: 8080 }, (err, m) => {
  assert.equal(pair.server.getMappings()[0].externalPort, m.externalPort)
  pair.destroy()
})
```

A real client session joined to a real gateway session with no sockets, no
root and no router. Delivery is asynchronous, so ordering semantics are
preserved rather than collapsing into synchronous calls that would hide races.

```js
createTestPair({
  latency: 50,
  intercept: (direction, buf) => {
    if (direction === 'client->server' && Math.random() < 0.5) return false
  }
})

pair.addClient()      // a second client on the same segment
```

This is how the library tests itself, and it found real bugs: a gateway that
announced in only one dialect, a search window shorter than the MX it sent, and
a table walk that recursed once per entry.


## 🎯 Use cases

#### A desktop app that needs to be reachable

```js
import { open } from 'port-mapper'

open(8080, { description: 'MyApp' }, (err, mapping) => {
  if (err) return ui.showError(err.message)

  mapping.diagnose((_, d) => {
    if (d.reachable) ui.showAddress(mapping.address)
    else ui.showProblem(d.detail, d.suggestion)
  })
})

app.on('before-quit', e => {
  e.preventDefault()
  mapping.close(() => app.exit())
})
```

`cleanupOnExit` catches Ctrl+C and SIGTERM but not a crash, so the finite lease
is the real safety net — which is why `lifetime: 0` should be a deliberate
choice, not a default.

#### A self-hosted service with dynamic DNS

```js
const mapper = createMapper({ description: 'Nextcloud', watchdog: true })

mapper.start(() => {
  mapper.map({ internalPort: 443 }, () => {})
  mapper.subscribe(() => {})
})

mapper.on('external-ip-changed', c => updateDNS(c.to))
mapper.on('mapping-vanished', m => log('router dropped ' + m.externalPort))
```

#### A router on a Raspberry Pi

```js
import { createServer, enforce } from 'port-mapper'

createServer({
  externalIp: wanAddress,
  wanInterface: 'eth0',
  lanInterface: 'br0',
  enforce: enforce.all()
}).listen(() => {})
```

Together with [`dhcp-server`](https://www.npmjs.com/package/dhcp-server) and
[`mdns-local`](https://www.npmjs.com/package/mdns-local), this replaces
`dnsmasq` + `avahi` + `miniupnpd` with one Node process.

#### A policy layer that enforces nothing

```js
createServer({ policy: 'deny-all', enforce: [enforce.noop()] })
  .on('port-request', (req, control) => {
    audit.log(req.internalIp, req.externalPort, req.via)
    approved.has(req.internalIp) ? control.allow() : control.reject()
  })
```

A gateway that listens to every mapping request on the network, records who
asked for what and by which protocol, and decides — without touching the
kernel. Useful for a corporate or guest network, and there is no equivalent in
any language.

#### Choosing a NAT traversal strategy

```js
mapper.diagnose((_, d) => {
  if (d.reachable)                 return useDirectPort()
  if (d.natType === 'symmetric')   return useRelay()      // turn-server
  return useHolePunching()                                // turn-server, STUN
})
```

Port mapping and ICE are complementary answers to the same problem.
`diagnose()` is what decides between them.


## 📊 Comparison

Compared against the four Node port-mapping libraries and the three generic
UPnP libraries, by reading their published source.

| | port-mapper | achingbrain | nat-api | runonflux | nat-upnp |
|---|:---:|:---:|:---:|:---:|:---:|
| **PCP (RFC 6887)** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **NAT-PMP (RFC 6886)** | ✅ | ✅ | ✅ | ❌ | ❌ |
| **UPnP-IGD:1** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **AddAnyPortMapping (IGD:2)** | ✅ | ✅ | ❌ | ❌ | ❌ |
| **IPv6 pinholes** | ✅ | ✅ | ❌ | ❌ | ❌ |
| | | | | | |
| **GetListOfPortMappings** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **DeletePortMappingRange** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **GetStatusInfo** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **GetConnectionTypeInfo** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **WANCommonInterfaceConfig** | ✅ | ❌ | ❌ | ❌ | ❌ |
| | | | | | |
| **SCPD fetched + parsed** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **GENA eventing** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **SEQ gap detection** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **BOOTID / ssdp:update** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **SEARCHPORT** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **setMulticastInterface** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **LOCATION subnet validation** | ✅ | ❌ | ❌ | ❌ | ❌ |
| | | | | | |
| **Epoch used for reboot detect** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Error code classification** | ✅ | ✅ | ❌ | ❌ | ❌ |
| **718 / 725 / 713 handled** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Exact port (PREFER_FAILURE)** | ✅ | ❌ | ❌ | ❌ | ❌ |
| | | | | | |
| **Cancellation** | ✅ | ✅ | ❌ | ❌ | ❌ |
| **Export / import state** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Watchdog / verification** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **CGNAT / double-NAT diagnosis** | ✅ | partial | ❌ | ❌ | ❌ |
| **STUN cross-check** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Interface ranking (Docker/VPN)** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Local port listening check** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Router quirks database** | ✅ | ❌ | ❌ | ❌ | ❌ |
| | | | | | |
| **Gateway / IGD responder** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Enforcement adapters** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **In-memory test transport** | ✅ | ❌ | ❌ | ❌ | ❌ |
| | | | | | |
| **TypeScript types** | 🚧 | ✅ | ❌ | ✅ | ❌ |
| **Dependencies** | 1 | 9 | 3 | 4 | 2 |

Two findings from reading their source are worth calling out, because they are
not visible from the outside:

**Nobody fetches the SCPD.** All four read `SCPDURL` out of the device
description and store it, and none of them ever request it. Every one of them
is guessing which actions the gateway implements.

**Nobody uses the epoch.** `@achingbrain/nat-port-mapper` and `nat-api` both
parse it into a field that is never read again. There is no gateway-restart
detection in any Node port-mapping library: a mapping disappears and the client
carries on believing it holds one.


## 🔧 Router quirks

Every mature implementation carries this knowledge; none of them carries it as
data. miniupnpc has it in comments and scattered branches, and every
application that uses UPnP eventually rediscovers the same behaviours from bug
reports.

```js
mapper.on('quirks', list => {
  // [{ id: 'miniupnpd-renewal-does-not-extend', note: '...', source: '...' }]
})
```

Currently recorded, each with a citation:

| Quirk | Effect |
|-------|--------|
| MiniUPnPd ignores repeated `AddPortMapping` | Renewal deletes and recreates |
| MiniUPnPd secure mode answers 718 | A conflict that is really a refusal |
| MiniUPnPd 2.1+ with a private WAN address | 501 on every mapping |
| FRITZ!Box raises leases under 120s | Lease clamped to 120 |
| MiniUPnPd caps leases at 7 days | Lease clamped to 604800 |
| Some builds reclaim idle mappings | Verify rather than trust a renewal |
| ZTE gateways | UPnP only, nothing on 5351 |
| TP-Link Deco | NAT-PMP but not PCP; double-NAT by default |

The first is the one that quietly breaks things: on MiniUPnPd a repeated
`AddPortMapping` reports success and leaves the original expiry untouched, so
a client that renews this way watches its mapping expire exactly on schedule
while every renewal looked fine.

Pull requests adding a quirk are very welcome — one row, with a source.


## 🩹 Troubleshooting

**`PORTMAP_DEBUG=1`** prints every packet, decision and state transition.

```bash
PORTMAP_DEBUG=1 node app.js
PORTMAP_DEBUG=discovery,soap node app.js     # only some categories
```

Categories: `discovery`, `session`, `soap`, `transport`, `enforce`, `diagnose`.

```
[port-mapper:discovery] M-SEARCH → 239.255.255.250:1900 (attempt 1/3)
[port-mapper:discovery] response from 192.168.1.1: IGD:1, MiniUPnPd/2.1
[port-mapper:discovery] quirks: miniupnpd-renewal-does-not-extend, ...
[port-mapper:soap]      AddPortMapping {"NewExternalPort":8080,...}
[port-mapper:session]   mapped tcp 8080 → 81.2.3.4:8080, lease 7200s
[port-mapper:session]   renewal armed in 3600s
```

**"The mapping succeeded but nothing connects."**
Run `diagnose()`. The usual answers are `DOUBLE_NAT` (a second router in front
of yours — very common with mesh systems in router mode) and `CGNAT` (the ISP
is translating; no amount of port mapping will help).

**"Nothing is listening on tcp/8080."**
The mapping was made and traffic will arrive nowhere. The check is advisory: a
service bound to one specific address can be invisible to it.

**"No gateway answered."**
Try `mapper.getInterfaces()`. On a machine with Docker or a VPN up, the
outgoing interface may not be the one the gateway is on — the library ranks
interfaces by which shares a subnet with the default route, but an unusual
setup may need `interface` set explicitly.

**"Discovery works sometimes."**
A gateway one hop away often ignores unicast M-SEARCH. Try
`searchUnicast: '192.168.1.1'` for a specific device, and check
`getCandidates()` to see what was heard and passed over.

**"It worked yesterday."**
Check `gateway-restarted` and `lost`. A router reboot drops every mapping
without announcing it over UPnP, which is what the epoch and BOOTID tracking
are for.


## 📁 Project structure

```
port-mapper/
├── index.js                     - Public API
├── bin/probe.mjs                - Command-line diagnostics
└── src/
    ├── wire.js                    - PCP + NAT-PMP binary protocol, both sides
    ├── ssdp.js                    - SSDP, XML parsing, device descriptions
    ├── soap.js                    - SOAP, IGD actions, error codes, SCPD, GENA
    ├── control.js                 - The decision object, shared by every engine
    ├── lifecycle.js               - Renewal, retransmission, epoch policy
    ├── quirks.js                  - Known gateway misbehaviours
    ├── interfaces.js              - Interface ranking, local port checks
    ├── reachability.js            - STUN verification via turn-server
    ├── errors.js, debug.js, timers.js
    │
    ├── pmp_session.js             - PCP + NAT-PMP client engine
    ├── upnp_session.js            - UPnP-IGD client engine
    ├── pmp_server_session.js      - PCP + NAT-PMP gateway engine
    ├── upnp_server_session.js     - UPnP-IGD gateway engine
    │
    ├── negotiate.js               - Concurrent protocol race
    ├── mapper.js                  - Client transport: sockets, HTTP, diagnosis
    ├── server.js                  - Gateway transport
    ├── open.js                    - One-line entry point
    ├── testing.js                 - In-memory test transport
    └── enforce/
        ├── index.js               - Adapter contract and selection
        ├── nftables.js, iptables.js, pf.js, relay.js
        ├── exec.js                - Command execution
        └── conformance.js         - Shared adapter test suite
```

| File | Lines | Role |
|------|-------|------|
| `upnp_session.js` | 1,756 | UPnP client — discovery, control, eventing |
| `mapper.js` | 1,481 | Client transport, diagnosis, persistence |
| `upnp_server_session.js` | 1,197 | UPnP gateway — SSDP, SOAP, subscriptions |
| `wire.js` | 1,192 | Binary protocols, every byte on the wire |
| `pmp_session.js` | 966 | PCP/NAT-PMP client engine |
| `soap.js` | 773 | SOAP, IGD actions, SCPD, GENA |
| `pmp_server_session.js` | 760 | PCP/NAT-PMP gateway engine |
| `server.js` | 685 | Gateway transport, enforcement wiring |
| `ssdp.js` | 680 | SSDP and XML |
| everything else | ~2,300 | enforce, testing, quirks, interfaces, helpers |
| **Total** | **~13,600** | **319 tests, one dependency** |


## 🛣 Roadmap

### ✅ Done

- PCP (RFC 6887) — MAP, PEER, ANNOUNCE, PREFER_FAILURE, THIRD_PARTY, FILTER
- NAT-PMP (RFC 6886) — client and gateway, announcements, epoch handling
- UPnP-IGD:1 and IGD:2 — every mapping action, plus status, connection type and
  traffic counters
- WANIPv6FirewallControl — pinholes on both sides
- SCPD fetched and parsed; capabilities read rather than assumed
- GENA subscriptions, renewal, sequence-gap detection
- SSDP over IPv4 and IPv6, BOOTID / NEXTBOOTID / CONFIGID / SEARCHPORT
- Gateway restart detection on both protocols
- Concurrent protocol negotiation
- CGNAT, double-NAT and upstream-NAT diagnosis, with optional STUN verification
- Interface ranking that survives Docker, VPNs and hypervisors
- Export / import, verification, watchdog
- Full gateway: PCP, NAT-PMP and UPnP-IGD responder with one policy handler
- Enforcement adapters: nftables, iptables, pf, userspace relay, no-op
- Adapter conformance suite
- In-memory test transport
- Router quirks database
- 319 tests passing

### 🚧 In progress

- TypeScript definitions

### 📋 Planned

- `mapAll()` — map on every local interface at once
- OpenWrt adapter (UCI-aware, survives `fw4 reload`)
- Container-aware enforcement detection
- Reachability probing through an external echo service

_Community contributions are welcome! Please ⭐ star the repo to follow progress._


## 📜 License

**Apache License 2.0**

```
Copyright © 2026 colocohen

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
