/**
 * quirks.js — known deviations, by gateway.
 *
 * Every mature port-mapping implementation carries this knowledge; none of
 * them carries it as data. miniupnpc has it in comments and scattered
 * branches, and every application that uses UPnP eventually rediscovers the
 * same handful of behaviours from bug reports. Collected here, a quirk is one
 * row that a user report can extend, rather than a special case buried in
 * control flow.
 *
 * Matching is on the SERVER header a device sends in SSDP and on its
 * manufacturer and model, because those are what a gateway actually tells us
 * about itself. Nothing here changes what is sent on the wire by default: a
 * quirk either adjusts a default the specification leaves open, or it explains
 * an error that would otherwise be misread.
 *
 * Sources are recorded per entry. A quirk without one is a rumour.
 */


const QUIRKS = [
  {
    id: 'miniupnpd-renewal-does-not-extend',
    match: { server: /MiniUPnPd/i },
    // miniupnp#199, openwrt/packages#2889: repeating AddPortMapping for a
    // mapping that already exists leaves the original expiry in place. A
    // client that renews by repeating the request watches its mapping expire
    // on schedule while every renewal reports success.
    effects: { renewByRecreate: true },
    note: 'MiniUPnPd does not extend an existing lease when AddPortMapping is ' +
          'repeated, so a renewal has to delete the mapping and create it again.',
    source: 'github.com/miniupnp/miniupnp/issues/199'
  },

  {
    id: 'miniupnpd-secure-mode-reports-718',
    match: { server: /MiniUPnPd/i },
    // With secure_mode enabled it refuses to map on behalf of another host,
    // and answers 718 ConflictInMappingEntry rather than 606. A client that
    // reads 718 as "port taken" then retries other ports forever.
    effects: { conflictMayMeanRefusal: true },
    note: 'In secure mode MiniUPnPd answers a third-party mapping attempt with ' +
          '718, which reads as a port conflict but is a refusal.',
    source: 'snbforums.com/threads/upnp-throwing-conflictinmappingentry.73065'
  },

  {
    id: 'miniupnpd-rejects-private-external',
    match: { server: /MiniUPnPd\/2\.[1-9]/i },
    // From 2.1 it refuses to operate when its own WAN address is RFC 1918,
    // failing every AddPortMapping with 501. The mapping is not the problem;
    // the double NAT is.
    effects: { failsBehindDoubleNat: true },
    note: 'MiniUPnPd 2.1+ refuses to map when its own external address is ' +
          'private, answering 501 — the gateway is behind another NAT.',
    source: 'redmine.pfsense.org/issues/10398'
  },

  {
    id: 'fritzbox-minimum-lease-120',
    // AVM identifies itself in the SERVER header on some firmwares and only in
    // the description on others, so both are matched
    match: { server: /AVM|FRITZ/i, manufacturer: /AVM/i, model: /FRITZ/i },
    // miniupnp#222: a requested duration below 120 seconds is silently raised
    // to 120, so a client asking for 30 and renewing at 15 is renewing four
    // times more often than it needs to
    effects: { minimumLease: 120 },
    note: 'FRITZ!Box raises any lease shorter than 120 seconds to 120.',
    source: 'github.com/miniupnp/miniupnp/issues/222'
  },

  {
    id: 'miniupnpd-maximum-lease-week',
    match: { server: /MiniUPnPd/i },
    effects: { maximumLease: 604800 },
    note: 'MiniUPnPd caps a lease at seven days.',
    source: 'forum.openwrt.org/t/need-help-with-miniupnp-lease-duration/3552'
  },

  {
    id: 'miniupnpd-clears-idle-mappings',
    match: { server: /MiniUPnPd/i },
    // Some builds reclaim mappings that have carried no traffic, regardless of
    // the lease. Renewing on schedule does not save them.
    effects: { reclaimsIdleMappings: true },
    note: 'Some MiniUPnPd builds reclaim mappings that have seen no traffic, ' +
          'whatever the lease says — verify the mapping rather than trusting ' +
          'a successful renewal.',
    source: 'snbforums.com/threads/upnp-lease-times.32532'
  },

  {
    id: 'zte-igd1-no-pcp',
    match: { manufacturer: /ZTE/i, server: /ZTE/i },
    // Observed on a ZTE F680: UPnP-IGD:1 only, no answer on 5351, and finite
    // leases are honoured
    effects: { noPcp: true, noNatPmp: true },
    note: 'ZTE gateways generally answer UPnP only; nothing listens on 5351.',
    source: 'field report, ZTE F680'
  },

  {
    id: 'tplink-deco-natpmp-only',
    match: { model: /Deco|E4R/i, manufacturer: /TP-?LINK/i },
    // Observed on a Deco E4R: NAT-PMP answers, PCP is rejected with
    // UNSUPPORTED_VERSION, and in router mode it double-NATs by default
    effects: { noPcp: true, doubleNatByDefault: true },
    note: 'TP-Link Deco answers NAT-PMP but rejects PCP, and in its default ' +
          'router mode it puts a second NAT in front of the ISP gateway.',
    source: 'field report, TP-Link Deco E4R'
  },

  {
    id: 'zte-refuses-privileged-ports',
    match: { manufacturer: /ZTE/i, server: /ZTE/i, model: /F680/i },
    // Observed on a ZTE F680: port 80 comes back 718 because the router's own
    // admin interface holds it, and 443 makes the SOAP endpoint close the
    // connection without answering at all
    effects: { refusesPrivilegedPorts: true },
    note: 'ZTE gateways refuse to map ports below 1024 over UPnP — 80 answers ' +
          '718 and 443 drops the connection. Forward them by hand in the ' +
          'router\'s own interface instead. This makes ACME http-01 and ' +
          'tls-alpn-01 impossible through UPnP on these devices.',
    source: 'field report, ZTE F680 (ETB Colombia)'
  },

  {
    id: 'ssdp-unicast-search-ignored',
    match: { server: /.*/ },
    applyByDefault: false,
    // Very common: a device joins the SSDP group and never answers a unicast
    // M-SEARCH, which is why a gateway one hop away cannot be discovered
    effects: { unicastSearchUnreliable: true },
    note: 'Many gateways listen for SSDP only on the multicast group and ignore ' +
          'a unicast M-SEARCH, so a device a hop away may be undiscoverable.',
    source: 'field report; observed on ZTE F680'
  }
];


/**
 * Which quirks apply to a device.
 *
 *   match({ server: 'Linux/3.4 UPnP/1.1 MiniUPnPd/2.1', manufacturer: 'AVM' })
 *
 * Entries marked applyByDefault:false are informational and are only returned
 * when explicitly asked for, so a general match never carries advice that was
 * not about this device.
 */
function match(device, options) {
  options = options || {};
  var out = [];

  for (var i = 0; i < QUIRKS.length; i++) {
    var q = QUIRKS[i];
    if (q.applyByDefault === false && !options.includeInformational) continue;

    var m = q.match;
    var hit =
      (m.server && device.server && m.server.test(device.server)) ||
      (m.manufacturer && device.manufacturer && m.manufacturer.test(device.manufacturer)) ||
      (m.model && device.modelName && m.model.test(device.modelName)) ||
      (m.model && device.friendlyName && m.model.test(device.friendlyName));

    if (hit) out.push(q);
  }

  return out;
}


/**
 * Collapse the matched quirks into the settings a session should use.
 *
 * Later entries do not overwrite earlier ones blindly: a lease bound is
 * tightened rather than replaced, so two gateways in a chain both get their
 * limits respected.
 */
function effects_of(quirks) {
  var out = {};

  for (var i = 0; i < quirks.length; i++) {
    var e = quirks[i].effects || {};
    var keys = Object.keys(e);

    for (var j = 0; j < keys.length; j++) {
      var key = keys[j];
      var value = e[key];

      if (key === 'minimumLease') {
        out.minimumLease = Math.max(out.minimumLease || 0, value);
      } else if (key === 'maximumLease') {
        out.maximumLease = out.maximumLease === undefined
          ? value : Math.min(out.maximumLease, value);
      } else {
        out[key] = value;
      }
    }
  }

  return out;
}


/** Apply the lease bounds a gateway is known to enforce. */
function clamp_lease(lifetime, effects) {
  if (!effects) return lifetime;
  if (effects.minimumLease && lifetime && lifetime < effects.minimumLease) {
    return effects.minimumLease;
  }
  if (effects.maximumLease && lifetime > effects.maximumLease) {
    return effects.maximumLease;
  }
  return lifetime;
}


/** Everything known, for a report or for documentation. */
function all() { return QUIRKS.slice(); }


export { QUIRKS, match, effects_of, clamp_lease, all };
