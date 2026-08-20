# Zone-Based DNS (zonedns) — design document

Date: 2026-08-18
Status: the design is settled. Three of §11's original four facts to verify have
been cleared, and the design works around the fourth.

## 1. The problem

The environment mixes Kubernetes and VMs. Every workload has a SPIFFE ID whose
path carries its zone. Different zones are **isolated at the network layer**, and
cross-zone traffic can only go through a zone gateway.

The requirement: DNS resolution must give different answers according to the
asking workload's zone.

- Within one zone → the destination service's in-zone VIP (an ordinary
  Kubernetes ClusterIP or LB VIP)
- Across zones → **the destination zone's gateway VIP**

## 2. Terms

| Term | Meaning |
|---|---|
| zone | A workload's network/trust partition, encoded in the path of its SPIFFE ID |
| zone gateway | A zone's entry point, and the only path for cross-zone traffic |
| source zone | The zone of the workload issuing the DNS query |
| dest zone | The zone of the workload the queried FQDN corresponds to |
| agent plugin | The CoreDNS plugin installed on every machine, inside node-local DNS |
| central plugin | The zonedns plugin on the central CoreDNS |

## 3. Core invariants

These three are the foundation of the whole design, and any change must revisit
them:

1. **A zone is a single property of a workload.** One workload has the same zone
   as a client and as a server. A zone is declared in exactly one place: the
   pod's `zone` label, or provisioning configuration on a VM.
2. **An FQDN belongs to exactly one zone.** No selection policy is needed, and no
   failover semantics.
3. **Zones are network-isolated.** A wrong DNS answer causes a failure to
   connect, not a policy bypass. This is what demotes most failure modes from
   security problems to connectivity problems, which can be detected and alerted
   on.

## 4. Architecture overview

```
  pod (labels: zone=zone-a, zonedns.io/host=payments.example.com)
    │  plain UDP DNS, entirely unmodified
    ▼
  node-local DNS (CoreDNS) + agent plugin          ← on every machine
    │  ① source IP → local pod watch → labels["zone"]
    │  ② look up the cache under (qname, qtype, zone)
    ▼  ③ DoH over mTLS (the node SVID as the client cert), zone in EDNS0
  central CoreDNS + zonedns plugin (running on a VM)
    │  ④ the EDNS0 zone is believed only once the client cert is in the
    │     authorized agent list
    │  ⑤ registry: FQDN → dest zone (from SPIRE Server entries)
    │  ⑥ same zone → hand to the next plugin; cross zone → the dest zone GW VIP
    ▼
  upstream DNS (kubernetes plugin / forward)
```

### Why identity is established at the node

A DNS query packet carries no identity, and nothing attaches one automatically:

- The resolver (glibc/musl) assembles messages per RFC 1035 and knows nothing of
  SPIFFE
- The SPIRE agent is not on the data path; it is passive, and the workload asks
  it through the Workload API
- Unforgeable caller identity at the OS level exists only over a unix domain
  socket (`SO_PEERCRED`); above IP there is none
- Stuffing an SVID into the query would mean nothing either: certificates are
  public, and without a handshake nothing proves possession of the private key

So identity can only be established by a component that knows the pod's identity
and sits on the data path. The candidates are inside the pod (a per-pod sidecar)
or on the node (node-local DNS). The node was chosen because it needs no change
to workloads, works the same on Kubernetes and VMs, and the source IP cannot be
forged under CNI anti-spoofing.

### Alternatives considered and rejected

| Approach | Why rejected |
|---|---|
| Per-zone listener addresses, with dnsConfig injected by a webhook | Every machine would bind N link-local IPs, adding a zone would touch every node — and a pod could route around it at runtime |
| The zone in the qname (`payments.zone-a.example.com`) | The name changes when a service moves zone, binding naming to topology |
| One CoreDNS per zone, with no identity | A node mixes zones, and which instance was queried cannot determine the source zone |
| Full registry on each node, deciding locally | Every node would watch SPIRE Server, replicating the control plane onto every machine |
| eBPF inserting the EDNS0 option into outbound packets | It would have to parse and rewrite DNS in eBPF, recompute checksums, and handle an existing OPT; the receiver must still trust that program, which is the same trust model as trusting the agent — cost with nothing bought |
| A per-pod DNS sidecar | An extra container per pod, and "a sidecar per process" is unworkable on a VM |

## 5. The deployment-time contract

Both the zone and the external name are declared at deploy time, and **declared
once**.

### Kubernetes

The Deployment's pod template:

```yaml
metadata:
  labels:
    zone: zone-a
    zonedns.io/host: payments.example.com
```

`ClusterSPIFFEID`：

```yaml
apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterSPIFFEID
spec:
  podSelector:
    matchExpressions:
      - {key: zonedns.io/host, operator: Exists}
  spiffeIDTemplate: 'spiffe://example.org/zone/{{ .PodMeta.Labels.zone }}/ns/{{ .PodMeta.Namespace }}/sa/{{ .PodSpec.ServiceAccountName }}'
  dnsNameTemplates:
    - '{{ index .PodMeta.Labels "zonedns.io/host" }}'
```

**The Exists guard on `podSelector` is a requirement, not an optimisation.**
spire-controller-manager renders templates without `missingkey=error`, so a
missing label renders as the empty string; and SPIRE Server's
`x509util.ValidateLabel` refuses an empty DNS name with `ErrEmptyDomain`, which
**fails creation of the whole registration entry and leaves the pod without an
SVID** — damage reaching far beyond DNS.

The resulting SPIRE entry:

```
spiffe_id: spiffe://example.org/zone/zone-a/ns/prod/sa/payments
selectors: [k8s:pod-uid:...]
dns_names: [payments.example.com]
```

### VMs

A VM belongs to exactly one zone. The SPIRE entry has the same shape and the
registry cannot tell the difference:

```
spiffe_id: spiffe://example.org/zone/zone-c/vm/billing-01
dns_names: [billing.example.com]
```

The agent's zone is written into its configuration at provisioning time, or
parsed from the local SVID; there is no per-query determination.

### Istio ServiceEntry for the zone GW VIP — recommended, not required

**As things stand, `meshConfig.outboundTrafficPolicy.mode` is `ALLOW_ANY`,
Istio's default**, so although a cross-zone answer (a zone GW VIP) is not in
Istio's service registry, it still goes straight through the PassthroughCluster
and **works without a `ServiceEntry`**.

Registering the zone GW VIPs as `ServiceEntry`s is recommended hardening, for two
reasons:

- **Observability.** Istio's documentation states that observability degrades for
  passthrough traffic. Cross-zone traffic is precisely what this design most
  needs to monitor, and only registration gives it ordinary mesh telemetry.
- **Not depending on a mesh-level default.** Should anyone later tighten the mode
  to `REGISTRY_ONLY` for configuration hygiene, all unregistered cross-zone
  traffic would fall into the BlackHoleCluster and break.

**An exception that needs confirming**: a `Sidecar` resource can override this
mode per namespace or per workload. `ALLOW_ANY` at the mesh level does not
guarantee it holds everywhere; if some namespace overrides to `REGISTRY_ONLY`,
cross-zone traffic breaks within that scope while working elsewhere — a partial
failure that is hard to diagnose.

```
kubectl get sidecar -A -o yaml | grep -B10 -A2 outboundTrafficPolicy
```

## 6. Subproject 1: the central plugin

### 6.1 The `identity` unit — the trust boundary

```go
func SourceZone(ctx context.Context, w dns.ResponseWriter) (zone string, ok bool)
```

**The order must not be rearranged:**

1. The connection did not come from an mTLS listener → return `ok=false` (**this
   is the ordinary path, not an error**)
2. Take the peer certificate (the TLS layer has already verified the chain
   against the SPIRE trust bundle)
3. Take the agent's SPIFFE ID from the SAN URI → **it must appear in the
   configured authorized agent list**
4. **Read the zone declared in EDNS0 only once step 3 passes**; otherwise ignore
   the declaration and increment a metric (this is an attack signal and must be
   alertable)
5. Validate the zone string's format — character set and length

Transport-independent: DoT and DoH obtain certificates through different APIs,
isolated behind an interface.

```go
// DoT
w.(dns.ConnectionStater).ConnectionState().PeerCertificates
// DoH — DoHWriter does not implement ConnectionStater
w.(*dnsserver.DoHWriter).Request().TLS.PeerCertificates
```

Server-side mTLS is enabled through the `client_auth` option of CoreDNS's `tls`
plugin, set to `RequireAndVerifyClientCert` with `ClientCAs = RootCAs`.

### 6.2 The `registry` unit

```go
func Lookup(fqdn string) (zone string, ok bool)
```

It **polls** `ListEntries` on the SPIRE Server Entry API and flattens each entry
into `dns_names[i] → zone`, taking the zone from the `/zone/<X>/` segment of the
`spiffe_id` path.

**The Entry API has no watch or stream RPC.** `ListEntries` is a paginated unary
call; the one streaming RPC, `SyncAuthorizedEntries`, exists for an agent to sync
the entries it is authorized for and cannot list them all. So this unit is a
poller rather than a watcher, paginating with `page_size` / `next_page_token` and
using `output_mask` to fetch only `spiffe_id` and `dns_names`, keeping responses
small.

Accessing the Entry API requires an **admin SVID** — the VM central runs on needs
a SPIRE agent, and its registration entry must set `admin: true`.

Failure handling encapsulated inside: the first load not yet complete (returns
`ok=false` throughout, taking the non-zone-aware path); a failed poll keeps the
previous snapshot and increments a metric; several entries declaring one
`dns_name` into different zones (a conflict → the FQDN becomes unresolvable and a
metric is incremented, with no picking one of them).

### 6.3 The `zonetable` unit

```go
func Gateway(zone string) (netip.Addr, bool)
```

Pure configuration, from the Corefile or a mounted config file. The entry count
is on the order of the number of zones, a few dozen.

### 6.4 The decision logic

A pure function, no I/O:

| source zone | dest zone | Action |
|---|---|---|
| known | known, same | Hand to the next plugin |
| known | known, different | **Answer with that zone's GW VIP** |
| known | not in the registry | Hand to the next plugin (an external domain) |
| known | known, but no GW configured | **SERVFAIL** plus a high-priority metric |
| unknown | anything | Hand to the next plugin |

Only the second row changes an answer. The fourth deliberately does not fail
open: the registry says the zone exists but the zone table has no GW for it,
which is a missing configuration, and silently returning the direct VIP would
break zone isolation without a sound.

### 6.5 Caching and plugin order

The central side **does not need** a zone-aware cache:

- Same-zone answers come from upstream, are independent of the source zone, and
  only clients in the service's own zone reach that branch — so the original
  qname suffices as a key
- Cross-zone answers come from a configuration table held in memory and need no
  cache

The price is one ordering constraint: **`zonedns` must sort before `cache`**.
Otherwise cache answers ahead of zonedns and hands a same-zone answer to a
cross-zone client. This constraint must be checked at plugin registration and a
wrong order refused; documenting it is not enough.

### 6.6 The protocol contract between agent and central

Subproject 1 defines this contract and subproject 2 consumes it; compatibility
between them rests entirely on this section.

**Transport**: **DoH over mTLS (settled)**. The client cert is the SVID of the
machine the agent runs on, verified against the SPIRE trust bundle.

The agent side **does not use** CoreDNS's built-in `forward` plugin, even though
it does support DoH and mTLS (`forward . https://... { tls CERT KEY CA }`, with
`Proxy.SetTLSConfig` carrying the settings into DoH's
`http.Transport.TLSClientConfig`). The reason is that the `tls` option takes
**file paths and reads them once, at config parse time**, while SPIRE SVIDs
rotate frequently — a default TTL of one hour, reissued at the halfway point.
Swapping certificates by having the `reload` plugin re-read the configuration
**flushes the node cache along with it** — every half hour, on every machine —
which works directly against the point of deploying a node-local cache.

So the agent plugin holds its own upstream connection, taking certificates from
go-spiffe's `workloadapi.X509Source` and using
`tls.Config.GetClientCertificate` to fetch the currently valid SVID at each
handshake. Rotation happens entirely in memory, needs no configuration reload,
and leaves the node cache untouched.

**How the source zone is carried**: an EDNS0 option, with an option code from the
local/experimental range (65001–65534). The configured value must be identical at
both ends; the default is fixed in the contract and can be overridden by
configuration. The payload is the zone as a UTF-8 string, without the rest of the
SPIFFE ID.

Why EDNS0 rather than EDNS Client Subnet or a custom record: ECS means a network
prefix, not an identity, and intermediate resolvers rewrite it per RFC 7871; a
custom record would affect caching and serialisation behaviour.

**Validation rule**: before believing the option, central must complete steps 1–3
of §6.1. Failing that, the option is **treated as absent** rather than as an
error — the query continues on the non-zone-aware path and a metric is
incremented.

**TTL**: the TTL of a cross-zone answer is set by central, defaulting to 30
seconds. This value bounds the propagation delay when a service moves zone or a
zone GW VIP changes, and the agent's zone-aware cache must respect it. Zero is
not used because the node side would lose the benefit of caching entirely; a long
TTL is not used because a wrong answer during a zone topology change persists for
the whole TTL, and under network isolation that means sustained connection
failures.

## 7. Subproject 2: the agent plugin

Compiled into a self-built node-local DNS image; NodeLocal DNSCache is CoreDNS.
Node-local DNS's **addressing and deployment shape are entirely unchanged**: one
link-local address, the existing iptables rules, pods' resolv.conf untouched, no
mutating webhook, and no restart of existing pods. Adding a zone requires no
change to any node.

### 7.1 Kubernetes mode

```
source IP → the local pod table → labels["zone"]
```

The pod table is watched with `fieldSelector: spec.nodeName=<self>`, a few dozen
local entries. The `zone` label it reads is the very value `spiffeIDTemplate`
uses to produce the SPIFFE ID, so by construction the two cannot drift apart.

The premise: NodeLocal DNSCache uses a link-local address with no DNAT or
conntrack, so the source IP is the real pod IP. Whether an Istio sidecar is
present is transparent to this — the sidecar shares the app's netns, and even if
the query goes through the sidecar's DNS proxy before being forwarded, the source
IP is still the pod IP.

### 7.2 VM mode

The zone is settled at startup from a configuration file, shared by every query,
with no per-query determination.

### 7.3 Caching

It **must** be zone-aware: the final answer varies by zone. The key is
`(qname, qtype, zone)`. Since the agent computes the zone itself, the
implementation is straightforward. It sorts before the existing `cache` plugin.

### 7.4 Scoping through the Corefile

**The existing node-local cache is zone-blind** — keyed on `(qname, qtype)`. Were
it to cache zone-routed names, then once a zone-a pod had asked, a zone-b pod
would receive that same answer.

The approach is to have the agent plugin handle only the zone-routed domains, in
a server block of its own, leaving every other setting untouched:

```
cluster.local:53 { ... existing configuration untouched ... }

example.com:53 {
    zonedns_agent {
        spire_socket /run/spire/sockets/agent.sock
        upstream     https://central-dns/dns-query
    }
}

.:53 { ... existing cache + forward untouched ... }
```

The zone-aware cache of §7.3 is held by the agent plugin itself; the stock
`cache` plugin is not used. This arrangement confines the effect of adopting this
design on existing node-local DNS behaviour to a single domain.

### 7.5 Verifying the upstream's identity

**The agent must pin central by SPIFFE ID and must not merely verify the
certificate chain.**

Doing ordinary TLS verification against the SPIRE trust bundle alone would let
**any SVID** in the trust domain impersonate central. This is exactly symmetric
to the `AuthorizeMemberOf` problem found and fixed while implementing subproject
1, but the consequences are heavier on this side: a forged central can return
whatever it likes — telling a zone-a client that a same-zone service is actually
cross-zone, and handing back an attacker-controlled address. The agent has no
independent way to check the answer and believes it entirely.

The approach is the same as in subproject 1: `tlsconfig.AuthorizeID` with
central's SPIFFE ID from configuration, as a required setting — no default, and
startup fails without it.

**Deployment coupling**: the SPIFFE ID of the agent's own SVID must appear in
central's `authorized_agent` list, or central ignores the zone it declares and
falls back silently to the non-zone-aware path. The two ends' configurations must
be maintained as a pair.

### 7.6 Failure modes and their detection

With problems of this kind the greatest risk is not that they break but that they
break quietly. Every one of them must have a means of detection:

| Failure mode | Detection |
|---|---|
| A recycled pod IP still mapping to the old pod | The watch's delete event invalidates the mapping at once; an IP that cannot be found always takes the fallback, and an old value is **never** reused |
| SNAT/masquerading on the node rewriting the source IP | A metric for the proportion of queries whose source IP equals the node IP; a jump raises an alert |
| hostNetwork pods, whose source IP is the node IP | Fall back to the non-zone-aware path; the identity resolver is designed as a pluggable interface |
| The Kubernetes watch breaking | An explicit readiness state; while not ready, take the fallback rather than guess |

## 8. Threat model

| Attack | Outcome |
|---|---|
| A pod forging its source IP | CNI anti-spoofing blocks it; and even if it succeeded, the response could not be delivered to the attacker |
| An unauthorized source connecting straight to central CoreDNS and declaring any zone | The client cert is not in the authorized list → the declaration is ignored → the non-zone-aware path |
| Impersonation using somebody else's SVID certificate, the public part | Without the private key the mTLS handshake fails |
| Tampering with the EDNS0 zone value | It travels inside the mTLS tunnel and cannot be tampered with in transit |

Because zones are network-isolated, even a wrong zone decision yields an address
that does not route, so the consequence is a failed connection rather than a
policy bypass.

## 9. Known limitations

1. **A workload may have exactly one external FQDN.** A second optional label
   renders the empty string when unset and the entry is refused; a second
   `ClusterSPIFFEID` is masked by `entriesMasked` because its SPIFFE ID and
   selector are identical. Multiple aliases would require the Istio traversal
   approach instead.
2. **`zonedns.io/host` and a VirtualService's `hosts:` are two declarations of
   one name.** Drift means the registry cannot find the name → no zone routing, a
   degraded but safe outcome — and **nothing raises an error**. DNS queries keep
   returning answers, the answers simply stop being bound by zone.

   The defence is `cmd/zonedns-drift`: a set comparison of every VirtualService's
   `hosts:` against every pod label carrying `zonedns.io/host`, reported in both
   directions — hosts nobody claims (dangerous: clients will query them) and
   labels nobody queries (usually a typo). Exit code 0 clean, 1 drift found, 2 the
   check itself failed (cannot connect, insufficient permission, no Istio CRD).
   Suited to CI, or a CronJob on a schedule.

   Three kinds of name are excluded before the comparison and listed under
   `--show-skipped`: wildcard hosts, cluster-internal names (short names and
   `*.svc.cluster.local`), and VirtualServices bound to a gateway rather than the
   mesh. None of them can have a corresponding workload label, and comparing them
   would only produce false alarms.

   **This check compares names only.** Names matching on both sides can still
   point at the wrong workload — verifying that would mean tracing the route from
   VirtualService to destination Service to pod, the Istio traversal approach
   named in limitation 1, which this design deliberately does not adopt. The tool
   writes that boundary into its own output, so a clean report cannot be read as
   "correctly configured".
3. **Auditing is only at zone granularity.** Central does not know which workload
   is asking. Any future per-workload DNS policy would need a redesign rather than
   an extension.
4. **hostNetwork pods do not support zone routing.**

5. **A zone-aware listener must be DoH and must not be DoT.** Found during
   implementation review: CoreDNS's `metrics` plugin wraps the ResponseWriter in
   `NewRecorder(w)`, and that Recorder embeds `dns.ResponseWriter` as an
   **interface field**, so the `w.(dns.ConnectionStater)` type assertion that DoT
   certificate extraction depends on necessarily fails. The consequence is that
   every DoT query is judged to have "no certificate" → takes the non-zone-aware
   path → **zone isolation switches off silently, and the `unauthorized_agent`
   alert never fires**.

   The DoH path is unaffected because it takes the `*http.Request` from the
   context (see §6.1), regardless of whether the writer was wrapped — which is
   exactly why the context was chosen over a type assertion in the first place.

   Not fixed by reordering plugins: sorting `zonedns` before `metrics` would fix
   DoT, but CoreDNS's standard request metrics would then never see a cross-zone
   answer again — too high a price for a transport already decided against.

6. **Certificates with several URI SANs are always refused.** SPIFFE specifies
   exactly one URI SAN per certificate, but `crypto/tls`'s chain verification
   does not check how many there are. Were several accepted and the first spiffe
   URI taken, an attacker holding a certificate carrying both an authorized
   agent's ID and their own could impersonate it simply by ordering the
   authorized one first. So `SPIFFEIDFromCert` requires exactly one URI SAN, and
   refuses on ambiguity.

## 10. Testing strategy

- The `identity` unit must be tested more densely than any other — **whether the
  whole of zone isolation can be bypassed depends on nothing but it**.
  Adversarial cases: no cert, an unauthorized cert, an authorized cert with no
  EDNS0, several EDNS0 options, a zone string containing separator characters, a
  missing zone. Both certificate-extraction paths, DoT and DoH, tested once each.
- The decision logic is a pure function, exhausted table-driven over all five
  rows of §6.4.
- `registry`'s failure handling: the first load incomplete, the watch dropping,
  `dns_names` conflicts.
- The plugin ordering constraint: registering after `cache` must be an error.
- End to end: the central plugin can be verified without an agent, using a
  constructed mTLS connection plus EDNS0.

## 11. Facts to verify

1. ~~**Istio DNS capture status.**~~ **Confirmed: not enabled.** Queries are not
   intercepted by the sidecar and always reach node-local DNS. Whether a sidecar
   is present is transparent to this design — it shares the app's netns and the
   source IP is still the pod IP.

2. ~~**The effect of `outboundTrafficPolicy` on zone GW VIPs.**~~ **Confirmed:
   `ALLOW_ANY`**, so cross-zone traffic goes straight through the
   PassthroughCluster and works with no further configuration. `ServiceEntry`
   drops to a recommendation (see §5). **The one thing still to confirm**: whether
   any `Sidecar` resource overrides a namespace to `REGISTRY_ONLY` — cross-zone
   traffic would break within that scope while working everywhere else.

3. ~~**Where the central service sits.**~~ **Confirmed: on a VM, with no device
   terminating TLS on the path.** The trust boundary of §6.1 holds completely —
   the client cert central sees is the agent's own SVID.

   Confirmed again on 2026-08-20: this environment will have no TLS termination on
   the path to the DNS server.

   **This precondition is the design's security foundation.** Should an L7
   ingress, reverse proxy or TLS-terminating load balancer ever be introduced on
   that path, here is what happens:

   - **agent → central is stopped by construction.** `internal/dohupstream` pins
     the other side's SPIFFE ID with `tlsconfig.AuthorizeID(central)`, and a
     device presenting its own certificate fails the handshake outright —
     SERVFAIL plus `upstream_errors_total`. This side cannot fail silently.
   - **central → agent degrades, but with a signal.** What central sees is the
     intermediary's client cert, not the agent's own SVID. That identity is not
     in the `authorized_agent` list, so the zone declaration is ignored, the
     query falls back to the non-zone-aware path, and
     `coredns_zonedns_source_zone_total{reason="unauthorized_agent"}` rises —
     which is exactly why §9 limitation 5 and the deployment doc list it as a
     required alert.

   In other words, the runtime mTLS pinning is itself this precondition's
   continuous verification, and stronger than any test: it takes effect on every
   single query in production. **What no code can prevent is the human
   response** — adding the intermediary's SPIFFE ID to `authorized_agent` to
   "fix" that alert. After that step the device can declare any zone it likes,
   the whole of the isolation is defeated, and it is entirely silent. The runbook
   for the `unauthorized_agent` alert must say so plainly: the correct response is
   to remove the intermediary, not to authorize it.

4. **CoreDNS's support for multiple `bind` server blocks** — needed only if
   per-zone addresses are ever brought back.

## 12. Implementation order

Subproject 1, the central plugin, comes first. The contract has to exist before
anything else, and it can be verified end to end against real SPIRE entries with
no agent present. Subproject 2 consumes that contract, shares subproject 1's
stack — both are CoreDNS plugins — and can reuse the identity, zone parsing and
SPIFFE packages.
