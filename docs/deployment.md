# Deploying zonedns central

## Building

zonedns is an external CoreDNS plugin. CoreDNS plugins are linked at compile time
with no runtime loading mechanism, so the CoreDNS binary has to be rebuilt.

1. Fetch the CoreDNS source (the version must match the pin in `go.mod`)
2. Add one line to `plugin.cfg`, **before cache**:

   ```
   zonedns:github.com/jenting/zonedns/plugin/zonedns
   ```

   It must not go after `cache`. `setup()` calls
   `CheckDirectiveOrder(dnsserver.Directives)` the moment it starts, and a wrong
   order is refused outright rather than accepted silently (see
   `plugin/zonedns/setup.go`): with `cache` first, it answers from a
   `(qname, qtype)` key that carries no zone, and a cross-zone client receives an
   answer cached for another zone — with no sign of it at runtime.

3. Build:

   ```bash
   go generate && go build
   ```

## SPIRE preconditions

### 1. Workload registration entries — the registry's data source

zonedns's registry comes entirely from SPIRE registration entries: `dns_names`
supply the names and the `spiffe_id` path supplies the zone. On the Kubernetes
side they are produced by a `ClusterSPIFFEID`:

```yaml
apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterSPIFFEID
metadata:
  name: zonedns-workloads
spec:
  # A required guard: without this line, a pod not labelled zonedns.io/host
  # renders empty dns_names, SPIRE Server refuses the whole entry with
  # ErrEmptyDomain, and that pod gets no SVID at all — damage reaching far beyond
  # DNS. See §5 of the design doc.
  podSelector:
    matchExpressions:
      - {key: zonedns.io/host, operator: Exists}
  spiffeIDTemplate: 'spiffe://example.org/zone/{{ .PodMeta.Labels.zone }}/ns/{{ .PodMeta.Namespace }}/sa/{{ .PodSpec.ServiceAccountName }}'
  dnsNameTemplates:
    - '{{ index .PodMeta.Labels "zonedns.io/host" }}'
```

The corresponding Deployment pod template:

```yaml
metadata:
  labels:
    zone: zone-a
    zonedns.io/host: payments.example.com
```

On the VM side the entry has the same shape and the registry cannot tell the
difference:

```bash
spire-server entry create \
  -spiffeID spiffe://example.org/zone/zone-c/vm/billing-01 \
  -parentID spiffe://example.org/vm/vm-01 \
  -selector unix:uid:1000 \
  -dns billing.example.com
```

**A workload may have exactly one external FQDN** (design doc §9, known
limitation 1). A second optional label renders the empty string when unset and
the entry is refused; a second `ClusterSPIFFEID` is masked by `entriesMasked`
because its SPIFFE ID and selector are identical.

### 2. Central's own access to the Entry API

Two shapes, chosen by `spire_server` in the Corefile:

**Same machine (recommended)** — central and SPIRE Server share a VM and use the
local admin socket:

```
spire_server unix:///run/spire/sockets/server.sock
```

Access is governed by file permissions and needs no SVID, no
`spire_server_id` and no `workload_api`. Setting `spire_server_id` here does
nothing, since this path performs no mTLS handshake — leave it out; setting it
only invites confusion.

**Across machines** — mTLS, for which central needs a **SPIRE agent on the same
machine** to obtain an admin SVID, and that agent's registration entry must set
`admin: true`:

```bash
spire-server entry create \
  -spiffeID spiffe://example.org/zone/mgmt/service/zonedns-central \
  -parentID spiffe://example.org/vm/central-01 \
  -selector unix:uid:1000 \
  -admin
```

Besides `workload_api` — central's own Workload API socket, through which it
obtains that admin SVID — the Corefile **must** set `spire_server_id`:

```
spire_server     spire-server.example.org:8081
spire_server_id  spiffe://example.org/spire/server
workload_api     unix:///run/spire/sockets/agent.sock
```

`spire_server_id` pins SPIRE Server's **exact** SPIFFE ID (`AuthorizeID`) rather
than merely verifying "some member of the trust domain"
(`AuthorizeMemberOf`). Without it, anyone holding any SVID from the same trust
domain who can intercept this connection could impersonate SPIRE Server, feed a
forged registry, point any name at any zone, and thereby steer every routing
decision zonedns makes. When `spire_server` is a network address, `parseConfig`
refuses a configuration lacking `spire_server_id` outright — it fails closed.

There is no separate `trust_domain` option: `spire_server_id` is itself a
complete SPIFFE ID, trust domain included, so there is nothing to declare
twice.

## Corefile

**The transport is DNS-over-HTTPS, not DNS-over-TLS.** Both look like "DNS over
TLS", but zonedns's identity extraction is only reliable over DoH:

- A DoH client certificate is taken from the `*http.Request` in the context (the
  `identity` package), regardless of how CoreDNS wraps the
  `dns.ResponseWriter`.
- A DoT client certificate requires type-asserting the `ResponseWriter` to
  `dns.ConnectionStater`. CoreDNS's built-in `metrics` plugin wraps the writer in
  a Recorder that stores `dns.ResponseWriter` as an **interface field** rather
  than embedding a named concrete type, and the assertion necessarily fails on a
  writer it has wrapped.

The consequence: attach zonedns to a DoT listener such as `853` and every query
is judged to have "no certificate" and falls quietly back to the non-zone-aware
path — zone isolation switches off entirely, while the `unauthorized_agent`
metric that ought to raise the alarm never increments, because the code that
checks the client cert is never reached. `setup()` prints a startup warning when
it detects a DoT listener (see `warnIfDoT` in `plugin/zonedns/setup.go`) but
**does not refuse to start**. That is deliberate: sorting `zonedns` before
`metrics` would fix DoT, but CoreDNS's standard request metrics would then never
see a cross-zone answer again — too high a price for a transport already decided
against (design doc §9, limitation 5). In practice, use the `https://` listener
below; `853` is simply the misconfiguration an operator may reach for out of
habit, and the reason is set out here first.

```
https://example.com:443 {
    tls /etc/zonedns/svid.pem /etc/zonedns/svid-key.pem /etc/zonedns/bundle.pem {
        client_auth require_and_verify
    }

    zonedns {
        spire_server unix:///run/spire/sockets/server.sock
        poll_interval 30s

        # Only source zones declared by these SPIFFE IDs are believed.
        # Matched exactly; prefixes are not supported.
        authorized_agent spiffe://example.org/zone/infra/node/node-01
        authorized_agent spiffe://example.org/zone/infra/node/node-02

        edns0_code 65001
        ttl 30

        gateway zone-a 203.0.113.10
        gateway zone-b 203.0.113.11
        gateway zone-c 203.0.113.12
    }

    cache 30
    forward . 10.96.0.10
    prometheus :9153
    log
    errors
}
```

`client_auth require_and_verify` is required — without it CoreDNS does not ask
for a client certificate, `identity` gets none, every query takes the
non-zone-aware path, and **zone routing fails completely with no error
message**.

### Options in the `zonedns` block

These are the options `plugin/zonedns/setup.go` actually supports, and the only
ones. Any name not listed — including `trust_domain`, which older versions had
and which has been removed — is refused outright by `parseConfig`.

| Option | Required? | What it does |
|---|---|---|
| `spire_server` | **Required** | A `unix://` socket or `host:port`, choosing the access mode; see the previous section. |
| `authorized_agent` | **Required, at least one**; repeatable | The agent SPIFFE IDs permitted to declare a source zone, matched exactly. None at all means the plugin can never be zone-aware, which `parseConfig` treats as a misconfiguration and refuses. |
| `spire_server_id` | **Required** when `spire_server` is `host:port`; not needed for `unix://`, where setting it does nothing | Pins SPIRE Server's exact SPIFFE ID; see the previous section. |
| `workload_api` | Required when `spire_server` is `host:port` | Central's own Workload API socket, through which it obtains the admin SVID used to access the Entry API. |
| `poll_interval` | Optional, defaults to `30s` | How often the SPIRE Entry API is polled. Must be positive, or startup is refused. |
| `edns0_code` | Optional, defaults to `65001` | The EDNS0 option code carrying the source zone between agent and central. Must fall in IANA's local/experimental range `65001`–`65534`, and must match the agent's setting. |
| `ttl` | Optional, defaults to `30` | The TTL in seconds of a cross-zone answer, that is, a gateway address. |
| `gateway` | Optional, repeatable; syntax `gateway <zone> <address>` | The zone to gateway VIP mapping. Declaring one zone twice is refused, rather than the later entry winning. |

## Required alerts

These metrics are defined in `plugin/zonedns/metrics.go` and all carry the
`coredns_zonedns_` prefix — CoreDNS's metrics namespace is `coredns` and the
subsystem is `zonedns`.

| Metric | Condition | Meaning |
|---|---|---|
| `coredns_zonedns_source_zone_total{reason="unauthorized_agent"}` | Any non-zero growth | An unauthorized source is declaring a zone; this is an attack signal. **For the response see "An irreversible precondition" below — the identity must never be added to `authorized_agent` to silence it** |
| `coredns_zonedns_decision_total{action="servfail"}` | Any non-zero growth | Some zone has no gateway configured |
| `coredns_zonedns_registry_conflicts` | > 0 | An FQDN is declared into several zones, and those names are currently unresolvable |
| `coredns_zonedns_registry_ready` | == 0 for longer than one `poll_interval` | The registry has not loaded and every query falls back to non-zone-aware |
| `coredns_zonedns_registry_poll_errors` | > 0 | Consecutive failures polling the SPIRE Entry API — an expired admin SVID, `admin: true` revoked, a network partition. The Store keeps the previous snapshot, so neither `registry_ready` nor `registry_names` changes; this is the only metric that moves under this failure, while newly registered names or names that changed zone stay unresolvable and silently take the non-zone-aware path until polling recovers |
| `coredns_zonedns_source_zone_total{reason="no_tls"}` | Still growing after the migration is complete | Some client is not using the mTLS path |

`coredns_zonedns_registry_names`, the number of currently resolvable names, is
not an alert, but dropping to 0 or falling sharply is worth watching — it usually
means entries have disappeared en masse on the SPIRE Server side.

## An irreversible precondition

**No device may terminate TLS on the path between central and the node agents** —
no L7 ingress, no reverse proxy, no TLS-terminating load balancer. With one in
place, the client certificate central sees is that device's, the
`authorized_agent` comparison either fails or matches the wrong thing, and
**queries still return answers normally** — the failure is entirely silent
(design doc §11, item 3).

**Confirmed with the environment owner on 2026-08-20: there will be no TLS
termination on the path to the DNS server.** The design's security foundation
holds.

The runtime verifies this continuously, and more strongly than any periodic test
could — it takes effect on every query:

- **agent → central is stopped by construction.** The agent pins the other
  side's SPIFFE ID with `AuthorizeID(central)`, and a device presenting its own
  certificate fails the handshake outright, giving SERVFAIL plus
  `upstream_errors_total`. This side cannot fail silently.
- **central → agent degrades, but `unauthorized_agent` moves.** That is why the
  alert exists.

### The correct response to that alert

When `unauthorized_agent` rises, **the only correct response is to find the
unauthorized identity and remove it** — and if it is an intermediary, to take
that device off the path.

**Never add its SPIFFE ID to `authorized_agent` to make the alert go away.**
After that step the identity can declare any zone it likes, the whole of zone
isolation is defeated, and from then on it is entirely silent — the alert stops
firing, queries keep returning answers, and the answers are simply no longer
bound by anything. This is the step no code can prevent: `authorized_agent` is
configuration, and central trusts whoever the configuration says to trust.

For an additional active check, issue queries periodically with an unauthorized
certificate and confirm the zone declaration really is ignored — that is, that
the response is the ordinary non-zone-aware answer rather than a SERVFAIL or a
connection-level refusal. `identity` treats "unauthorized" and "no certificate"
as the same fallback, a deliberate fail-safe (design doc §6.1), which also means
this check cannot rest on whether the query failed and must compare the response
contents.

# Deploying the zonedns node side (the agent)

`plugin/zonedns_agent` determines the asking workload's zone, caches answers
under `(qname, qtype, zone)`, and declares the zone to central over mTLS DoH.
Like central it is an external CoreDNS plugin and must be compiled into the
binary; unlike central, what it compiles into is not ordinary CoreDNS but
`sigs.k8s.io/node-local-dns` — NodeLocal DNSCache, which is CoreDNS underneath.

**The length of this document is not an accident.** Nearly every failure mode in
this system returns an answer that looks normal rather than raising an error; a
wrong setting does not announce itself. Every section below answers the same
question: which misconfiguration makes zone isolation fail quietly.

## Building

1. Fetch the `sigs.k8s.io/node-local-dns` source.
2. Add this to the blank import block in `cmd/node-cache/main.go`:

   ```go
   _ "github.com/jenting/zonedns/plugin/zonedns_agent"
   ```

3. Insert `"zonedns_agent"` into `dnsserver.Directives`, **before `"cache"`**.
   It is the same guard as central's `CheckDirectiveOrder`, for the same reason:
   node-local-dns's built-in `cache` plugin keys on `(qname, qtype)` and does not
   include the asking workload's zone; with it first, once a zone-a pod has
   asked, a zone-b pod receives that same answer, and there is no sign of it at
   runtime. `setup()` calls `CheckDirectiveOrder(dnsserver.Directives)` the
   moment it starts, and a wrong order is refused outright rather than accepted
   silently (see `plugin/zonedns_agent/setup.go`).
4. **`go mod vendor`, not `go mod tidy`.** node-local-dns vendors its
   dependencies into the repo — there is a `vendor/` directory — so adding this
   module requires re-vendoring, or the build fails with "marked as explicit in
   vendor/modules.txt, but not explicitly required in go.mod". This repo is
   private and `go get` cannot reach it from inside a container, so a `replace`
   pointing at the source is needed too:

   ```bash
   go mod edit -replace github.com/jenting/zonedns=/path/to/zonedns
   go mod edit -require github.com/jenting/zonedns@v0.0.0
   go mod tidy          # must come before vendor
   GOOS=linux go mod vendor
   ```

   `go mod tidy` cannot be skipped, and cannot swap places with vendor: this
   module brings in dependencies upstream's `go.mod` does not have, and without
   tidying first `go mod vendor` fails outright with
   `updates to go.mod needed`.

5. **Both the vendoring and the build must specify `GOOS=linux`.** Running
   `go mod vendor` directly on macOS omits
   `k8s.io/kubernetes/pkg/util/iptables` — it is linux-only, and node-local-dns
   uses it to manage iptables rules. The symptom is a run of
   `undefined: utiliptables.Table`, which looks like a dependency version
   conflict when the vendor tree is simply missing that platform's files.
   node-local-dns only ever builds for linux, so its existing
   `Dockerfile.node-cache` does not run into this; only a direct local build
   does.

6. Build with `sigs.k8s.io/node-local-dns`'s existing `Makefile` and
   `Dockerfile.node-cache` — the deployment shape follows that project's
   artifacts entirely, and no separate CI/CD pipeline is needed.

These steps have been verified in practice: the build against
`sigs.k8s.io/node-local-dns`'s mainline succeeds and `zonedns_agent` loads
normally in the resulting binary — it reaches `NewMTLS` and stops there for want
of a SPIRE socket, which shows both the Corefile parse and the plugin
registration hold.

## Image size

Upstream `node-local-dns` depends only on `k8s.io/apimachinery` and does not
include `client-go`. `zonedns_agent`'s k8s mode (`internal/podzone`) needs
`client-go` to build the node-scoped informer over local pods, so the self-built
image is noticeably larger than upstream's — an expected trade, not a sign that
the build configuration is wrong.

Measured on one machine with one set of build parameters, `linux/arm64`:

| Binary | Size |
|---|---|
| Upstream node-local-dns | 44.7 MB |
| With `zonedns_agent` | 86.0 MB |

**Close to double: +39.4 MB, +92%.** This number is worth putting in front of
whoever manages image distribution before adoption: every node pulls this image.

VM mode never touches `client-go` at runtime (see the Corefile below), but since
it is the same binary, the size difference is present in both modes.

## Version pinning

`go.mod` pins the Kubernetes packages (`k8s.io/api`, `k8s.io/apimachinery`,
`k8s.io/client-go`) to `v0.35.4` and the `go` directive to `1.25.0`,
deliberately identical to what `sigs.k8s.io/node-local-dns` uses upstream rather
than following this repo's own pace. Moving any of them forward breaks the very
project this plugin exists to be compiled into:

- A `go` directive ahead of upstream demands a newer Go toolchain than
  upstream `node-local-dns`'s build environment, which its build scripts and CI
  images may not provide.
- Kubernetes libraries ahead of upstream drag upstream's own Kubernetes
  dependency forward with them, and underneath that sit `k8s.io/kubernetes`'s own
  version compatibility constraints — not something this repo can decide
  unilaterally.

Before raising any of these three versions, confirm that
`sigs.k8s.io/node-local-dns` upstream has already moved to the corresponding
version, not the other way round.

## Kubernetes manifests

The complete, directly applyable manifests are in `deploy/k8s/` — RBAC,
ConfigMap, DaemonSet and ClusterSPIFFEID — together with a table of the values
that must be replaced per environment. What follows explains what changed
relative to upstream.

## Changes to the DaemonSet

The deployment shape — a DaemonSet, one per node, the link-local address, the
iptables rules, pods' `resolv.conf` — is entirely unchanged. This is what §7
promised at the outset: adding a zone requires no change to any node, and
switching to the zone-aware image leaves the existing topology alone too. Only
three things change:

1. **`image`** points at the self-built registry from the previous section.
2. **RBAC** gains `get`/`list`/`watch` on pods (see below).
3. **The Corefile ConfigMap** gains one new server block (see below), leaving the
   existing `cluster.local:53` and `.:53` blocks alone.

## Corefile

As on the central side, `zonedns_agent` handles only the zone-routed domains, in
a server block of its own; node-local-dns's existing cluster-internal resolution
and default forward are entirely unaffected.

### Kubernetes mode

```
cluster.local:53 { ... existing configuration entirely untouched ... }

example.com:53 {
    zonedns_agent {
        mode              k8s
        node_name         {$NODE_NAME}
        zone_label        zone
        upstream          https://central.example.org:8443
        central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
        workload_api      unix:///run/spire/sockets/agent.sock
        cache_size        4096
    }
}

.:53 { ... existing cache + forward entirely untouched ... }
```

`{$NODE_NAME}` expands from the environment variable injected by the downward
API (`spec.nodeName`).

### VM mode

```
example.com:53 {
    zonedns_agent {
        mode              vm
        zone              zone-c
        upstream          https://central.example.org:8443
        central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
        workload_api      unix:///run/spire/sockets/agent.sock
        cache_size        4096
    }
}
```

VM mode needs neither `node_name` nor `zone_label` — there is no per-query
determination, the whole machine has one zone — and specifies it directly with
`zone`.

### Options in the `zonedns_agent` block

These are the options `parseConfig` in `plugin/zonedns_agent/setup.go` actually
supports, and the only ones; any name not listed is refused outright.

| Option | Required? | What it does |
|---|---|---|
| `mode` | **Required**, `k8s` or `vm` | Chooses which `ZoneResolver` is used. Any other value is refused. |
| `upstream` | **Required** | Central's address, **without a path**. The DoH path is always `/dns-query` and CoreDNS's doh package appends it; writing it in yourself makes the actual request `/dns-query/dns-query`, central answers HTTP 404, and all the agent sees is "upstream returned 404", which points at nothing — so a value carrying a path is refused at startup. It must be an `https://` URL. Plain `http://` is refused at startup, and not as a matter of style: over a plaintext transport the `http.Transport`'s `TLSClientConfig` is never consulted, the SPIFFE pin from `central_spiffe_id` is moot, and there is no error or warning while queries go out as usual. |
| `central_spiffe_id` | **Required, no default** | Without it, any SVID in the trust domain can impersonate central, and the agent — having no independent way to check the answers it receives — believes them entirely. |
| `workload_api` | **Required** | The agent's own SPIRE Workload API socket, through which it obtains the SVID it presents to central. |
| `zone` | **Required** in `vm` mode | The zone this VM belongs to. It must pass `ednszone.Valid` — letters, digits, `-`, `_`, at most 63 bytes — or central silently ignores this VM's zone declaration. |
| `node_name` | **Required** in `k8s` mode | Injected by the downward API; `podzone.Watcher` uses it to filter the pod watch to this node. |
| `zone_label` | Optional, defaults to `zone` | Which label on a pod is read as its zone. It must be the same label SPIRE's `spiffeIDTemplate` reads (see the central deployment section), or the zone the node determines will not match the zone in the registry. |
| `cache_size` | Optional, defaults to `4096` | The maximum number of entries in the zone-aware cache; must be a positive integer. |
| `node_ip` | Optional; also settable through the `NODE_IP` environment variable | This node's own address, used only to detect masquerading — when the source IP equals the node IP there is no way to tell which workload is asking. **A malformed value from either source fails startup rather than being ignored silently**: this address is the sole basis for masquerade detection, and swallowing one mistyped character in the DaemonSet manifest would leave that signal permanently dead with nothing recorded. The Corefile's `node_ip` takes precedence over the environment variable, being parsed later. |
| `edns0_code` | Optional, defaults to `65001` | The EDNS0 option code carrying the source zone between agent and central. Must fall in IANA's local/experimental range `65001`–`65534`, validated exactly as central's `edns0_code` is (see earlier in this document). **It must be identical to the `edns0_code` in central's Corefile**; see the next section. |

`central_spiffe_id`, `workload_api` and `cache_size` mean the same thing in both
k8s and vm mode and do not vary with it.

## RBAC

The minimum permissions k8s mode needs:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: zonedns-agent
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]
```

Bound to the ServiceAccount the node-local-dns DaemonSet uses. VM mode needs none
of this RBAC — `NewStaticResolver` never touches the Kubernetes API.

## Required alerts

These metrics are defined in `plugin/zonedns_agent/metrics.go` and all carry the
`coredns_zonedns_agent_` prefix — CoreDNS's metrics namespace is `coredns` and
the subsystem is `zonedns_agent`.

| Metric | Condition | Meaning |
|---|---|---|
| `coredns_zonedns_agent_zone_resolution_total{result="node_ip"}` | Any non-zero growth | A query's source IP equals the node's own: either something on the node is doing SNAT/masquerading and rewriting source addresses, or this is a hostNetwork workload. In neither case can the asking workload be identified, and the whole node silently degrades to declaring no zone |
| `coredns_zonedns_agent_zone_resolution_total{result="unknown"}` | Sustained growth | Some pod has no zone label, or the local informer is lagging behind pod creation (k8s mode) |
| `coredns_zonedns_agent_resolver_ready` | `== 0` for longer than one startup cycle | The pod watcher has not finished its first sync and no query declares a zone (always 1 in VM mode, where it does not apply) |
| `coredns_zonedns_agent_upstream_errors_total` | Any non-zero growth | A DoH exchange with central failed; the query returns SERVFAIL rather than passing to the next plugin (this plugin has no next plugin to pass to) |
| `coredns_zonedns_agent_cache_total{result="miss"}` | An unusually high proportion | The cache is too small (`cache_size`), or the TTL central hands out is too short, so most queries make the round trip to central |

`coredns_zonedns_agent_zone_resolution_total{result="bad_source"}` and
`{result="ok"}` are not alerts but are useful while investigating: `bad_source`
means the source IP received could not be parsed, which should almost never
happen, and `ok` counts ordinary successful determinations, useful for judging
whether the proportion of `unknown`/`node_ip` is out of the ordinary.

## Settings that must be maintained as a pair

Zone routing's trust relationship is pinned in both directions. Both sides must
change together, and changing one leaves the other silently out of service:

- **agent → central**: the SPIFFE ID of the SVID the agent presents to central
  must appear in the `authorized_agent` list of central's Corefile (see earlier
  in this document). Absent from that list, central ignores every zone this
  agent declares and every query takes the non-zone-aware path — the connection
  is not refused, and
  `coredns_zonedns_source_zone_total{reason="unauthorized_agent"}` is the only
  signal that moves.
- **central → agent**: central's own SPIFFE ID must be set as
  `central_spiffe_id` in the agent's Corefile. It is required at startup anyway,
  so it cannot simply be forgotten; but if the SPIFFE ID set here does not match
  the SVID central actually presents — central rotated its certificate and this
  was not updated with it — the mTLS handshake fails outright,
  `upstream_errors_total` rises, and queries return SERVFAIL. This side's failure
  is not silent, because `AuthorizeID` refusing the connection is itself an
  observable event.
- **`edns0_code` on both sides**: the `edns0_code` in both Corefiles must be the
  same value. Each side defaults to `65001`, so leaving both alone keeps them in
  step automatically; but once one side is changed to a non-default value and the
  other is not, the agent keeps writing the zone under its own code while
  central's `ednszone.Get` reads a different one — which amounts to "the option
  is not there". Queries still respond "normally", every one of them falling back
  to the ordinary non-zone-aware answer, and neither side's startup can detect
  the mismatch, since both values pass their own range checks. Before changing
  `edns0_code` on either side, confirm the other will change at the same time.

When adding a node, remember to add its SPIFFE ID — determined by its SPIRE
registration entry, see the central deployment section — to `authorized_agent`;
when decommissioning one, remember to remove it, since the old node's certificate
remains a valid authorized source for as long as it has not expired.

## The drift check (zonedns-drift)

The above are pairs of settings between the two ends; there is another pair that
lives not between the ends but in **the deployment contract**: a workload's
external name is written both in the pod's `zonedns.io/host` label and in the
Istio VirtualService's `hosts:`. The former becomes the dns_name of the SPIRE
entry through the `ClusterSPIFFEID`'s `dnsNameTemplates`, and therefore the key of
central's registry; the latter determines the name clients actually query.

**When they drift, nothing raises an error.** Central cannot find the name in the
registry, treats it as not its own and hands it downstream — queries keep
returning answers while that service silently loses zone routing. There is no
SERVFAIL and no alert: `unauthorized_agent` does not move,
`upstream_errors_total` does not move, because both ends are working perfectly
well and simply talking about different names.

```bash
go run ./cmd/zonedns-drift --show-skipped
```

| Exit code | Meaning | What to do |
|---|---|---|
| 0 | No drift | — |
| 1 | Drift found | Fix the label or the VirtualService per the report |
| 2 | The check failed | Fix that and re-run — **this is not "no drift"** |

The report has two directions:

- **VirtualService hosts no pod claims** — the dangerous side. Clients query this
  name, the registry does not have it, and so it never receives the correct
  cross-zone answer.
- **Pod labels no VirtualService declares** — one more registry entry nobody
  queries. Usually a typo, or a rename where one side was missed; harmless in
  itself, but it almost always accompanies the first kind.

A rename is the most typical trigger: change the VirtualService and forget the
label, or the other way round, and one change produces an entry in both
directions at once.

### When to run it

- **In CI**: against a staging cluster, with exit code 1 blocking the deployment.
- **As a CronJob**: hourly against production. Drift is nearly always something a
  person introduced, and it does not heal on its own.

Permissions needed to run inside the cluster — cluster-wide `list`:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: zonedns-drift
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["list"]
  - apiGroups: ["networking.istio.io"]
    resources: ["virtualservices"]
    verbs: ["list"]
```

With insufficient permission the tool fails with exit code 2 and prints the
original Forbidden error, which is neither mistaken for "Istio's CRD is not
installed" nor passed off as a clean report.

`--namespace` narrows the check to a single namespace. **Do not use it for real
checks**: Istio lets a VirtualService in namespace A point at a service in
namespace B, and scoping reports that arrangement as "no pod claims it". It
exists for testing and deliberately scoped checks.

### What it does not check

Names only. Names matching on both sides **can still point at the wrong
workload** — verifying that would mean tracing the route from VirtualService to
destination Service to pod, the Istio traversal approach considered and rejected
during design (see design doc §9, limitation 2). The tool prints this sentence in
every report, so a clean one cannot be read as "correctly configured".
