# zonedns

Zone-based DNS for mixed Kubernetes and VM environments, built on SPIFFE/SPIRE.

When workloads within one zone talk to each other, the answer is the ordinary
service address; across zones it is the destination zone's gateway VIP. The
asking workload's zone is determined by node-local DNS from the source pod IP and
declared to central over mTLS DoH; the queried name's zone comes from its SPIRE
registration entry.

Zones are isolated at the network layer and cross-zone traffic can only go
through a zone gateway — which is what makes a wrong answer a failure to connect
rather than a policy bypass.

## Documentation

| Document | Contents |
|---|---|
| `docs/superpowers/specs/2026-08-18-zonedns-design.md` | The design, core invariants, threat model and **known limitations** |
| `docs/deployment.md` | Building and deploying both ends, required alerts, settings that must be maintained as a pair |
| `deploy/k8s/` | Directly applyable Kubernetes manifests for the node side |
| `build/` | Two Dockerfiles and the registration file that injects the plugin |
| `Makefile` | The entry point for building, testing, images and the drift check (`make help`) |

Coming to this for the first time, start with §3 of the spec (core invariants)
and §9 (known limitations) — most of this system's failure modes return a
plausible-looking answer rather than an error, and §9 is the list of them.

## Architecture

```
pod ──plain UDP DNS──▶ node-local DNS + zonedns_agent
                          │  source IP → local pod → zone label
                          │  cached under (qname, qtype, zone)
                          ▼  mTLS DoH, zone carried in EDNS0
                      CoreDNS + zonedns (running on a VM)
                          │  the declaration is believed only from a verified agent
                          │  registry: FQDN → zone (polls the SPIRE Entry API)
                          ▼  same zone → downstream; cross zone → the gateway VIP
```

## Deployment precondition

**No device may terminate TLS on the path between an agent and central** — no
L7 ingress, no reverse proxy, no TLS-terminating load balancer. The whole of zone
isolation rests on the client certificate central sees being the agent's own
SVID; the moment something in between terminates TLS, what central sees is that
device's certificate.

(Confirmed with the environment owner on 2026-08-20: this environment will have
no TLS termination on the path to the DNS server.)

This precondition needs no periodic test to maintain it. The runtime verifies it
on every single query:

- **agent → central is stopped by construction** — the agent pins the other
  side's SPIFFE ID with `AuthorizeID(central)`, and a device presenting its own
  certificate fails the handshake outright. This side cannot fail silently.
- **central → agent degrades, but with a signal** —
  `coredns_zonedns_source_zone_total{reason="unauthorized_agent"}` rises.

**The correct response to an `unauthorized_agent` alert is to remove that
unauthorized identity, never to add its SPIFFE ID to `authorized_agent` to make
the alert go away.** After that step the identity can declare any zone it likes,
the whole of the isolation is defeated, and from then on it is entirely silent.
This is the step no code can prevent — the configuration says who is trusted, and
central trusts them.

## Components

**Central side**

| Path | What it does |
|---|---|
| `plugin/zonedns` | The CoreDNS plugin: parses the Corefile, connects to SPIRE Server, decides and responds |
| `internal/identity` | The trust boundary: verifies the agent's identity and reads the source zone declaration |
| `internal/registry` | Polls the SPIRE Entry API and maintains a read-only FQDN → zone snapshot |
| `internal/zonetable` | The zone → gateway VIP configuration |
| `internal/decision` | The core decision table (a pure function, no I/O) |

**Node side**

| Path | What it does |
|---|---|
| `plugin/zonedns_agent` | The CoreDNS plugin: determines the source zone, keys the cache by it, declares it to central |
| `internal/podzone` | Local pod IP → zone (a node-scoped informer) |
| `internal/zonecache` | An answer cache keyed by `(qname, qtype, zone)` |
| `internal/dohupstream` | The mTLS DoH client that pins central's SPIFFE ID |

**Shared**

| Path | What it does |
|---|---|
| `internal/ednszone` | The EDNS0 wire format between the two ends |
| `internal/spiffezone` | Extracts the zone from a SPIFFE ID path |
| `internal/testcerts` | For tests only: throwaway certificates with a given URI SAN, imported only by `_test.go` |

**Tools**

| Path | What it does |
|---|---|
| `cmd/zonedns-drift` | Compares VirtualService `hosts:` against pods' `zonedns.io/host` labels and catches drift between the two declarations |
| `internal/drift` | The comparison and collection logic behind that tool |

The node side and the central side share no code, only the wire format defined by
`internal/ednszone` — how a zone declaration is encoded inside an EDNS0 option.
That is the sole compatibility interface between them. Change the format on
either side alone and the other neither fails to compile nor errors at runtime;
the declared zone simply becomes unreadable and queries fall quietly back to the
non-zone-aware path.

## Building

Both plugins are external CoreDNS plugins, and CoreDNS plugins are **linked at
compile time** with no runtime loading mechanism, so both require rebuilding the
host binary.

- **The central side** compiles into ordinary CoreDNS: add a line to
  `plugin.cfg` (**it must come before `cache`**), then
  `go generate && go build`
- **The node side** compiles into `sigs.k8s.io/node-local-dns`: add a blank
  import and insert `"zonedns_agent"` into `dnsserver.Directives` (**again
  before `cache`**), bearing in mind that the project vendors its dependencies
  and that the build must use `GOOS=linux`

The ordering requirement on both ends is not a preference: the built-in `cache`
plugin keys on `(qname, qtype)` and does not include the asking workload's zone.
If it sorts first, a pod in one zone receives an answer cached for another, with
no sign of it at runtime. Both ends check the order at startup and refuse a wrong
one.

```bash
make images          # both images
make image-central   # the central side only
make image-agent     # the node side only
make help            # every target
```

Both Dockerfiles carry their own self-check: the central one confirms `-plugins`
lists `zonedns`, and the node one feeds in a Corefile containing `zonedns_agent`
to confirm the directive is recognised. A failure stops at build time rather than
becoming an image that looks fine and has no plugin in it.

For the full steps and the reasoning behind the version pins, see
`docs/deployment.md`.

## Tests

```bash
go test ./... -race
```

`internal/identity`'s tests cover a range of bypass attempts — whether zone
isolation holds at all depends on nothing but that package, so read its tests
before changing it. Each end has an end-to-end test proving one name yields
different answers under different source zones: the central side in
`plugin/zonedns/e2e_test.go`, the node side in
`plugin/zonedns_agent/e2e_test.go`, the latter through real DoH wire encoding and
decoding.

### The two-ends integration test

`internal/integration` runs the real `Agent.ServeDNS` through a **real mTLS
handshake** into the real `ZoneDNS.ServeDNS`, substituting neither end's logic.
It covers situations a one-sided test cannot construct: the two ends configured
with different `edns0_code`s, an unauthorized certificate refused in a real
handshake, and a client's forged declaration stripped on the wire.

The fake central there is **deliberately as strict as the real one** — it applies
exactly the path check CoreDNS's DoH server applies. The bug where the `upstream`
URL had `/dns-query` appended twice escaped 16 tasks and two final reviews for
precisely one reason: the test doubles of the time accepted any path. A
permissive double reproduces the very blind spot it exists to prevent.

### Tests that need a real cluster

`internal/podzone/cluster_test.go` sits behind the `cluster` build tag and an
ordinary `go test ./...` does not reach it. CI runs it on a two-node kind
cluster; to reproduce locally:

```bash
kind create cluster --config deploy/kind/two-node.yaml
kubectl apply -f deploy/k8s/01-rbac.yaml
go test -tags=cluster ./internal/podzone/ -run TestCluster -v
```

It verifies what `fake.NewSimpleClientset` structurally cannot: its object
tracker **ignores field selectors**, so "the informer sees only this node's pods"
has never actually happened in any other test. The test connects with that
ServiceAccount's token and uses the real RBAC from
`deploy/k8s/01-rbac.yaml`, so insufficient permissions leave the informer unable
to sync and the test fails.

Two nodes are required: a single-node cluster cannot prove the scoping really
took effect.

`internal/drift/cluster_test.go` sits behind the same `cluster` tag and needs a
cluster with the Istio CRDs installed:

```bash
kind create cluster
make istio-crds
make test-drift
```

It verifies what the fake dynamic client structurally cannot: that fake
**validates nothing about the GVR** — a wrong group, a wrong resource plural, a
wrong version, and it lists happily all the same. Which means "this tool can
actually read VirtualServices" has never been proven by any unit test, and it is
the premise of the whole check: not being able to read them looks exactly like
having no drift, a nice clean report.

## The drift check

This design writes a workload's external name twice — the pod's
`zonedns.io/host` label determines the dns_name of its SPIRE entry, and therefore
the key of central's registry, while the Istio VirtualService's `hosts:`
determines the name clients actually query. **When the two declarations drift,
nothing raises an error**: central cannot find the name, treats it as not its
own, hands it downstream, and that service silently loses zone routing while DNS
queries keep returning answers.

```bash
make drift              # using the current kubeconfig
go run ./cmd/zonedns-drift --show-skipped
```

| Exit code | Meaning |
|---|---|
| 0 | No drift |
| 1 | Drift found |
| 2 | The check itself failed (cannot connect, insufficient permission, no Istio CRD) |

Exit code 2 is deliberately kept apart from 0: if a cluster with no Istio CRD and
a cluster with no drift both printed "clean", this tool would fall silent at
exactly the moment it most needs to speak.

Three kinds of name are excluded before the comparison, and `--show-skipped`
lists them with the reason: wildcard hosts, cluster-internal names (short names
and `*.svc.cluster.local`), and VirtualServices bound to a gateway rather than
the mesh. None of them can have a corresponding workload label, and comparing
them would only manufacture false alarms.

**This check compares names only.** Names matching on both sides can still point
at the wrong workload — verifying that would mean tracing the route from
VirtualService to destination Service to pod, the Istio traversal approach
considered and rejected during design. The tool prints that boundary in its own
output.

Permissions needed to run inside the cluster, as a CronJob: cluster-wide `list`
on `pods` and on `networking.istio.io`'s `virtualservices`.

`--namespace` narrows the check to a single namespace, but **it narrows
correctness with it**: Istio lets a VirtualService in namespace A point at a
service in namespace B, and scoping reports that arrangement as "no pod claims
it". Its purpose is testing and deliberately scoped checks; for real use keep the
default of the whole cluster.

## CI

`.github/workflows/ci.yaml` has five jobs. Each corresponds to something a unit
test structurally cannot prove:

| Job | What it proves |
|---|---|
| `test` | Formatting, `go vet`, `go build`, `go mod tidy` being a no-op, `go test -race` |
| `plugin-link` | Both plugins really link into the host binary and register; and separately, that a binary built in the **wrong order** really is refused at startup |
| `manifests` | `deploy/k8s/*.yaml` pass a server-side dry-run against a real API server, with the real `ClusterSPIFFEID` CRD installed — without the CRD a mistyped field name sails through as valid YAML |
| `informer` | On a two-node kind cluster, the `spec.nodeName` field selector really scopes to this machine, and the permissions in `deploy/k8s/01-rbac.yaml` really suffice |
| `drift` | The drift check runs against a real Istio CRD, all three exit codes are correct, and the report **names names** |

`tidy-check` is not fastidiousness: the CoreDNS version must match upstream
node-local-dns and the Kubernetes libraries must sit on the same line, or the
agent plugin will not link. Those pins are held by this job alone.

`plugin-link` and `drift` both deliberately include a **reverse check** — build
something that should fail, and confirm it really does. Verify only the success
path and a check that always passes looks exactly like a correct one.

## Current state

**Working**: both plugins and the interface between them, the node side's
Kubernetes manifests, both Dockerfiles and the Makefile, the drift check tool,
and the five CI jobs above.

**Not done yet**:

| Item | Consequence |
|---|---|
| VM-side deployment artifacts for central | Central runs on a VM, but the repo holds only the prose in `docs/deployment.md` — no systemd unit, no directly applyable file of any kind |
| `PrometheusRule` | The required alerts are listed in `docs/deployment.md`, but there is no applyable rule file — for now they have to be built by hand from the list |
| The tail of spec §11, item 2 | Whether any `Sidecar` resource overrides a namespace to `REGISTRY_ONLY`. If one does, cross-zone traffic breaks within that scope while working everywhere else |
| Spec §11, item 4 | CoreDNS's support for multiple `bind` server blocks — needed only if per-zone addresses are ever brought back |

There are also a handful of recorded but unaddressed minor issues, such as
`podzone.Run` not being re-entrant (calling it twice builds a second informer)
and `zonecache` caching responses that are unsuccessful but carry answers.
Neither is reachable given how they are currently used.
