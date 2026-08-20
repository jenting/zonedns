# zonedns node-side Kubernetes deployment

These are the complete manifests for node-local-dns with `zonedns_agent`. The
central side (`zonedns`) is not here — it is deployed on a VM; see
`docs/deployment.md`.

## Apply order

```bash
kubectl apply -f 01-rbac.yaml
kubectl apply -f 02-configmap.yaml
kubectl apply -f 03-daemonset.yaml
kubectl apply -f 04-clusterspiffeid.yaml   # needs spire-controller-manager's CRD
```

## Values you must replace

The manifests deliberately leave places to fill in per environment, all
collected in this table.

| File | Where | Replace with |
|---|---|---|
| `02-configmap.yaml` | `example.com:53 {` | The domain your VirtualService `hosts:` actually use. Only queries landing in this block take the zone-routed path |
| `02-configmap.yaml` | `upstream` | Central's address, **without a path** |
| `02-configmap.yaml` | `central_spiffe_id` | Central's own SPIFFE ID |
| `02-configmap.yaml` | `workload_api` | The path at which the SPIRE agent exposes its socket on the node |
| `02-configmap.yaml` | `zone_label` | If it is not `zone` |
| `03-daemonset.yaml` | `image` | Your self-built image (see below) |
| `03-daemonset.yaml` | `hostPath` of `spire-agent-socket` | The same as `workload_api`; the two must agree |
| `04-clusterspiffeid.yaml` | The trust domain in both `spiffeIDTemplate`s | Your trust domain |

The `__PILLAR__*` placeholders are kept per upstream convention and are
substituted by your existing node-local-dns installation flow. If you apply an
already-substituted version directly, replace them with the real values.

## Building the image

Upstream's `k8s-dns-node-cache` does not contain `zonedns_agent` — CoreDNS
plugins are linked at compile time and there is no runtime loading mechanism.
For the build steps see "Node side (agent) deployment → Building" in
`docs/deployment.md`.

The key point: when inserting `zonedns_agent` into `plugin.cfg` it **must sort
before `cache`**, or the plugin refuses to start and says why.

## What this manifest changes relative to upstream

Three things only; everything else follows `kubernetes/kubernetes`'s
`cluster/addons/dns/nodelocaldns/nodelocaldns.yaml` exactly:

1. **image** points at the self-built version
2. **RBAC**: upstream's ServiceAccount holds no permissions; this adds
   `get`/`list`/`watch` on pods, so the informer can map a query's source IP to
   the pod's zone label
3. **Two extra mounts and two extra environment variables on the DaemonSet**:
   SPIRE's Workload API socket, plus `NODE_NAME` and `NODE_IP`

Present upstream already and none of it optional: `hostNetwork`,
`dnsPolicy: Default`, `priorityClassName`, both `-localip` addresses, the
`xtables-lock` mount, the `NET_ADMIN` capability, and tolerations covering every
taint. None of that concerns zone routing; it is what node-local-dns requires to
manage its dummy interface and iptables rules.

## Settings that must be maintained as a pair

Miss either side and zone routing **stops working silently** — queries still
return answers, they just stop distinguishing zones.

- The node SPIFFE ID produced by `04-clusterspiffeid.yaml` must appear verbatim
  in the `authorized_agent` list of central's Corefile
- Central's SPIFFE ID must be the local Corefile's `central_spiffe_id`
- Both ends' `edns0_code` must be identical
- The local `zone_label` must be the same label that
  `04-clusterspiffeid.yaml`'s `spiffeIDTemplate` reads

## Verification

Whether the RBAC took effect:

```bash
kubectl auth can-i list pods \
  --as=system:serviceaccount:kube-system:node-local-dns
```

Whether zone resolution is working (on any node):

```bash
kubectl -n kube-system exec ds/node-local-dns -- \
  wget -qO- http://127.0.0.1:9253/metrics | grep zonedns_agent
```

Any non-zero growth in `zone_resolution_total{result="node_ip"}` means something
on the node is rewriting queries' source IPs, and the whole node silently
degrades to declaring no zone at all. For the full list of alerts see
`docs/deployment.md`.

## Known limitations

- **RBAC cannot be scoped to a single node.** The informer filters by
  `spec.nodeName` and in practice reads only the few dozen pods on this machine,
  but the permission granted is cluster-wide read access to pods. That is worth
  putting in front of a security review before adoption.
- **hostNetwork pods cannot be identified.** Their source IP is the node IP,
  shared by every hostNetwork pod on the node, so they always fall back to the
  non-zone-aware path (spec §9, known limitation 4).
- **A workload may have exactly one external FQDN** (spec §9, known
  limitation 1).
