package drift

import "strings"

// SkipReason explains why a name takes no part in the comparison. An empty
// string means it does.
type SkipReason string

const (
	// SkipWildcard: a wildcard host cannot correspond to a single workload's label.
	SkipWildcard SkipReason = "wildcard host"

	// SkipGatewayBound: a VirtualService bound to an ingress/egress gateway
	// rather than the mesh serves north-south traffic into and out of the
	// cluster, and those hosts were never going to carry a workload label.
	SkipGatewayBound SkipReason = "bound to a gateway rather than the mesh"

	// SkipShortName: a name with no dot is a cluster-internal short name
	// (payments), which Istio expands into an FQDN. It is not the name a client
	// uses for a cross-zone lookup.
	SkipShortName SkipReason = "short name, not an FQDN"

	// SkipClusterLocal: a cluster-internal FQDN
	// (payments.default.svc.cluster.local). A service's VirtualService commonly
	// lists both its external name and this Kubernetes-native one; the latter
	// never carries a zonedns.io/host label, so comparing it only produces
	// false alarms.
	SkipClusterLocal SkipReason = "cluster-internal name"
)

// DefaultClusterDomain is Kubernetes's default cluster domain.
const DefaultClusterDomain = "cluster.local"

// ShouldSkipHost decides whether a VirtualService host takes part in the
// comparison.
func ShouldSkipHost(host, clusterDomain string) SkipReason {
	if strings.HasPrefix(host, "*") {
		return SkipWildcard
	}
	if !strings.Contains(host, ".") {
		return SkipShortName
	}
	if clusterDomain != "" && strings.HasSuffix(host, "."+strings.TrimSuffix(clusterDomain, ".")) {
		return SkipClusterLocal
	}
	return ""
}

// ShouldSkipVirtualService decides from spec.gateways whether to skip a whole
// VirtualService.
//
// An unset gateways field is equivalent to ["mesh"], meaning sidecar-to-sidecar
// traffic — which is what this design covers. One that names gateways
// explicitly without including "mesh" serves north-south traffic.
func ShouldSkipVirtualService(gateways []string) SkipReason {
	if len(gateways) == 0 {
		return ""
	}
	for _, g := range gateways {
		if g == "mesh" {
			return ""
		}
	}
	return SkipGatewayBound
}
