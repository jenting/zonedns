package zonedns_agent

import "net/netip"

// ZoneResolver determines the asking workload's zone from a query's source
// address.
//
// It is an interface because the two deployments determine it in fundamentally
// different ways: on Kubernetes every pod has its own IP and one node can mix
// several zones, so each query must be judged on its own; on a VM the whole
// machine belongs to one zone, settled once at startup.
type ZoneResolver interface {
	// Zone returns the zone a source address belongs to. An unrecognised source
	// returns ok=false, and the caller must take that as "declare no zone" rather
	// than guess one.
	Zone(src netip.Addr) (zone string, ok bool)
}

// StaticResolver is the VM-mode resolver: one zone for the whole machine,
// independent of the source address.
type StaticResolver struct {
	zone string
}

// NewStaticResolver builds a resolver that always returns zone.
func NewStaticResolver(zone string) StaticResolver {
	return StaticResolver{zone: zone}
}

// Zone implements ZoneResolver.
func (s StaticResolver) Zone(netip.Addr) (string, bool) {
	if s.zone == "" {
		return "", false
	}
	return s.zone, true
}
