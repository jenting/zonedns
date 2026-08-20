// Package drift compares two independently written declarations of a service
// name and reports where they disagree.
//
// By design a workload's external name is written in two places: the pod's
// zonedns.io/host label (which becomes the dns_name of its SPIRE registration
// entry, and therefore the key of the central registry), and the Istio
// VirtualService's spec.hosts (the name clients actually query). They are two
// declarations of the same fact, and nothing keeps them in agreement.
//
// Drift raises no error. The name a client queries is absent from the registry,
// so central treats it as "not mine", hands it downstream, and that service
// silently loses zone routing — the query still returns an answer. The design
// doc (§9, known limitation 2) lists this comparison as a precondition; this
// package is it.
package drift

import "sort"

// Report is the result of one comparison.
type Report struct {
	// UnclaimedHosts are names a VirtualService declares that no pod claims via
	// zonedns.io/host. This is the dangerous direction: clients resolve them,
	// and the registry does not have them.
	UnclaimedHosts []string

	// UnroutedLabels are names labelled on pods that no VirtualService declares.
	// Usually a typo or a leftover — a registry entry nothing ever queries.
	UnroutedLabels []string
}

// OK reports whether there is any drift.
func (r Report) OK() bool {
	return len(r.UnclaimedHosts) == 0 && len(r.UnroutedLabels) == 0
}

// Compare compares the two sets of names.
//
// The caller is responsible for filtering out whatever should not take part
// (VirtualServices bound to a gateway rather than the mesh, wildcard hosts),
// because those judgements need Istio semantics; this function only does set
// arithmetic.
func Compare(virtualServiceHosts, podLabelHosts []string) Report {
	inVS := toSet(virtualServiceHosts)
	inLabel := toSet(podLabelHosts)

	var r Report
	for h := range inVS {
		if _, ok := inLabel[h]; !ok {
			r.UnclaimedHosts = append(r.UnclaimedHosts, h)
		}
	}
	for h := range inLabel {
		if _, ok := inVS[h]; !ok {
			r.UnroutedLabels = append(r.UnroutedLabels, h)
		}
	}
	sort.Strings(r.UnclaimedHosts)
	sort.Strings(r.UnroutedLabels)
	return r
}

func toSet(in []string) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		out[s] = struct{}{}
	}
	return out
}
