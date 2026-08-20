package drift

import "testing"

func TestShouldSkipHost(t *testing.T) {
	tests := []struct {
		name string
		host string
		want SkipReason
	}{
		{"external FQDN is compared", "payments.example.com", ""},
		{"wildcard host", "*.example.com", SkipWildcard},
		{"bare wildcard", "*", SkipWildcard},
		{"cluster short name", "payments", SkipShortName},
		{"cluster-internal FQDN", "payments.default.svc.cluster.local", SkipClusterLocal},
		{"cluster domain with a trailing dot is recognised too", "payments.default.svc.cluster.local", SkipClusterLocal},
		// The suffix match must be bounded by a dot. Otherwise an external name
		// like notcluster.local is mistaken for an internal one and quietly
		// dropped from the comparison — losing exactly the drift we are after.
		{"external name that merely looks like the suffix", "notcluster.local", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ShouldSkipHost(tc.host, DefaultClusterDomain); got != tc.want {
				t.Errorf("ShouldSkipHost(%q) = %q, want %q", tc.host, got, tc.want)
			}
		})
	}
}

func TestShouldSkipHostCustomClusterDomain(t *testing.T) {
	if got := ShouldSkipHost("payments.default.svc.k8s.internal", "k8s.internal"); got != SkipClusterLocal {
		t.Errorf("got %q, want %q", got, SkipClusterLocal)
	}
	// Once the cluster domain changes, the default one is just an ordinary
	// external name.
	if got := ShouldSkipHost("payments.default.svc.cluster.local", "k8s.internal"); got != "" {
		t.Errorf("got %q, want no skip", got)
	}
}

func TestShouldSkipHostTrailingDotInClusterDomain(t *testing.T) {
	if got := ShouldSkipHost("payments.default.svc.cluster.local", "cluster.local."); got != SkipClusterLocal {
		t.Errorf("got %q, want %q", got, SkipClusterLocal)
	}
}

func TestShouldSkipVirtualService(t *testing.T) {
	tests := []struct {
		name     string
		gateways []string
		want     SkipReason
	}{
		{"unset means mesh", nil, ""},
		{"empty slice means mesh", []string{}, ""},
		{"mesh named explicitly", []string{"mesh"}, ""},
		{"serves both a gateway and the mesh", []string{"istio-ingressgateway", "mesh"}, ""},
		{"bound to an ingress gateway only", []string{"istio-ingressgateway"}, SkipGatewayBound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ShouldSkipVirtualService(tc.gateways); got != tc.want {
				t.Errorf("ShouldSkipVirtualService(%v) = %q, want %q", tc.gateways, got, tc.want)
			}
		})
	}
}
