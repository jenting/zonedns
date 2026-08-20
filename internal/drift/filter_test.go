package drift

import "testing"

func TestShouldSkipHost(t *testing.T) {
	tests := []struct {
		name string
		host string
		want SkipReason
	}{
		{"對外 FQDN 要比對", "payments.example.com", ""},
		{"萬用 host", "*.example.com", SkipWildcard},
		{"單獨的萬用字元", "*", SkipWildcard},
		{"cluster 短名", "payments", SkipShortName},
		{"cluster 內部 FQDN", "payments.default.svc.cluster.local", SkipClusterLocal},
		{"帶結尾點的 cluster domain 也要認得", "payments.default.svc.cluster.local", SkipClusterLocal},
		// 尾綴比對必須以點為界，否則 notcluster.local 這種對外名稱會被誤判成
		// 內部名稱而靜靜地不比對 —— 漏掉的正是我們要抓的漂移。
		{"只是尾巴長得像的對外名稱", "notcluster.local", ""},
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
	// 換了 cluster domain 之後，預設的那個就只是一個普通對外名稱了。
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
		{"未設定等同 mesh", nil, ""},
		{"空 slice 等同 mesh", []string{}, ""},
		{"明確寫 mesh", []string{"mesh"}, ""},
		{"同時服務 gateway 和 mesh", []string{"istio-ingressgateway", "mesh"}, ""},
		{"只綁 ingress gateway", []string{"istio-ingressgateway"}, SkipGatewayBound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ShouldSkipVirtualService(tc.gateways); got != tc.want {
				t.Errorf("ShouldSkipVirtualService(%v) = %q, want %q", tc.gateways, got, tc.want)
			}
		})
	}
}
