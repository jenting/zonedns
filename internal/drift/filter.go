package drift

import "strings"

// SkipReason 說明某個名稱為何不參與比對。空字串代表要比對。
type SkipReason string

const (
	// SkipWildcard：萬用 host 不可能對應到單一 workload 的 label。
	SkipWildcard SkipReason = "wildcard host"

	// SkipGatewayBound：綁在 ingress/egress gateway 而非 mesh 的 VirtualService，
	// 服務的是進出叢集的南北向流量，那些 host 本來就不會有對應的 workload label。
	SkipGatewayBound SkipReason = "bound to a gateway rather than the mesh"

	// SkipShortName：不含點的名稱是 cluster 內部短名（payments），Istio 會把它
	// 補成 FQDN；它不是 client 拿來跨 zone 查詢的名字。
	SkipShortName SkipReason = "short name, not an FQDN"

	// SkipClusterLocal：cluster 內部 FQDN（payments.default.svc.cluster.local）。
	// 同一個服務的 VirtualService 通常會同時列出對外名稱和這種 k8s 原生名稱；
	// 後者永遠不會有 zonedns.io/host label，拿去比對只會產生假警報。
	SkipClusterLocal SkipReason = "cluster-internal name"
)

// DefaultClusterDomain 是 kubernetes 預設的 cluster domain。
const DefaultClusterDomain = "cluster.local"

// ShouldSkipHost 判斷一個 VirtualService host 是否不參與比對。
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

// ShouldSkipVirtualService 依 spec.gateways 判斷整個 VirtualService 是否跳過。
//
// 未設定 gateways 等同 ["mesh"]，也就是 sidecar 之間的流量 —— 那才是本設計
// 涵蓋的範圍。明確列出 gateway 且不含 "mesh" 的，服務的是南北向流量。
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
