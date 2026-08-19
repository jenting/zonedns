package zonedns_agent

import "net/netip"

// ZoneResolver 從查詢的來源位址判定發問 workload 的 zone。
//
// 抽成介面是因為 k8s 與 VM 兩種部署的判定方式本質不同：k8s 上每個 pod 有自己的 IP
// 且同節點可混多個 zone，所以要逐查詢判斷；VM 上整台機器屬於同一個 zone，開機時
// 決定一次即可。
type ZoneResolver interface {
	// Zone 回傳該來源位址所屬的 zone。認不出來時回 ok=false —— 呼叫端必須把它
	// 當成「不宣告 zone」，而不是猜一個。
	Zone(src netip.Addr) (zone string, ok bool)
}

// StaticResolver 是 VM 模式的解析器：整台機器一個 zone，與來源位址無關。
type StaticResolver struct {
	zone string
}

// NewStaticResolver 建立固定回傳 zone 的解析器。
func NewStaticResolver(zone string) StaticResolver {
	return StaticResolver{zone: zone}
}

// Zone 實作 ZoneResolver。
func (s StaticResolver) Zone(netip.Addr) (string, bool) {
	if s.zone == "" {
		return "", false
	}
	return s.zone, true
}
