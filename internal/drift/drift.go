// Package drift 比對兩份各自獨立宣告的服務名稱，找出它們的分歧。
//
// 設計上，一個 workload 的對外名稱被寫在兩個地方：pod 的 zonedns.io/host label
// （它會變成 SPIRE registration entry 的 dns_name，也就是 central registry 的
// key），以及 Istio VirtualService 的 spec.hosts（client 實際查詢的名字）。
// 兩者是同一個事實的兩份宣告，沒有任何機制保證它們一致。
//
// 漂移的後果不會報錯：client 查的名字不在 registry 裡，central 就把它當成
// 「不歸我管」而交給下游，於是那個服務永遠拿不到 zone 路由 —— 查詢照常有答案。
// 設計文件（§9 已知限制 2）把「需要比對檢查防漂移」列為前提，這個套件就是它。
package drift

import "sort"

// Report 是一次比對的結果。
type Report struct {
	// UnclaimedHosts 是 VirtualService 宣告、但沒有任何 pod 以 zonedns.io/host
	// 認領的名稱。這是危險的一邊：client 會查它，registry 沒有它。
	UnclaimedHosts []string

	// UnroutedLabels 是 pod 標了、但沒有任何 VirtualService 宣告的名稱。
	// 多半是打錯字或殘留設定 —— registry 裡有一筆沒人會查的資料。
	UnroutedLabels []string
}

// OK 回報有沒有漂移。
func (r Report) OK() bool {
	return len(r.UnclaimedHosts) == 0 && len(r.UnroutedLabels) == 0
}

// Compare 比對兩組名稱。
//
// 呼叫端負責先篩掉不該參與比對的 VirtualService（綁在 gateway 而非 mesh 的、
// 萬用 host），因為那些判斷需要 Istio 的語意，而這裡只做集合運算。
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
