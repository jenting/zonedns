// Package decision 實作 zonedns 的核心決策邏輯（spec §6.4）。
//
// 刻意做成無 I/O 的純函式：所有外部狀態都由呼叫端先查好再傳進來。這讓決策表可以
// 被窮舉測試，也讓「什麼情況該做什麼」這件事集中在一個地方，不散落在 ServeDNS 裡。
package decision

import "net/netip"

// Action 是決策結果要採取的動作。
type Action int

const (
	// ActionPassThrough 把查詢交給 plugin chain 的下一個 plugin。
	ActionPassThrough Action = iota
	// ActionAnswerGateway 直接以 zone gateway VIP 回答。
	ActionAnswerGateway
	// ActionServFail 回 SERVFAIL。
	ActionServFail
)

func (a Action) String() string {
	switch a {
	case ActionPassThrough:
		return "passthrough"
	case ActionAnswerGateway:
		return "gateway"
	case ActionServFail:
		return "servfail"
	default:
		return "unknown"
	}
}

// Input 是做決策所需的全部資訊。
type Input struct {
	SourceZone string
	SourceOK   bool // 是否成功取得可信的 source zone
	DestZone   string
	DestOK     bool // 該 FQDN 是否在 registry 中
}

// Decision 是決策結果。Gateway 只在 Action 為 ActionAnswerGateway 時有意義。
type Decision struct {
	Action  Action
	Gateway netip.Addr
}

// Decide 實作 spec §6.4 的決策表。
//
// gateway 是 zone 到 gateway VIP 的查詢函式（通常是 zonetable.Table.Gateway）。
func Decide(in Input, gateway func(string) (netip.Addr, bool)) Decision {
	// source zone 未知 — 這是非 zone-aware 的正常路徑，不是錯誤。
	if !in.SourceOK {
		return Decision{Action: ActionPassThrough}
	}
	// 這個名字不歸我們管（例如外部網域）。
	if !in.DestOK {
		return Decision{Action: ActionPassThrough}
	}
	// 同 zone — 交給下游回一般答案。刻意不查 gateway 表：同 zone 根本不需要
	// gateway，若查了，未設定 gateway 的 zone 會在自己人互打時誤觸 SERVFAIL。
	if in.DestZone == in.SourceZone {
		return Decision{Action: ActionPassThrough}
	}
	// 跨 zone — 必須有 gateway 設定。
	gw, ok := gateway(in.DestZone)
	if !ok {
		// registry 說這個 zone 存在，但設定檔沒有它的 gateway。這是設定漏掉，
		// 靜默回一般答案等於無聲破壞 zone 隔離，因此刻意不 fail-open。
		return Decision{Action: ActionServFail}
	}
	return Decision{Action: ActionAnswerGateway, Gateway: gw}
}
