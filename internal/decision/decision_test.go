package decision

import (
	"net/netip"
	"testing"
)

var gwA = netip.MustParseAddr("203.0.113.10")

// gateways 模擬 zonetable：只有 zone-a 有 gateway 設定。
func gateways(zone string) (netip.Addr, bool) {
	if zone == "zone-a" {
		return gwA, true
	}
	return netip.Addr{}, false
}

func TestDecideTable(t *testing.T) {
	tests := []struct {
		name string
		in   Input
		want Decision
	}{
		{
			"same zone passes through",
			Input{SourceZone: "zone-a", SourceOK: true, DestZone: "zone-a", DestOK: true},
			Decision{Action: ActionPassThrough},
		},
		{
			"cross zone answers gateway",
			Input{SourceZone: "zone-b", SourceOK: true, DestZone: "zone-a", DestOK: true},
			Decision{Action: ActionAnswerGateway, Gateway: gwA},
		},
		{
			"dest not in registry passes through",
			Input{SourceZone: "zone-b", SourceOK: true, DestOK: false},
			Decision{Action: ActionPassThrough},
		},
		{
			"cross zone without gateway config servfails",
			Input{SourceZone: "zone-a", SourceOK: true, DestZone: "zone-z", DestOK: true},
			Decision{Action: ActionServFail},
		},
		{
			"unknown source passes through even when dest is known",
			Input{SourceOK: false, DestZone: "zone-a", DestOK: true},
			Decision{Action: ActionPassThrough},
		},
		{
			"unknown source passes through when dest unknown too",
			Input{SourceOK: false, DestOK: false},
			Decision{Action: ActionPassThrough},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Decide(tt.in, gateways)
			if got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

// Action.String() 的輸出是 Prometheus metric decision_total 的 action label
// value；調整 iota 順序會在不知不覺間改名 metric，並讓 docs/deployment.md
// 要求的 action="servfail" 告警（唯一會抓到「zone 缺 gateway 設定」的告警）
// 悄悄失效。每個常數的字串都要單獨鎖住，外加一個 out-of-range 值鎖住 default
// 分支 —— internal/identity 的 Reason.String() 已有這個測試，這是缺的另一半。
func TestActionString(t *testing.T) {
	cases := []struct {
		action Action
		want   string
	}{
		{ActionPassThrough, "passthrough"},
		{ActionAnswerGateway, "gateway"},
		{ActionServFail, "servfail"},
		{Action(999), "unknown"},
	}
	for _, c := range cases {
		if got := c.action.String(); got != c.want {
			t.Fatalf("Action(%d).String() = %q, want %q", c.action, got, c.want)
		}
	}
}

// 同 zone 不查 gateway 表 — 若查了，未設定 gateway 的 zone 會誤觸 SERVFAIL。
func TestSameZoneDoesNotConsultGatewayTable(t *testing.T) {
	called := false
	gw := func(string) (netip.Addr, bool) {
		called = true
		return netip.Addr{}, false
	}
	in := Input{SourceZone: "zone-z", SourceOK: true, DestZone: "zone-z", DestOK: true}
	if got := Decide(in, gw); got.Action != ActionPassThrough {
		t.Fatalf("got %v, want ActionPassThrough", got.Action)
	}
	if called {
		t.Fatal("gateway table consulted on the same-zone path")
	}
}
