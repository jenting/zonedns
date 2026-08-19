package zonedns

import (
	"context"
	"net/netip"
	"testing"

	"github.com/jenting/zonedns/internal/ednszone"
	"github.com/jenting/zonedns/internal/identity"
	"github.com/jenting/zonedns/internal/registry"
	"github.com/jenting/zonedns/internal/zonetable"
	"github.com/miekg/dns"
)

// 本檔案涵蓋 Task 10 要求的兩個端到端情境。
//
// 情境一（DoH 全路徑：agent 憑證 → context 中的 *http.Request → EDNS0 宣告 →
// registry 查詢 → gateway 答案）已由 zonedns_test.go 的
// TestServeDNSDoHCrossZoneAnswersGateway 逐步驗證過 —— 它同樣以
// testcerts.New 建立 agent 憑證、把它掛進 *http.Request.TLS、經
// dnsserver.HTTPRequestKey{} 放進 ctx、宣告 EDNS0 zone、再檢查回應是
// gateway VIP 而非下游答案，與情境一並無實質差異，因此這裡不重覆整套建構。
//
// 情境二（本檔案的 TestEndToEndSameNameDifferentZones）沒有既有測試以「同一份
// registry、只有 source zone 不同」的方式把兩個結果放在一起斷言 ——
// TestServeDNSSameZonePassesThrough 與 TestServeDNSCrossZoneAnswersGateway
// 各自驗證了其中一半，但都是各自呼叫 newHandler 建出獨立的 store，不是同一個
// store 實例。這是整套設計唯一存在的理由，值得單獨、明確地驗證一次。

// TestEndToEndSameNameDifferentZones 驗證：同一個 FQDN、同一份 registry
// snapshot、同一份 zone table，只因為發問 agent 宣告的 source zone 不同，
// 就得到完全不同的答案 —— zone-a 的 client 拿到下游的一般答案，zone-b 的
// client 拿到 zone-a 的 gateway VIP 且完全不落到下游。
func TestEndToEndSameNameDifferentZones(t *testing.T) {
	store := registry.NewStore()
	snap, _ := registry.BuildSnapshot([]registry.Entry{
		{SPIFFEIDPath: "/zone/zone-a/ns/prod/sa/payments", DNSNames: []string{"payments.example.com"}},
	})
	store.Replace(snap)

	zones := zonetable.New(map[string]netip.Addr{"zone-a": netip.MustParseAddr("203.0.113.10")})

	// build 讓兩個 client 共用同一個 store 與 zone table，只有 Next 不同 ——
	// 確保下面兩段斷言真的是在比較「同一份 registry 對不同 source zone 的
	// 反應」，而不是意外地比較兩份內容相同但實例不同的 registry。
	build := func(next *nextCalled) ZoneDNS {
		return ZoneDNS{
			Next:     next,
			Identity: identity.NewConfig([]string{testAgentID}, ednszone.DefaultCode),
			Registry: store,
			Zones:    zones,
			TTL:      30,
		}
	}

	// zone-a 的 client：與 payments.example.com 同 zone，交給下游回一般答案。
	nextA := &nextCalled{}
	rA, wA := newRequest(t, "payments.example.com.", dns.TypeA, "zone-a")
	if _, err := build(nextA).ServeDNS(context.Background(), wA, rA); err != nil {
		t.Fatalf("zone-a: ServeDNS: %v", err)
	}
	if !nextA.called {
		t.Fatal("zone-a client should have reached the next plugin (same zone as payments.example.com)")
	}
	if a, isA := wA.Msg.Answer[0].(*dns.A); !isA || a.A.String() != "10.96.0.7" {
		t.Fatalf("zone-a answer = %v, want the next plugin's normal answer 10.96.0.7", wA.Msg.Answer)
	}

	// zone-b 的 client：跨 zone，直接回 payments.example.com 所屬 zone（zone-a）
	// 的 gateway VIP，不能落到下游。
	nextB := &nextCalled{}
	rB, wB := newRequest(t, "payments.example.com.", dns.TypeA, "zone-b")
	if _, err := build(nextB).ServeDNS(context.Background(), wB, rB); err != nil {
		t.Fatalf("zone-b: ServeDNS: %v", err)
	}
	if nextB.called {
		t.Fatal("zone-b client (cross zone) must not reach the next plugin")
	}
	a, isA := wB.Msg.Answer[0].(*dns.A)
	if !isA || a.A.String() != "203.0.113.10" {
		t.Fatalf("zone-b answer = %v, want the zone-a gateway 203.0.113.10", wB.Msg.Answer)
	}
}
