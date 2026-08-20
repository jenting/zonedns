package integration

import (
	"testing"

	"github.com/coredns/coredns/plugin/pkg/doh"
	"github.com/jenting/zonedns/internal/ednszone"
	"github.com/miekg/dns"
)

// answerIP 取出回應裡第一筆 A 記錄的位址；沒有 A 記錄時回空字串。
func answerIP(m *dns.Msg) string {
	if m == nil {
		return ""
	}
	for _, rr := range m.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A.String()
		}
	}
	return ""
}

// 跨 zone：agent 宣告 zone-b，registry 說 payments 在 zone-a，client 應得
// zone-a 的 gateway，且不該落到下游。
func TestCrossZoneReturnsDestinationGateway(t *testing.T) {
	s := newStack(t, defaults())

	_, got := s.query(t, "payments.example.com.", dns.TypeA, "10.1.0.5")

	if ip := answerIP(got); ip != zoneAGateway {
		t.Fatalf("answer = %q, want %q", ip, zoneAGateway)
	}
	if s.downstream.called {
		t.Fatal("跨 zone 的查詢不該落到下游")
	}
}

// 同 zone：agent 宣告 zone-b，orders 也在 zone-b，應交給下游而不是回 gateway。
func TestSameZonePassesThrough(t *testing.T) {
	s := newStack(t, defaults())

	_, got := s.query(t, "orders.example.com.", dns.TypeA, "10.1.0.5")

	if !s.downstream.called {
		t.Fatal("同 zone 的查詢應該落到下游")
	}
	if ip := answerIP(got); ip == zoneAGateway || ip == zoneBGateway {
		t.Fatalf("同 zone 卻拿到 gateway 位址 %q", ip)
	}
}

// 同一個名字、兩個不同的宣告 zone，必須得到不同答案。這是整個系統存在的理由，
// 而且是唯一需要兩端都參與才能驗證的斷言。
func TestSameNameDifferentZonesDiffer(t *testing.T) {
	crossing := newStack(t, defaults()) // zone-b 問 zone-a 的名字
	_, crossMsg := crossing.query(t, "payments.example.com.", dns.TypeA, "10.1.0.5")
	crossGot := answerIP(crossMsg)

	optSame := defaults()
	optSame.agentZone = "zone-a" // 同 zone
	sameZone := newStack(t, optSame)
	_, sameMsg := sameZone.query(t, "payments.example.com.", dns.TypeA, "10.1.0.5")
	sameGot := answerIP(sameMsg)

	if crossGot != zoneAGateway {
		t.Fatalf("跨 zone answer = %q, want %q", crossGot, zoneAGateway)
	}
	if sameGot != downstreamIP {
		t.Fatalf("同 zone answer = %q, want %q", sameGot, downstreamIP)
	}
	if crossGot == sameGot {
		t.Fatal("兩個 zone 拿到相同答案 —— zone 判定沒有生效")
	}
}

// 兩端的 edns0_code 不一致：central 讀不到宣告，靜默退回非 zone-aware。
//
// 這個失效只有兩端一起才看得見 —— 節點端正確地送出了宣告，中心端正確地在自己
// 設定的 code 上找不到東西，兩邊各自都沒有錯。最終審查是靠讀兩邊的設定發現的，
// 這個測試讓它變成可執行的斷言。
func TestMismatchedOptionCodeSilentlyDisablesZoneRouting(t *testing.T) {
	opt := defaults()
	opt.agentEDNS0Code = 65001
	opt.centralCode = 65002
	s := newStack(t, opt)

	rcode, got := s.query(t, "payments.example.com.", dns.TypeA, "10.1.0.5")

	if !s.downstream.called {
		t.Fatal("code 不一致時應退回非 zone-aware 路徑（落到下游）")
	}
	if ip := answerIP(got); ip == zoneAGateway {
		t.Fatal("code 不一致卻仍走了 zone 路由")
	}
	// 也確認它確實是「安靜地」失敗：client 拿到的是正常回應，不是錯誤。
	if rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s，這個失效的特徵就是不會報錯", dns.RcodeToString[rcode])
	}
}

// 未授權的 agent：憑證由同一個 CA 簽發、握手成功，但 SPIFFE ID 不在授權清單，
// 宣告必須被忽略。
func TestUnauthorizedAgentDeclarationIgnored(t *testing.T) {
	opt := defaults()
	opt.clientSPIFFEID = rogueSPIFFEID
	s := newStack(t, opt)

	_, got := s.query(t, "payments.example.com.", dns.TypeA, "10.1.0.5")

	if !s.downstream.called {
		t.Fatal("未授權來源的宣告應被忽略並落到下游")
	}
	if ip := answerIP(got); ip == zoneAGateway {
		t.Fatal("未授權的 agent 竟然取得了跨 zone 的答案")
	}
}

// upstream URL 多帶路徑：DoH 的路徑由函式庫自動附加，多寫一次會變成
// /dns-query/dns-query，central 以 404 拒絕。
//
// 這正是真實部署時踩到的那個 bug。它躲過了所有既有測試，因為那些測試的假伺服器
// 接受任何路徑 —— 所以這裡的 handler 刻意套用跟 CoreDNS 完全相同的路徑檢查。
func TestDoubledDoHPathIsRejected(t *testing.T) {
	opt := defaults()
	opt.upstreamPath = doh.Path
	s := newStack(t, opt)

	rcode, _ := s.query(t, "payments.example.com.", dns.TypeA, "10.1.0.5")

	if s.seenPath != doh.Path+doh.Path {
		t.Fatalf("central 收到的路徑 = %q，want %q", s.seenPath, doh.Path+doh.Path)
	}
	if rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %s, want SERVFAIL —— 上游失敗必須是 SERVFAIL，不可降級成一般答案",
			dns.RcodeToString[rcode])
	}
	if s.downstream.called {
		t.Fatal("上游失敗不該落到下游 —— 那會繞過 zone 路由並回一個看起來正常的答案")
	}
}

// client 自己偽造宣告：agent 必須無條件剝除，central 只能看到 agent 的 zone。
func TestClientForgedDeclarationStrippedOnTheWire(t *testing.T) {
	s := newStack(t, defaults())

	m := new(dns.Msg)
	m.SetQuestion("payments.example.com.", dns.TypeA)
	// client 自稱 zone-a（同 zone），企圖換到直連位址而非 gateway。
	ednszone.Set(m, ednszone.DefaultCode, "zone-a")

	_, got := s.queryMsg(t, m, "10.1.0.5")

	if ip := answerIP(got); ip != zoneAGateway {
		t.Fatalf("answer = %q, want %q —— client 偽造的 zone 影響了結果", ip, zoneAGateway)
	}
	if s.downstream.called {
		t.Fatal("client 偽造的同 zone 宣告被採信了")
	}
}
