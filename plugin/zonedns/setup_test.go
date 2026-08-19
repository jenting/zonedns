package zonedns

import (
	"strings"
	"testing"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin/pkg/transport"
)

func TestCheckDirectiveOrder(t *testing.T) {
	if err := CheckDirectiveOrder([]string{"zonedns", "cache", "forward"}); err != nil {
		t.Fatalf("valid order rejected: %v", err)
	}
}

// 順序錯誤必須是啟動失敗，不能只是警告 —— cache 排在前面時，跨 zone 的 client
// 會拿到別人快取的同 zone 答案，而這在執行期沒有任何徵兆。
func TestCheckDirectiveOrderRejectsCacheFirst(t *testing.T) {
	err := CheckDirectiveOrder([]string{"cache", "zonedns", "forward"})
	if err == nil {
		t.Fatal("expected error when cache precedes zonedns")
	}
	if !strings.Contains(err.Error(), "cache") {
		t.Fatalf("error should name the offending directive: %v", err)
	}
}

func TestCheckDirectiveOrderMissingZonedns(t *testing.T) {
	if err := CheckDirectiveOrder([]string{"cache", "forward"}); err == nil {
		t.Fatal("expected error when zonedns is absent from Directives")
	}
}

// 沒有 cache 時順序無所謂。
func TestCheckDirectiveOrderWithoutCache(t *testing.T) {
	if err := CheckDirectiveOrder([]string{"zonedns", "forward"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseCorefile(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns {
		spire_server unix:///tmp/spire-server/private/api.sock
		poll_interval 30s
		authorized_agent spiffe://example.org/node/n1
		authorized_agent spiffe://example.org/node/n2
		edns0_code 65001
		ttl 30
		gateway zone-a 203.0.113.10
		gateway zone-b 203.0.113.11
	}`)

	cfg, err := parseConfig(c)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if len(cfg.authorizedAgents) != 2 {
		t.Fatalf("authorizedAgents = %d, want 2", len(cfg.authorizedAgents))
	}
	if cfg.ttl != 30 {
		t.Fatalf("ttl = %d, want 30", cfg.ttl)
	}
	if cfg.zones.Len() != 2 {
		t.Fatalf("zones = %d, want 2", cfg.zones.Len())
	}
	if got, ok := cfg.zones.Gateway("zone-a"); !ok || got.String() != "203.0.113.10" {
		t.Fatalf("gateway zone-a = (%s,%v)", got, ok)
	}
}

// 沒有授權 agent 等於這個 plugin 永遠不會 zone-aware，是設定錯誤而非合法組態。
func TestParseCorefileRequiresAuthorizedAgent(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns {
		spire_server unix:///tmp/spire-server/private/api.sock
		gateway zone-a 203.0.113.10
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected error when no authorized_agent is configured")
	}
}

func TestParseCorefileRejectsBadGatewayAddress(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns {
		spire_server unix:///tmp/spire-server/private/api.sock
		authorized_agent spiffe://example.org/node/n1
		gateway zone-a not-an-ip
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected error for malformed gateway address")
	}
}

// warnIfDoT 必須只在 transport 為 tls 時回傳警告文字，其餘傳輸方式一律回傳空字串。
//
// 原因：身分擷取在 DoT 與 DoH 上的做法不同 —— DoH 從 context 取出 *http.Request，
// 這在其他 plugin 包裝 ResponseWriter 之後仍然有效；DoT 則對 ResponseWriter 做
// dns.ConnectionStater 型別斷言，而 CoreDNS 內建的 metrics plugin 會用一個把
// dns.ResponseWriter 存成 interface 欄位的 Recorder 包住 writer，導致斷言失敗。
// 後果是 DoT listener 上每個查詢都安靜地回報「沒有憑證」，zone 路由整個關閉，
// 且未授權 agent 的告警永遠不會觸發，而過程中沒有任何錯誤。
func TestWarnIfDoT(t *testing.T) {
	msg := warnIfDoT(transport.TLS)
	if msg == "" {
		t.Fatal("expected a warning for the tls transport")
	}
	if !strings.Contains(msg, "DoH") && !strings.Contains(msg, "https://") {
		t.Fatalf("warning should recommend DoH: %q", msg)
	}

	for _, tr := range []string{transport.DNS, transport.GRPC, transport.HTTPS, transport.QUIC, transport.UNIX, ""} {
		if msg := warnIfDoT(tr); msg != "" {
			t.Fatalf("transport %q should not warn, got %q", tr, msg)
		}
	}
}
