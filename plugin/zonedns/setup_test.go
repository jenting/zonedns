package zonedns

import (
	"strings"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin/pkg/transport"
	"github.com/prometheus/client_golang/prometheus/testutil"
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

// 重複宣告同一個 zone 的 gateway 會靜默用後面那筆覆蓋前面那筆，等於在不知情的
// 情況下把跨 zone 流量改導到另一個位址 —— 必須直接拒絕設定檔，而不是接受
// 「最後寫的贏」。
func TestParseCorefileRejectsDuplicateGateway(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns {
		spire_server unix:///tmp/spire-server/private/api.sock
		authorized_agent spiffe://example.org/node/n1
		gateway zone-a 203.0.113.10
		gateway zone-a 198.51.100.9
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected error for a zone with two gateway declarations")
	}
}

// k8s label value 允許點字元，但 ednszone.Valid（identity 用來驗證 agent
// 宣告的 source zone 的同一套規則）拒絕。若 gateway 端不擋，一個帶點的 zone
// 名稱能正常當 dest zone 使用，卻會讓該 zone 裡每一個 workload 的 source zone
// 宣告永遠被判定不合法而丟棄，靜默降級成 zone-盲。必須在設定解析時就拒絕。
func TestParseCorefileRejectsNonConformingGatewayZoneName(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns {
		spire_server unix:///tmp/spire-server/private/api.sock
		authorized_agent spiffe://example.org/node/n1
		gateway zone.a 203.0.113.10
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected error for a gateway zone name that ednszone.Valid rejects")
	}
}

// poll_interval 0 或負值會讓 OnStartup 那個 goroutine 裡的 time.NewTicker
// panic，直接讓 process 崩潰 —— 必須在解析設定檔的當下就擋下來。
func TestParseCorefileRejectsNonPositivePollInterval(t *testing.T) {
	for _, v := range []string{"0s", "-5s"} {
		c := caddy.NewTestController("dns", `zonedns {
			spire_server unix:///tmp/spire-server/private/api.sock
			authorized_agent spiffe://example.org/node/n1
			poll_interval `+v+`
		}`)
		if _, err := parseConfig(c); err == nil {
			t.Fatalf("poll_interval %q: expected error", v)
		}
	}
}

// fmt.Sscanf("%d") 會在遇到第一個非數字字元時停止掃描但不回報錯誤，因此
// "5m"（duration 格式）會被誤判成 5、"30.5" 被誤判成 30、"65001abc" 被誤判成
// 65001。改用 strconv.ParseUint 後這些輸入都必須被整個拒絕，而不是截斷取用
// 開頭那段數字。
func TestParseCorefileRejectsMalformedTTL(t *testing.T) {
	for _, v := range []string{"5m", "30.5", "30abc"} {
		c := caddy.NewTestController("dns", `zonedns {
			spire_server unix:///tmp/spire-server/private/api.sock
			authorized_agent spiffe://example.org/node/n1
			ttl `+v+`
		}`)
		if _, err := parseConfig(c); err == nil {
			t.Fatalf("ttl %q: expected error", v)
		}
	}
}

// edns0_code 必須落在 IANA 保留給 local/experimental 用途的 65001-65534 區間，
// 且不接受帶尾碼垃圾字元的輸入（同一個 strconv 修法順帶解決）。
func TestParseCorefileRejectsMalformedEdns0Code(t *testing.T) {
	for _, v := range []string{"65000", "65535", "65001abc"} {
		c := caddy.NewTestController("dns", `zonedns {
			spire_server unix:///tmp/spire-server/private/api.sock
			authorized_agent spiffe://example.org/node/n1
			edns0_code `+v+`
		}`)
		if _, err := parseConfig(c); err == nil {
			t.Fatalf("edns0_code %q: expected error", v)
		}
	}
}

func TestParseCorefileAcceptsEdns0CodeUpperBound(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns {
		spire_server unix:///tmp/spire-server/private/api.sock
		authorized_agent spiffe://example.org/node/n1
		edns0_code 65534
	}`)
	cfg, err := parseConfig(c)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.edns0Code != 65534 {
		t.Fatalf("edns0Code = %d, want 65534", cfg.edns0Code)
	}
}

// spire_server 是網路位址時走 mTLS：少了 spire_server_id 就只能驗證「trust
// domain 內的某個成員」，任何持有同 trust domain SVID 的攻擊者攔截連線後都能
// 冒充 SPIRE Server、餵一份偽造的 registry。必須 fail closed，在設定檔解析時
// 就拒絕。
func TestParseCorefileRequiresSpireServerIDForNetworkAddress(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns {
		spire_server spire-server.example.org:8443
		workload_api unix:///tmp/agent/public/api.sock
		authorized_agent spiffe://example.org/node/n1
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected error when spire_server is a network address without spire_server_id")
	}
}

// unix:// 走本機管理 socket，不受 mTLS 身分驗證影響，不需要 spire_server_id。
func TestParseCorefileUnixSocketDoesNotRequireSpireServerID(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns {
		spire_server unix:///tmp/spire-server/private/api.sock
		authorized_agent spiffe://example.org/node/n1
	}`)
	if _, err := parseConfig(c); err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
}

func TestParseCorefileAcceptsSpireServerIDForNetworkAddress(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns {
		spire_server spire-server.example.org:8443
		spire_server_id spiffe://example.org/spire/server
		workload_api unix:///tmp/agent/public/api.sock
		authorized_agent spiffe://example.org/node/n1
	}`)
	cfg, err := parseConfig(c)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.spireServerID != "spiffe://example.org/spire/server" {
		t.Fatalf("spireServerID = %q, want spiffe://example.org/spire/server", cfg.spireServerID)
	}
}

// registryReady 是跨 Corefile reload 共用的套件層級 gauge（見 setup.go）。若
// setup() 不主動歸零，reload 後它會繼續回報前一個 instance 的就緒狀態，而新的
// （空的）Store 其實會讓每個查詢都靜默走非 zone-aware 路徑 —— 這個 metric 正是
// 在最需要準確的時候說謊。
//
// setup() 內部第一步會呼叫 CheckDirectiveOrder(dnsserver.Directives)，那是
// vendor 進來、編譯期就固定的 CoreDNS 內建 directive 清單，不包含 "zonedns"
// （要包含它，必須是下游用自己的 plugin.cfg 重新產生 zdirectives.go 之後的組
// 建）。測試在本檔案的其他測試都只呼叫 parseConfig，唯獨這裡需要 setup() 真的
// 跑到底才能驗證 registryReady 的歸零時機，所以在測試範圍內暫時把 "zonedns"
// 插進 "cache" 之前（滿足 CheckDirectiveOrder），跑完立刻還原。本套件沒有任何
// 測試使用 t.Parallel()，因此這個暫時性的全域修改不會與其他測試競爭。
func TestSetupResetsRegistryReadyGauge(t *testing.T) {
	registryReady.Set(1)      // 模擬前一個 instance 已經就緒過。
	registryPollErrors.Set(3) // 模擬前一個 instance 曾經連續輪詢失敗過。

	origDirectives := dnsserver.Directives
	extended := make([]string, 0, len(origDirectives)+1)
	inserted := false
	for _, d := range origDirectives {
		if d == "cache" && !inserted {
			extended = append(extended, "zonedns")
			inserted = true
		}
		extended = append(extended, d)
	}
	if !inserted {
		extended = append(extended, "zonedns")
	}
	dnsserver.Directives = extended
	defer func() { dnsserver.Directives = origDirectives }()

	c := caddy.NewTestController("dns", `zonedns {
		spire_server unix:///tmp/spire-server/private/api.sock
		authorized_agent spiffe://example.org/node/n1
	}`)

	// dialSPIRE's unix:// branch uses grpc.NewClient, which is lazy and does
	// not dial or block — no live SPIRE Server socket is required for setup()
	// to return, and OnStartup/OnShutdown callbacks registered here are never
	// invoked by NewTestController, so no goroutine or network I/O actually
	// starts during this test.
	if err := setup(c); err != nil {
		t.Fatalf("setup: %v", err)
	}

	if got := testutil.ToFloat64(registryReady); got != 0 {
		t.Fatalf("registryReady = %v, want 0", got)
	}
	// Same reasoning as registryReady above: a fresh Poller starts with zero
	// consecutive failures, so a stale non-zero reading left over from a
	// previous instance would misreport a healthy reload as still degraded.
	if got := testutil.ToFloat64(registryPollErrors); got != 0 {
		t.Fatalf("registryPollErrors = %v, want 0", got)
	}
}

// go-spiffe 的 NewX509Source 文件明載會阻塞到第一筆 Workload API 更新抵達為止，
// 且不帶任何逾時 —— 若 dialSPIRE 用 context.Background() 呼叫它，一個沒起來的
// agent socket 會讓 setup() 永遠卡住（啟動時整個掛住、reload 時卡住 reload
// 本身）。這裡把 workloadAPIDialTimeout 縮短成測試可接受的長度，指向一個確定
// 不存在的 unix socket，驗證 dialSPIRE 會在這段時間內回傳錯誤，而不是一直等
// 下去；並驗證錯誤訊息指名 workload_api，讓操作者知道要檢查什麼。
func TestDialSPIRETimesOutWhenWorkloadAPIUnavailable(t *testing.T) {
	origTimeout := workloadAPIDialTimeout
	workloadAPIDialTimeout = 200 * time.Millisecond
	defer func() { workloadAPIDialTimeout = origTimeout }()

	cfg := &config{
		spireServer:   "spire-server.example.org:8443",
		spireServerID: "spiffe://example.org/spire/server",
		workloadAPI:   "unix:///tmp/zonedns-test-nonexistent-agent.sock",
	}

	start := time.Now()
	_, _, err := dialSPIRE(cfg)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error when the workload_api socket does not exist")
	}
	if !strings.Contains(err.Error(), "workload_api") {
		t.Fatalf("error should name the workload_api option so the operator knows what to check: %v", err)
	}
	// Generous upper bound: this must be well under NewX509Source's unbounded
	// default, not exactly workloadAPIDialTimeout to the millisecond.
	if elapsed > 5*time.Second {
		t.Fatalf("dialSPIRE took %s, want bounded by workloadAPIDialTimeout (%s)", elapsed, workloadAPIDialTimeout)
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
