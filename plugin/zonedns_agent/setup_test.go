package zonedns_agent

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/jenting/zonedns/internal/dohupstream"
	"github.com/jenting/zonedns/internal/ednszone"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestCheckDirectiveOrder(t *testing.T) {
	if err := CheckDirectiveOrder([]string{"zonedns_agent", "cache", "forward"}); err != nil {
		t.Fatalf("valid order rejected: %v", err)
	}
}

// 順序錯了必須是啟動失敗：cache 排在前面時，zone-盲的快取會把某個 zone 的答案
// 回給另一個 zone 的 pod，而執行期看不出任何異狀。
func TestCheckDirectiveOrderRejectsCacheFirst(t *testing.T) {
	err := CheckDirectiveOrder([]string{"cache", "zonedns_agent", "forward"})
	if err == nil {
		t.Fatal("expected an error when cache precedes zonedns_agent")
	}
	if !strings.Contains(err.Error(), "cache") {
		t.Fatalf("error should name the offending directive: %v", err)
	}
}

func TestCheckDirectiveOrderMissingPlugin(t *testing.T) {
	if err := CheckDirectiveOrder([]string{"cache", "forward"}); err == nil {
		t.Fatal("expected an error when zonedns_agent is absent")
	}
}

// cache 完全沒出現在 plugin.cfg 裡也必須成功 —— 沒有 cache 就沒有 zone-盲快取
// 這個風險，不該被當成錯誤擋下來。
func TestCheckDirectiveOrderNoCache(t *testing.T) {
	if err := CheckDirectiveOrder([]string{"zonedns_agent", "forward"}); err != nil {
		t.Fatalf("valid order without cache rejected: %v", err)
	}
}

func TestParseVMMode(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone zone-c
		upstream https://central.example.org/dns-query
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
		cache_size 4096
	}`)

	cfg, err := parseConfig(c)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.mode != modeVM {
		t.Fatalf("mode = %v, want vm", cfg.mode)
	}
	if cfg.zone != "zone-c" {
		t.Fatalf("zone = %q, want zone-c", cfg.zone)
	}
	if cfg.cacheSize != 4096 {
		t.Fatalf("cacheSize = %d, want 4096", cfg.cacheSize)
	}
}

func TestParseK8sMode(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode k8s
		node_name node-1
		zone_label zone
		upstream https://central.example.org/dns-query
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)

	cfg, err := parseConfig(c)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.mode != modeK8s {
		t.Fatalf("mode = %v, want k8s", cfg.mode)
	}
	if cfg.nodeName != "node-1" {
		t.Fatalf("nodeName = %q, want node-1", cfg.nodeName)
	}
	if cfg.zoneLabel != "zone" {
		t.Fatalf("zoneLabel = %q, want zone", cfg.zoneLabel)
	}
}

// central_spiffe_id 沒有安全的預設值：少了它就只剩憑證鏈驗證，信任域內任何一張
// SVID 都能冒充 central。
func TestParseRequiresCentralSPIFFEID(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone zone-c
		upstream https://central.example.org/dns-query
		workload_api unix:///run/spire/sockets/agent.sock
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected an error when central_spiffe_id is missing")
	}
}

func TestParseVMModeRequiresZone(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		upstream https://central.example.org/dns-query
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected an error when vm mode has no zone")
	}
}

func TestParseVMModeRejectsMalformedZone(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone zone.c
		upstream https://central.example.org/dns-query
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected an error for a zone name that the wire format cannot carry")
	}
}

func TestParseK8sModeRequiresNodeName(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode k8s
		upstream https://central.example.org/dns-query
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected an error when k8s mode has no node_name")
	}
}

func TestParseRejectsUnknownMode(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode kubernetes
		upstream https://central.example.org/dns-query
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected an error for an unrecognised mode")
	}
}

func TestParseRejectsNonPositiveCacheSize(t *testing.T) {
	for _, v := range []string{"0", "-1"} {
		c := caddy.NewTestController("dns", `zonedns_agent {
			mode vm
			zone zone-c
			upstream https://central.example.org/dns-query
			central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
			workload_api unix:///run/spire/sockets/agent.sock
			cache_size `+v+`
		}`)
		if _, err := parseConfig(c); err == nil {
			t.Fatalf("cache_size %s was accepted", v)
		}
	}
}

func TestParseRejectsMalformedCacheSize(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone zone-c
		upstream https://central.example.org/dns-query
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
		cache_size 4096abc
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("trailing garbage in cache_size was accepted")
	}
}

// 一個 http:// 的 upstream 會讓 DoH 查詢走純文字傳輸，NewMTLS 的 TLSClientConfig
// （因此也包含 SPIFFE AuthorizeID 的 central 身分釘住）根本不會被用上 —— 必須在
// 設定解析時就擋下來，而不是留給執行期悄悄退化成不驗證身分的連線。
func TestParseRejectsHTTPUpstream(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone zone-c
		upstream http://central.example.org/dns-query
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)
	err := parseConfigErr(t, c)
	if !strings.Contains(err.Error(), "https") {
		t.Fatalf("error should explain that https is required: %v", err)
	}
}

func TestParseRejectsMalformedUpstreamURL(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone zone-c
		upstream ://missing-scheme
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)
	parseConfigErr(t, c)
}

func TestParseAcceptsHTTPSUpstream(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone zone-c
		upstream https://central.example.org/dns-query
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)
	if _, err := parseConfig(c); err != nil {
		t.Fatalf("valid https upstream rejected: %v", err)
	}
}

// parseConfigErr 是共用的小工具：呼叫 parseConfig 並要求它回錯誤，回錯誤本身
// 讓呼叫端可以再檢查訊息內容。
func parseConfigErr(t *testing.T, c *caddy.Controller) error {
	t.Helper()
	_, err := parseConfig(c)
	if err == nil {
		t.Fatal("expected parseConfig to return an error")
	}
	return err
}

// 一個設了但解不開的 NODE_IP 必須讓 parseConfig 失敗，而不是悄悄當成沒設 ——
// 否則 masquerade 偵測（節省告警操作者「這個節點已經退化成單一 zone」的唯一
// 訊號）會因為 DaemonSet manifest 裡的一個錯字悄悄停用，且沒有任何記錄。
func TestParseNodeIPEnvRejectsMalformed(t *testing.T) {
	t.Setenv("NODE_IP", "not-an-ip")
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone zone-c
		upstream https://central.example.org/dns-query
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected an error for a malformed NODE_IP environment variable")
	}
}

// 沒設 NODE_IP 時必須維持原樣 —— cfg.nodeIP 留在零值，不能因為前一個檢查改動
// 而變成「設了但錯」的那條路徑。
func TestParseNodeIPEnvAbsentLeavesNodeIPUnset(t *testing.T) {
	t.Setenv("NODE_IP", "")
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone zone-c
		upstream https://central.example.org/dns-query
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)
	cfg, err := parseConfig(c)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.nodeIP.IsValid() {
		t.Fatalf("nodeIP = %v, want zero value when NODE_IP is absent", cfg.nodeIP)
	}
}

func TestParseMissingModeArgument(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode
		upstream https://central.example.org/dns-query
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected an error when mode has no argument")
	}
}

func TestParseMissingZoneArgument(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone
		upstream https://central.example.org/dns-query
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected an error when zone has no argument")
	}
}

// edns0_code 必須能在 agent 端設定，且驗證規則跟 central 端的
// plugin/zonedns/setup.go 完全一致 —— 兩端的值必須相同（spec §6.6），一個能
// 在其中一端過關、卻在另一端被拒絕的值，會讓操作者以為自己已經把兩端同步，
// 實際上其中一端永遠不會接受它。
func TestParseEdns0Code(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone zone-c
		upstream https://central.example.org/dns-query
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
		edns0_code 65002
	}`)
	cfg, err := parseConfig(c)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.edns0Code != 65002 {
		t.Fatalf("edns0Code = %d, want 65002", cfg.edns0Code)
	}
}

func TestParseEdns0CodeDefault(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone zone-c
		upstream https://central.example.org/dns-query
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)
	cfg, err := parseConfig(c)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.edns0Code != ednszone.DefaultCode {
		t.Fatalf("edns0Code = %d, want the default %d", cfg.edns0Code, ednszone.DefaultCode)
	}
}

func TestParseRejectsOutOfRangeEdns0Code(t *testing.T) {
	for _, v := range []string{"65000", "65535"} {
		c := caddy.NewTestController("dns", `zonedns_agent {
			mode vm
			zone zone-c
			upstream https://central.example.org/dns-query
			central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
			workload_api unix:///run/spire/sockets/agent.sock
			edns0_code `+v+`
		}`)
		if _, err := parseConfig(c); err == nil {
			t.Fatalf("edns0_code %s outside 65001-65534 was accepted", v)
		}
	}
}

func TestParseRejectsMalformedEdns0Code(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone zone-c
		upstream https://central.example.org/dns-query
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
		edns0_code 65002abc
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("trailing garbage in edns0_code was accepted")
	}
}

// vm 模式下 node_name 完全不起作用 —— 這台機器的 zone 由 zone 選項一次性決定，
// 不是逐查詢從 pod label 讀出來的。悄悄接受並丟棄它，會讓 Corefile 表達的意圖
// 跟實際行為對不上。
func TestParseVMModeRejectsNodeName(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone zone-c
		node_name node-1
		upstream https://central.example.org/dns-query
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)
	err := parseConfigErr(t, c)
	if !strings.Contains(err.Error(), "node_name") || !strings.Contains(err.Error(), "vm mode") {
		t.Fatalf("error should name the offending option and mode: %v", err)
	}
}

// 對稱地，k8s 模式下 zone 完全不起作用 —— 這個節點的 zone 逐查詢由 pod label
// 決定，寫死一個 zone 選項會讓操作者誤以為這個節點只服務那一個 zone。
func TestParseK8sModeRejectsZone(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode k8s
		node_name node-1
		zone zone-c
		upstream https://central.example.org/dns-query
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)
	err := parseConfigErr(t, c)
	if !strings.Contains(err.Error(), "zone") || !strings.Contains(err.Error(), "k8s mode") {
		t.Fatalf("error should name the offending option and mode: %v", err)
	}
}

func TestParseRejectsUnknownProperty(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone zone-c
		upstream https://central.example.org/dns-query
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
		bogus_property yes
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected an error for an unknown property")
	}
}

// reload 期間新舊兩個 k8s watcher 的生命週期會重疊：coredns/caddy 先完整啟動
// 新 instance（含它的 OnReady）才去關閉舊的。若較新世代已經把 resolverReady
// 標成就緒，較舊世代因為自己的 ctx 被取消而觸發的歸零就不該把它蓋掉 —— 否則
// 這個 gauge 會卡在 0，直到下一次 reload 都不會修正，即使新 instance 早已正常
// 運作。
func TestResolverReadyGuardIgnoresStaleShutdown(t *testing.T) {
	resolverGeneration.Store(0)
	resetResolverReadyGeneration(t)
	resolverReady.Set(0)
	defer func() {
		resolverGeneration.Store(0)
		resetResolverReadyGeneration(t)
		resolverReady.Set(0)
	}()

	gen1 := resolverGeneration.Add(1)
	markResolverReady(gen1)
	if got := testutil.ToFloat64(resolverReady); got != 1 {
		t.Fatalf("resolverReady = %v after gen1 ready, want 1", got)
	}

	gen2 := resolverGeneration.Add(1)
	markResolverReady(gen2)
	if got := testutil.ToFloat64(resolverReady); got != 1 {
		t.Fatalf("resolverReady = %v after gen2 ready, want 1", got)
	}

	// gen1's shutdown arrives late, after gen2 has already taken over — it
	// must not stomp gen2's readiness.
	markResolverStopped(gen1)
	if got := testutil.ToFloat64(resolverReady); got != 1 {
		t.Fatalf("stale generation's shutdown zeroed the gauge: got %v, want 1", got)
	}

	// gen2's own shutdown, with nothing newer having taken over, legitimately
	// zeroes it.
	markResolverStopped(gen2)
	if got := testutil.ToFloat64(resolverReady); got != 0 {
		t.Fatalf("resolverReady = %v after gen2 stopped, want 0", got)
	}
}

// resetResolverReadyGeneration 把 resolverReadyGeneration 歸零，用 white-box
// 測試的方式直接拿 resolverReadyMu，而不是透過 markResolverReady/
// markResolverStopped —— 這裡只是測試前後的清理，不是要重現任何交錯時機。
func resetResolverReadyGeneration(t *testing.T) {
	t.Helper()
	resolverReadyMu.Lock()
	resolverReadyGeneration = 0
	resolverReadyMu.Unlock()
}

// TestResolverReadyGuardTOCTOU 重現一個 check-then-act 的競態：gen1 讀到「我
// 還是最新世代」之後、還沒來得及依這個結論寫入 gauge 之前，gen2 搶先透過
// markResolverReady 取代它成為最新世代；接著 gen1 才執行它已經決定好（但此刻
// 已經過時）的動作。
//
// 這是 TestResolverReadyGuardIgnoresStaleShutdown 沒有覆蓋到的情境：那個測試
// 依序呼叫 markResolverReady(gen1)、markResolverReady(gen2)、
// markResolverStopped(gen1)，三次呼叫互不重疊，只驗證「讀」與「寫」各自的
// 結果、不驗證兩者之間有沒有窗口。這裡改用 resolverStoppedTestHook，強制在
// markResolverStopped(gen1) 讀出「還是最新」之後、真正寫入 gauge 之前，插入
// 一次完整的 markResolverReady(gen2) 呼叫 —— 若「讀、比較、寫」不是同一個不
// 可分割的臨界區，gen1 接下來就會把 gen2 剛寫好的「就緒」蓋掉，而且蓋掉之後
// 不會再有任何事件修正它，直到下一次 reload：跟這整套機制原本要避免的
// 「卡在 0」錯誤一樣，只是窗口從整個 reload 縮小成這一個 check-then-act 的
// 瞬間。
//
// hook 裡用獨立的 goroutine 去呼叫 markResolverReady(gen2)，而不是在這裡同步
// 呼叫：修好之後 markResolverReady 需要拿 markResolverStopped(gen1) 正持有的
// 同一把 resolverReadyMu，同步呼叫會讓呼叫端自己卡死在一個不可重入的鎖上。
// 開一個 goroutine 讓它去搶鎖，用 channel 確認它至少已經開始執行，再用一小段
// 排程餘裕，讓它有機會在還沒修好的版本上真的搶先寫完 —— 這段時間對修好的版本
// 沒有影響：它會卡在 Lock() 直到 gen1 放手為止。
func TestResolverReadyGuardTOCTOU(t *testing.T) {
	resolverReady.Set(0)
	resetResolverReadyGeneration(t)
	defer func() {
		resolverStoppedTestHook = nil
		resetResolverReadyGeneration(t)
		resolverReady.Set(0)
	}()

	gen1 := resolverGeneration.Add(1)
	markResolverReady(gen1)

	gen2 := resolverGeneration.Add(1)

	started := make(chan struct{})
	done := make(chan struct{})
	resolverStoppedTestHook = func() {
		go func() {
			close(started)
			markResolverReady(gen2)
			close(done)
		}()
		<-started
		runtime.Gosched()
		time.Sleep(10 * time.Millisecond)
	}

	markResolverStopped(gen1)
	// gen2's markResolverReady is guaranteed to eventually complete once
	// markResolverStopped(gen1) has returned and released resolverReadyMu, so
	// this cannot hang even if the guard is broken.
	<-done

	if got := testutil.ToFloat64(resolverReady); got != 1 {
		t.Fatalf("resolverReady = %v after gen2 superseded gen1's in-flight stop, want 1 "+
			"(gen2 is newer and reported ready; gen1's stale decision must not win)", got)
	}
	resolverReadyMu.Lock()
	gotGen := resolverReadyGeneration
	resolverReadyMu.Unlock()
	if gotGen != gen2 {
		t.Fatalf("resolverReadyGeneration = %d, want %d (gen2)", gotGen, gen2)
	}
}

// wireResolverReadyLifecycle 是 vm 模式在 setup() 裡實際呼叫的函式：立刻標成
// 就緒，並在 ctx 結束時清掉。這條路徑過去（Task 8 之前）只在 k8s 模式走，vm
// 模式是直接 resolverReady.Set(1) 且從不清空 —— 節點關閉之後 gauge 會繼續卡在
// 1，即使查詢早就沒人在回應。這裡直接測這個函式本身，而不是繞經完整的
// setup()：它是 vm 與 k8s 兩個模式共用的世代保護機制，機制本身的正確性已經由
// TestResolverReadyGuardIgnoresStaleShutdown 與 TestResolverReadyGuardTOCTOU
// 覆蓋，這裡只需要確認 vm 模式實際呼叫的這個函式確實接上了「就緒」與「清空」
// 兩端。
func TestWireResolverReadyLifecycleClearsOnCancel(t *testing.T) {
	resolverGeneration.Store(0)
	resetResolverReadyGeneration(t)
	resolverReady.Set(0)
	defer func() {
		resolverGeneration.Store(0)
		resetResolverReadyGeneration(t)
		resolverReady.Set(0)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	wireResolverReadyLifecycle(ctx)

	if got := testutil.ToFloat64(resolverReady); got != 1 {
		t.Fatalf("resolverReady = %v immediately after wiring, want 1", got)
	}

	cancel()

	deadline := time.Now().Add(2 * time.Second)
	for testutil.ToFloat64(resolverReady) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("resolverReady never cleared after ctx cancellation")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// fakeUpstreamConstructor 建立一個 newUpstream 替身：不接觸真正的 SPIRE
// Workload API，回傳一個零值 *dohupstream.Client（這幾個測試都不會真的用它
// 送查詢）與一個會記錄呼叫次數、也讓測試觀察到 setup() 傳進來的 ctx 的
// cleanup。
func fakeUpstreamConstructor(cleanupCalls *int, capturedCtx *context.Context) func(context.Context, dohupstream.Config) (*dohupstream.Client, func(), error) {
	return func(ctx context.Context, _ dohupstream.Config) (*dohupstream.Client, func(), error) {
		*capturedCtx = ctx
		return &dohupstream.Client{}, func() { *cleanupCalls++ }, nil
	}
}

// vmModeConfig 是可以直接餵給 setup() 的最小合法 vm 模式設定。
const vmModeConfig = `zonedns_agent {
	mode vm
	zone zone-c
	upstream https://central.example.org/dns-query
	central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
	workload_api unix:///run/spire/sockets/agent.sock
}`

// TestSetupRejectsBadDirectiveOrder 是 setup() 本身唯一一段先於 parseConfig
// 執行的邏輯：dnsserver.Directives 錯誤時必須直接拒絕啟動，而不是先解析完
// 設定才發現順序不對。
func TestSetupRejectsBadDirectiveOrder(t *testing.T) {
	origDirectives := dnsserver.Directives
	dnsserver.Directives = []string{"cache", "zonedns_agent"}
	defer func() { dnsserver.Directives = origDirectives }()

	c := caddy.NewTestController("dns", vmModeConfig)
	err := setup(c)
	if err == nil {
		t.Fatal("expected an error when cache precedes zonedns_agent in dnsserver.Directives")
	}
	if !strings.Contains(err.Error(), "cache") {
		t.Fatalf("error should name the offending directive: %v", err)
	}
}

// TestSetupVMModeSuccess 驗證 vm 模式端到端跑過 setup()：resolver_ready gauge
// 必須到 1（見 wireResolverReadyLifecycle），且 newUpstream 只被呼叫一次。
func TestSetupVMModeSuccess(t *testing.T) {
	origDirectives := dnsserver.Directives
	dnsserver.Directives = []string{"zonedns_agent", "cache"}
	defer func() { dnsserver.Directives = origDirectives }()

	resolverGeneration.Store(0)
	resetResolverReadyGeneration(t)
	resolverReady.Set(0)
	defer func() {
		resolverGeneration.Store(0)
		resetResolverReadyGeneration(t)
		resolverReady.Set(0)
	}()

	origNewUpstream := newUpstream
	var cleanupCalls int
	var capturedCtx context.Context
	newUpstream = fakeUpstreamConstructor(&cleanupCalls, &capturedCtx)
	defer func() { newUpstream = origNewUpstream }()

	c := caddy.NewTestController("dns", vmModeConfig)
	if err := setup(c); err != nil {
		t.Fatalf("setup: %v", err)
	}

	if got := testutil.ToFloat64(resolverReady); got != 1 {
		t.Fatalf("resolverReady = %v after successful vm-mode setup, want 1", got)
	}
	if capturedCtx == nil {
		t.Fatal("newUpstream was never called")
	}
	if capturedCtx.Err() != nil {
		t.Fatal("ctx passed to newUpstream was already cancelled on the success path")
	}
	if cleanupCalls != 0 {
		t.Fatalf("cleanup called %d times on the success path before shutdown, want 0", cleanupCalls)
	}
}

// TestSetupK8sModeFailurePathRunsCleanup 驗證每一條錯誤路徑都要把已經建立的
// 資源收乾淨。newUpstream 成功之後、rest.InClusterConfig() 保證失敗（測試環境
// 外沒有 KUBERNETES_SERVICE_HOST/PORT），setup() 必須在回錯誤之前呼叫
// cancel() 與 cleanup() —— 否則已經建立的 X509Source 與它持有的檔案描述器、
// 背景 goroutine 就外洩了，而且只在特定失敗組合下才會發生，難以事後察覺。
func TestSetupK8sModeFailurePathRunsCleanup(t *testing.T) {
	origDirectives := dnsserver.Directives
	dnsserver.Directives = []string{"zonedns_agent", "cache"}
	defer func() { dnsserver.Directives = origDirectives }()

	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")

	origNewUpstream := newUpstream
	var cleanupCalls int
	var capturedCtx context.Context
	newUpstream = fakeUpstreamConstructor(&cleanupCalls, &capturedCtx)
	defer func() { newUpstream = origNewUpstream }()

	c := caddy.NewTestController("dns", `zonedns_agent {
		mode k8s
		node_name node-1
		upstream https://central.example.org/dns-query
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)

	if err := setup(c); err == nil {
		t.Fatal("expected an error from rest.InClusterConfig() outside a cluster")
	}
	if capturedCtx == nil {
		t.Fatal("newUpstream was never called")
	}
	if capturedCtx.Err() == nil {
		t.Fatal("ctx passed to newUpstream was not cancelled on the k8s in-cluster-config failure path")
	}
	if cleanupCalls != 1 {
		t.Fatalf("cleanup called %d times on the failure path, want 1", cleanupCalls)
	}
}
