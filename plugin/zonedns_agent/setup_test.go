package zonedns_agent

import (
	"strings"
	"testing"

	"github.com/coredns/caddy"
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
	resolverReadyGeneration.Store(0)
	resolverReady.Set(0)
	defer func() {
		resolverGeneration.Store(0)
		resolverReadyGeneration.Store(0)
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
