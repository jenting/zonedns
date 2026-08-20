// Package integration 把節點端與中心端接起來測試。
//
// 為什麼需要它：兩端不共用程式碼，只共用 internal/ednszone 定義的線上格式。
// 各自的單元測試都在自己那一側驗證那個格式，所以只要兩邊對格式的理解一致地
// 錯了，兩邊都是綠的。真實部署時才會發現 —— 而且症狀通常是「查詢有答案，只是
// 不再分 zone」，沒有任何錯誤。
//
// 這個 harness 讓真正的 Agent.ServeDNS 經過真實的 mTLS 握手，打到真正的
// ZoneDNS.ServeDNS，中間不替換任何一端的邏輯。
package integration

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/pkg/doh"
	"github.com/coredns/coredns/plugin/test"
	"github.com/jenting/zonedns/internal/dohupstream"
	"github.com/jenting/zonedns/internal/ednszone"
	"github.com/jenting/zonedns/internal/identity"
	"github.com/jenting/zonedns/internal/registry"
	"github.com/jenting/zonedns/internal/testcerts"
	"github.com/jenting/zonedns/internal/zonecache"
	"github.com/jenting/zonedns/internal/zonetable"
	centralplugin "github.com/jenting/zonedns/plugin/zonedns"
	agentplugin "github.com/jenting/zonedns/plugin/zonedns_agent"
	"github.com/miekg/dns"
)

const (
	agentSPIFFEID   = "spiffe://example.org/zone/infra/node/node-01"
	centralSPIFFEID = "spiffe://example.org/zone/mgmt/service/zonedns-central"
	rogueSPIFFEID   = "spiffe://example.org/zone/zone-b/ns/default/sa/attacker"

	zoneAGateway = "203.0.113.10"
	zoneBGateway = "203.0.113.11"
	downstreamIP = "10.96.0.7"
)

// options 讓每個案例只覆寫它關心的那一項，其餘用一致的預設。
type options struct {
	agentZone      string // agent 宣告的 zone
	agentEDNS0Code uint16 // 節點端使用的 option code
	centralCode    uint16 // 中心端期待的 option code
	clientSPIFFEID string // agent 出示的憑證身分
	upstreamPath   string // 附加在 upstream URL 後的路徑（用來重現路徑重複的錯誤）
}

func defaults() options {
	return options{
		agentZone:      "zone-b",
		agentEDNS0Code: ednszone.DefaultCode,
		centralCode:    ednszone.DefaultCode,
		clientSPIFFEID: agentSPIFFEID,
	}
}

// downstream 模擬 central 背後的一般 DNS —— 同 zone 或不歸 zonedns 管的名字
// 最終會落到這裡。回一個固定位址，讓測試分得出「走了 zone 路由」與「沒走」。
type downstream struct{ called bool }

func (d *downstream) Name() string { return "downstream" }
func (d *downstream) ServeDNS(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	d.called = true
	m := new(dns.Msg)
	m.SetReply(r)
	m.Answer = []dns.RR{test.A("payments.example.com. 30 IN A " + downstreamIP)}
	w.WriteMsg(m)
	return dns.RcodeSuccess, nil
}

// stack 是接好的兩端。
type stack struct {
	agent      agentplugin.Agent
	downstream *downstream
	server     *httptest.Server
	// seenPath 記錄 central 實際收到的 HTTP 路徑。
	seenPath string
}

func (s *stack) Close() { s.server.Close() }

// query 從 client 的角度發一個查詢。
//
// 回傳 rcode 與寫出的訊息。訊息可能是 nil —— 失敗路徑刻意不自己寫回應，因為
// plugin.ClientWrite(RcodeServerFailure) 為 false，由 CoreDNS 的 server 產生
// 那個回應。斷言失敗情境時要看 rcode，不是看訊息內容。
func (s *stack) query(t *testing.T, qname string, qtype uint16, clientIP string) (int, *dns.Msg) {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	return s.queryMsg(t, m, clientIP)
}

// queryMsg 發一個呼叫端自己組好的查詢 —— 用來模擬 client 帶了自製的 EDNS0 內容。
func (s *stack) queryMsg(t *testing.T, m *dns.Msg, clientIP string) (int, *dns.Msg) {
	t.Helper()
	w := &test.ResponseWriter{}
	w.RemoteIP = clientIP
	rec := dnstest.NewRecorder(w)

	code, err := s.agent.ServeDNS(context.Background(), rec, m)
	if err != nil {
		t.Fatalf("agent.ServeDNS: %v", err)
	}
	return code, rec.Msg
}

// newStack 把兩端接起來。
//
// central 那側刻意用 CoreDNS 自己的 doh 套件解析請求，並套用跟 CoreDNS 的 DoH
// server 完全相同的路徑檢查（r.URL.Path == doh.Path）。寬鬆的測試替身會複製它
// 本來要防的盲點：真實部署裡 upstream URL 若多帶了路徑，central 會回 404，而
// 一個接受任何路徑的假伺服器永遠不會顯示這件事。
func newStack(t *testing.T, opt options) *stack {
	t.Helper()

	ca := testcerts.NewCA(t)
	serverCert := ca.Issue(t, centralSPIFFEID)
	clientCert := ca.Issue(t, opt.clientSPIFFEID)

	// ── 中心端：真的 ZoneDNS handler
	store := registry.NewStore()
	snap, _ := registry.BuildSnapshot([]registry.Entry{
		{SPIFFEIDPath: "/zone/zone-a/ns/prod/sa/payments", DNSNames: []string{"payments.example.com"}},
		{SPIFFEIDPath: "/zone/zone-b/ns/prod/sa/orders", DNSNames: []string{"orders.example.com"}},
	})
	store.Replace(snap)

	down := &downstream{}
	central := centralplugin.ZoneDNS{
		Next:     down,
		Identity: identity.NewConfig([]string{agentSPIFFEID}, opt.centralCode),
		Registry: store,
		Zones: zonetable.New(map[string]netip.Addr{
			"zone-a": netip.MustParseAddr(zoneAGateway),
			"zone-b": netip.MustParseAddr(zoneBGateway),
		}),
		TTL: 30,
	}

	s := &stack{downstream: down}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.seenPath = r.URL.Path
		// 與 CoreDNS 的 DoH server 相同的檢查，一字不改。
		if r.URL.Path != doh.Path {
			http.Error(w, "", http.StatusNotFound)
			return
		}
		req, err := doh.RequestToMsg(r)
		if err != nil {
			http.Error(w, "", http.StatusBadRequest)
			return
		}
		// CoreDNS 的 DoH server 把 *http.Request 放進 context，identity 就是從
		// 那裡取 peer certificate 的。
		ctx := context.WithValue(r.Context(), dnsserver.HTTPRequestKey{}, r)
		rec := dnstest.NewRecorder(&test.ResponseWriter{})
		if _, err := central.ServeDNS(ctx, rec, req); err != nil {
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
		packed, err := rec.Msg.Pack()
		if err != nil {
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(packed)
	})

	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.Pool(),
	}
	srv.StartTLS()
	s.server = srv

	// ── 節點端：真的 Agent，經真實 mTLS 連上上面那個 server
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      ca.Pool(),
	}}}

	cacheStore, err := zonecache.New(64)
	if err != nil {
		t.Fatalf("zonecache.New: %v", err)
	}
	s.agent = agentplugin.Agent{
		Resolver:  staticZone(opt.agentZone),
		Cache:     cacheStore,
		Upstream:  dohupstream.NewWithHTTPClient(srv.URL+opt.upstreamPath, hc),
		EDNS0Code: opt.agentEDNS0Code,
		NodeIP:    netip.MustParseAddr("192.168.1.10"),
	}

	t.Cleanup(s.Close)
	return s
}

// staticZone 讓每個查詢都被判定成同一個 zone —— 這裡要測的是兩端的協定，
// 不是節點端怎麼查出 zone（那有 podzone 自己的測試）。
type staticZone string

func (z staticZone) Zone(netip.Addr) (string, bool) {
	if z == "" {
		return "", false
	}
	return string(z), true
}

var _ plugin.Handler = (*downstream)(nil)
