package zonedns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/netip"
	"testing"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/jenting/zonedns/internal/ednszone"
	"github.com/jenting/zonedns/internal/identity"
	"github.com/jenting/zonedns/internal/registry"
	"github.com/jenting/zonedns/internal/testcerts"
	"github.com/jenting/zonedns/internal/zonetable"
	"github.com/miekg/dns"
)

const testAgentID = "spiffe://example.org/node/n1"

// nextCalled 是一個記錄自己是否被呼叫的下游 plugin。
type nextCalled struct{ called bool }

func (n *nextCalled) Name() string { return "next" }
func (n *nextCalled) ServeDNS(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	n.called = true
	m := new(dns.Msg)
	m.SetReply(r)
	m.Answer = []dns.RR{test.A("payments.example.com. 5 IN A 10.96.0.7")}
	w.WriteMsg(m)
	return dns.RcodeSuccess, nil
}

// dotWriter 模擬 DoT 連線：ConnectionState 是它自己宣告的方法（不是靠內嵌的
// dns.ResponseWriter 介面欄位促升而來），所以直接把 *dotWriter 傳進 ServeDNS 時
// dns.ConnectionStater 斷言會成功。
//
// 它同時記錄最後一次寫入的訊息（Msg），故意不再另外包一層
// dnstest.NewRecorder：dnstest.Recorder 本身也是把 dns.ResponseWriter 存成
// 介面欄位，若拿它包住 dotWriter 再傳進 ServeDNS，Msg 的方法集只會有介面本身
// 宣告的方法，ConnectionState 斷言就會失敗 —— 這正是 identity.PeerCertificates
// 文件描述、也是本任務要求新增的 DoT 警告所指的那個「ResponseWriter 包裝讓 DoT
// 憑證擷取安靜失效」的情境，測試不該再次踩進同一個陷阱。
type dotWriter struct {
	dns.ResponseWriter
	state *tls.ConnectionState
	Msg   *dns.Msg
}

func (w *dotWriter) ConnectionState() *tls.ConnectionState { return w.state }

func (w *dotWriter) WriteMsg(m *dns.Msg) error {
	w.Msg = m
	return w.ResponseWriter.WriteMsg(m)
}

// dohWriter 模擬 DoH 連線的 ResponseWriter：它刻意不實作 dns.ConnectionStater，
// 因為真正的 DoH server 也不會讓 writer 帶連線狀態 —— 身分必須從 context 裡的
// *http.Request 讀出（見 internal/identity/peercert.go）。若 ServeDNS 有 bug
// 忘記把呼叫端傳入的 ctx 往下傳給 SourceZone（例如誤用
// context.Background()），這個 writer 會讓身分擷取直接落回「沒有憑證」，
// 讓依賴 DoH 路徑的測試確實失敗，而不是意外地從 DoT 分支拿到憑證而蒙混過去。
type dohWriter struct {
	dns.ResponseWriter
	Msg *dns.Msg
}

func (w *dohWriter) WriteMsg(m *dns.Msg) error {
	w.Msg = m
	return w.ResponseWriter.WriteMsg(m)
}

func newHandler(t *testing.T, next plugin.Handler) ZoneDNS {
	t.Helper()

	store := registry.NewStore()
	snap, _ := registry.BuildSnapshot([]registry.Entry{
		{SPIFFEIDPath: "/zone/zone-a/ns/prod/sa/payments", DNSNames: []string{"payments.example.com"}},
		{SPIFFEIDPath: "/zone/zone-z/ns/prod/sa/lonely", DNSNames: []string{"lonely.example.com"}},
	})
	store.Replace(snap)

	return ZoneDNS{
		Next:     next,
		Identity: identity.NewConfig([]string{testAgentID}, ednszone.DefaultCode),
		Registry: store,
		Zones: zonetable.New(map[string]netip.Addr{
			"zone-a": netip.MustParseAddr("203.0.113.10"),
		}),
		TTL: 30,
	}
}

// newRequest 建立一個來自已授權 agent、帶指定 source zone 的查詢。
//
// 命名為 newRequest 而非 request：本檔案所在的 zonedns 套件在 zonedns.go 匯入了
// "github.com/coredns/coredns/request" 套件（識別字為 request）。Go 不允許同一
// 識別字同時存在於檔案區塊（import）與套件區塊（頂層宣告）——即使宣告在不同檔案，
// 用 request 當函式名仍會與該匯入衝突而編譯失敗，因此改名。
func newRequest(t *testing.T, qname string, qtype uint16, zone string) (*dns.Msg, *dotWriter) {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	if zone != "" {
		ednszone.Set(m, ednszone.DefaultCode, zone)
	}
	certs := []*x509.Certificate{testcerts.New(t, testAgentID)}
	w := &dotWriter{
		ResponseWriter: &test.ResponseWriter{},
		state:          &tls.ConnectionState{PeerCertificates: certs},
	}
	return m, w
}

func TestServeDNSCrossZoneAnswersGateway(t *testing.T) {
	next := &nextCalled{}
	h := newHandler(t, next)

	r, w := newRequest(t, "payments.example.com.", dns.TypeA, "zone-b")

	code, err := h.ServeDNS(context.Background(), w, r)
	if err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if code != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR", code)
	}
	if next.called {
		t.Fatal("cross-zone query must not reach the next plugin")
	}
	// ServeDNS's own return value is not what the client sees: CoreDNS only
	// rewrites the reply's rcode when the returned code fails plugin.ClientWrite,
	// which RcodeSuccess does not. The client sees w.Msg.Rcode as written by
	// answerGateway, so that is what must be asserted here.
	if w.Msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("w.Msg.Rcode = %d, want NOERROR", w.Msg.Rcode)
	}
	if len(w.Msg.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(w.Msg.Answer))
	}
	a, isA := w.Msg.Answer[0].(*dns.A)
	if !isA {
		t.Fatalf("answer is %T, want *dns.A", w.Msg.Answer[0])
	}
	if a.A.String() != "203.0.113.10" {
		t.Fatalf("answer = %s, want 203.0.113.10", a.A)
	}
	if a.Hdr.Ttl != 30 {
		t.Fatalf("ttl = %d, want 30", a.Hdr.Ttl)
	}
}

// 專案唯一支援的傳輸方式是 DoH（見 setup.go 的 warnIfDoT），身分擷取走的是
// context 裡的 *http.Request，而非對 writer 做型別斷言那條路徑。這個測試確保
// ServeDNS 真的把呼叫端傳入的 ctx 往下傳給 Identity.SourceZone —— 若不小心
// 改成 context.Background()，所有帶 DoT ConnectionStater 的測試仍會通過（它們
// 走的是另一條分支），只有這個測試會發現迴歸。
func TestServeDNSDoHCrossZoneAnswersGateway(t *testing.T) {
	next := &nextCalled{}
	h := newHandler(t, next)

	m := new(dns.Msg)
	m.SetQuestion("payments.example.com.", dns.TypeA)
	ednszone.Set(m, ednszone.DefaultCode, "zone-b")

	cert := testcerts.New(t, testAgentID)
	req := &http.Request{TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}}
	ctx := context.WithValue(context.Background(), dnsserver.HTTPRequestKey{}, req)

	w := &dohWriter{ResponseWriter: &test.ResponseWriter{}}

	code, err := h.ServeDNS(ctx, w, m)
	if err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if code != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR", code)
	}
	if next.called {
		t.Fatal("cross-zone query must not reach the next plugin")
	}
	if w.Msg == nil || len(w.Msg.Answer) != 1 {
		t.Fatalf("answers = %v, want 1", w.Msg)
	}
	a, isA := w.Msg.Answer[0].(*dns.A)
	if !isA {
		t.Fatalf("answer is %T, want *dns.A", w.Msg.Answer[0])
	}
	if a.A.String() != "203.0.113.10" {
		t.Fatalf("answer = %s, want 203.0.113.10", a.A)
	}
}

func TestServeDNSSameZonePassesThrough(t *testing.T) {
	next := &nextCalled{}
	h := newHandler(t, next)

	r, w := newRequest(t, "payments.example.com.", dns.TypeA, "zone-a")
	if _, err := h.ServeDNS(context.Background(), w, r); err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if !next.called {
		t.Fatal("same-zone query must reach the next plugin")
	}
}

func TestServeDNSUnknownNamePassesThrough(t *testing.T) {
	next := &nextCalled{}
	h := newHandler(t, next)

	r, w := newRequest(t, "external.example.net.", dns.TypeA, "zone-b")
	if _, err := h.ServeDNS(context.Background(), w, r); err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if !next.called {
		t.Fatal("name outside the registry must reach the next plugin")
	}
}

// 沒有 client cert 的查詢走非 zone-aware 路徑，不是錯誤。
func TestServeDNSNoIdentityPassesThrough(t *testing.T) {
	next := &nextCalled{}
	h := newHandler(t, next)

	m := new(dns.Msg)
	m.SetQuestion("payments.example.com.", dns.TypeA)
	if _, err := h.ServeDNS(context.Background(), dnstest.NewRecorder(&test.ResponseWriter{}), m); err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if !next.called {
		t.Fatal("query without identity must reach the next plugin")
	}
}

// registry 有這個 zone，但設定檔沒有它的 gateway —— 必須 SERVFAIL，不可靜默放行。
func TestServeDNSMissingGatewayServfails(t *testing.T) {
	next := &nextCalled{}
	h := newHandler(t, next)

	r, w := newRequest(t, "lonely.example.com.", dns.TypeA, "zone-b")
	code, err := h.ServeDNS(context.Background(), w, r)
	if err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if code != dns.RcodeServerFailure {
		t.Fatalf("rcode = %d, want SERVFAIL", code)
	}
	if next.called {
		t.Fatal("misconfigured zone must not fall through to a normal answer")
	}
}

// IPv4 gateway 遇到 AAAA 查詢時回 NODATA（NOERROR + 空 answer），
// 讓 client 正常退回 A。回 NXDOMAIN 會讓 client 認為這個名字不存在。
func TestServeDNSCrossZoneAAAAWithIPv4GatewayReturnsNoData(t *testing.T) {
	next := &nextCalled{}
	h := newHandler(t, next)

	r, w := newRequest(t, "payments.example.com.", dns.TypeAAAA, "zone-b")

	code, err := h.ServeDNS(context.Background(), w, r)
	if err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if code != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR", code)
	}
	// NODATA means NOERROR with an empty answer section, as seen by the client —
	// not just ServeDNS's return value. Without this, a mutation that sets
	// m.Rcode = dns.RcodeNameError whenever the answer is empty (turning NODATA
	// into NXDOMAIN, which makes clients abandon the A lookup too) would leave
	// the suite green.
	if w.Msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("w.Msg.Rcode = %d, want NOERROR", w.Msg.Rcode)
	}
	if len(w.Msg.Answer) != 0 {
		t.Fatalf("answers = %d, want 0", len(w.Msg.Answer))
	}
	if next.called {
		t.Fatal("cross-zone AAAA must not fall through")
	}
}

// 非 A/AAAA 的查詢型別不介入 —— 例如 SRV、TXT 應照常由下游回答。
func TestServeDNSOtherQtypePassesThrough(t *testing.T) {
	next := &nextCalled{}
	h := newHandler(t, next)

	r, w := newRequest(t, "payments.example.com.", dns.TypeTXT, "zone-b")
	if _, err := h.ServeDNS(context.Background(), w, r); err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if !next.called {
		t.Fatal("TXT query must reach the next plugin")
	}
}
