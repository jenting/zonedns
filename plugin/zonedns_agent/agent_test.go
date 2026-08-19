package zonedns_agent

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/jenting/zonedns/internal/ednszone"
	"github.com/jenting/zonedns/internal/zonecache"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// fakeUpstream 記錄它收到的查詢並回一筆固定答案。
type fakeUpstream struct {
	seen  []*dns.Msg
	err   error
	calls int

	// rcode 為非零值時覆蓋回應的 Rcode（RcodeSuccess 恰好是零值，所以預設就是
	// 原本「回一筆成功答案」的行為）。
	rcode int
	// withAnswer 讓回應即使 rcode 非成功也帶著固定的 A record —— 用來測試快取
	// 路徑在收到 in-band 失敗時的行為。
	withAnswer bool
}

func (f *fakeUpstream) Exchange(_ context.Context, m *dns.Msg) (*dns.Msg, error) {
	f.calls++
	f.seen = append(f.seen, m.Copy())
	if f.err != nil {
		return nil, f.err
	}
	resp := new(dns.Msg)
	resp.SetReply(m)
	if f.rcode != 0 {
		resp.Rcode = f.rcode
	}
	if f.rcode == 0 || f.withAnswer {
		resp.Answer = []dns.RR{test.A("payments.example.com. 30 IN A 203.0.113.10")}
	}
	return resp, nil
}

// writerFrom 建立一個 source IP 為 ip 的 ResponseWriter。
func writerFrom(ip string) *dnstest.Recorder {
	w := &test.ResponseWriter{}
	w.RemoteIP = ip
	return dnstest.NewRecorder(w)
}

func newAgent(t *testing.T, resolver ZoneResolver, up Upstream) Agent {
	t.Helper()
	c, err := zonecache.New(64)
	if err != nil {
		t.Fatalf("zonecache.New: %v", err)
	}
	return Agent{
		Resolver:  resolver,
		Cache:     c,
		Upstream:  up,
		EDNS0Code: ednszone.DefaultCode,
		NodeIP:    netip.MustParseAddr("192.168.1.10"),
	}
}

func queryFor(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	return m
}

// mapResolver 是最小的 ZoneResolver 測試替身。
type mapResolver map[string]string

func (m mapResolver) Zone(ip netip.Addr) (string, bool) {
	z, ok := m[ip.String()]
	return z, ok
}

func TestServeDNSDeclaresTheSourceZone(t *testing.T) {
	up := &fakeUpstream{}
	a := newAgent(t, mapResolver{"10.1.0.5": "zone-a"}, up)

	code, err := a.ServeDNS(context.Background(), writerFrom("10.1.0.5"), queryFor("payments.example.com."))
	if err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if code != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR", code)
	}
	if up.calls != 1 {
		t.Fatalf("upstream calls = %d, want 1", up.calls)
	}

	zone, ok := ednszone.Get(up.seen[0], ednszone.DefaultCode)
	if !ok {
		t.Fatal("upstream query carried no zone declaration")
	}
	if zone != "zone-a" {
		t.Fatalf("declared zone = %q, want zone-a", zone)
	}
}

// 認不出來源時仍要轉發，但不可宣告任何 zone —— 猜一個 zone 比不宣告危險得多。
func TestServeDNSUnknownSourceDeclaresNothing(t *testing.T) {
	up := &fakeUpstream{}
	a := newAgent(t, mapResolver{}, up)

	if _, err := a.ServeDNS(context.Background(), writerFrom("10.1.0.99"), queryFor("payments.example.com.")); err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if up.calls != 1 {
		t.Fatalf("upstream calls = %d, want 1 — the query must still be answered", up.calls)
	}
	if _, ok := ednszone.Get(up.seen[0], ednszone.DefaultCode); ok {
		t.Fatal("a zone was declared for a source we could not identify")
	}
}

// 沒識別出來源時，若查詢本身帶著偽造的 zone 宣告，agent 必須清除它 —— 否則攻擊者
// 可以在 agent 猜不到 zone 的那一刻，自己決定要宣告哪個 zone，而 central 會相信
// agent 轉發的一切。
func TestServeDNSStripsForgedZoneWhenSourceUnknown(t *testing.T) {
	up := &fakeUpstream{}
	a := newAgent(t, mapResolver{}, up)

	q := queryFor("payments.example.com.")
	ednszone.Set(q, ednszone.DefaultCode, "zone-attacker-forged")

	if _, err := a.ServeDNS(context.Background(), writerFrom("10.1.0.99"), q); err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if zone, ok := ednszone.Get(up.seen[0], ednszone.DefaultCode); ok {
		t.Fatalf("forged zone declaration %q reached upstream for an unidentified source", zone)
	}
}

// 已識別出來源時，agent 自己判定的 zone 必須覆蓋查詢裡任何既有宣告 —— client 不能
// 冒充 agent 對自己 zone 的判斷。
func TestServeDNSOverridesForgedZoneWhenSourceKnown(t *testing.T) {
	up := &fakeUpstream{}
	a := newAgent(t, mapResolver{"10.1.0.5": "zone-a"}, up)

	q := queryFor("payments.example.com.")
	ednszone.Set(q, ednszone.DefaultCode, "zone-attacker-forged")

	if _, err := a.ServeDNS(context.Background(), writerFrom("10.1.0.5"), q); err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	zone, ok := ednszone.Get(up.seen[0], ednszone.DefaultCode)
	if !ok {
		t.Fatal("upstream query carried no zone declaration")
	}
	if zone != "zone-a" {
		t.Fatalf("declared zone = %q, want zone-a (the agent's own determination, not the client's)", zone)
	}
}

// 這是本套件存在的理由：同名查詢、不同 zone，不可共用快取。
func TestCacheIsKeyedByZone(t *testing.T) {
	up := &fakeUpstream{}
	a := newAgent(t, mapResolver{"10.1.0.5": "zone-a", "10.1.0.9": "zone-b"}, up)

	if _, err := a.ServeDNS(context.Background(), writerFrom("10.1.0.5"), queryFor("payments.example.com.")); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := a.ServeDNS(context.Background(), writerFrom("10.1.0.9"), queryFor("payments.example.com.")); err != nil {
		t.Fatalf("second: %v", err)
	}
	if up.calls != 2 {
		t.Fatalf("upstream calls = %d, want 2 — the second zone reused the first zone's cached answer", up.calls)
	}
}

func TestCacheHitAvoidsUpstream(t *testing.T) {
	up := &fakeUpstream{}
	a := newAgent(t, mapResolver{"10.1.0.5": "zone-a"}, up)

	for i := 0; i < 3; i++ {
		if _, err := a.ServeDNS(context.Background(), writerFrom("10.1.0.5"), queryFor("payments.example.com.")); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if up.calls != 1 {
		t.Fatalf("upstream calls = %d, want 1", up.calls)
	}
}

// 上游失敗必須是 SERVFAIL，不可交給下一個 plugin —— 那會繞過 zone 路由並回一個
// 看起來正常的直連位址。
func TestUpstreamErrorIsServfail(t *testing.T) {
	up := &fakeUpstream{err: errors.New("central unreachable")}
	a := newAgent(t, mapResolver{"10.1.0.5": "zone-a"}, up)

	code, err := a.ServeDNS(context.Background(), writerFrom("10.1.0.5"), queryFor("payments.example.com."))
	if err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if code != dns.RcodeServerFailure {
		t.Fatalf("rcode = %d, want SERVFAIL", code)
	}
}

// 上游以 in-band DNS 失敗（例如 NXDOMAIN）回應時，client 必須看到那個真正的
// rcode —— 不可被 SetReply 洗成 NOERROR，否則一個真的不存在的名字看起來像是
// 存在但沒有紀錄。
func TestServeDNSPreservesUpstreamNXDOMAIN(t *testing.T) {
	up := &fakeUpstream{rcode: dns.RcodeNameError}
	a := newAgent(t, mapResolver{"10.1.0.5": "zone-a"}, up)

	w := writerFrom("10.1.0.5")
	if _, err := a.ServeDNS(context.Background(), w, queryFor("payments.example.com.")); err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if w.Rcode != dns.RcodeNameError {
		t.Fatalf("client-visible rcode = %d, want NXDOMAIN (%d)", w.Rcode, dns.RcodeNameError)
	}
}

// 同一條規則也適用於快取命中路徑：存進快取、再取出來寫給 client 的訊息，一樣不
// 能被 SetReply 洗掉原本的 rcode。
func TestCacheHitPreservesUpstreamRcode(t *testing.T) {
	up := &fakeUpstream{rcode: dns.RcodeServerFailure, withAnswer: true}
	a := newAgent(t, mapResolver{"10.1.0.5": "zone-a"}, up)

	for i := 0; i < 2; i++ {
		w := writerFrom("10.1.0.5")
		if _, err := a.ServeDNS(context.Background(), w, queryFor("payments.example.com.")); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if w.Rcode != dns.RcodeServerFailure {
			t.Fatalf("call %d: client-visible rcode = %d, want SERVFAIL (%d)", i, w.Rcode, dns.RcodeServerFailure)
		}
	}
	if up.calls != 1 {
		t.Fatalf("upstream calls = %d, want 1 — the second call should have hit the cache", up.calls)
	}
}

// source IP 等於節點 IP 是 masquerade 的徵兆，必須可觀測。
func TestNodeIPSourceIsCounted(t *testing.T) {
	up := &fakeUpstream{}
	a := newAgent(t, mapResolver{}, up)

	before := readCounter(t, zoneResolutionTotal, "node_ip")
	if _, err := a.ServeDNS(context.Background(), writerFrom("192.168.1.10"), queryFor("payments.example.com.")); err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if after := readCounter(t, zoneResolutionTotal, "node_ip"); after != before+1 {
		t.Fatalf("node_ip counter = %v, want %v", after, before+1)
	}
}

func TestStaticResolver(t *testing.T) {
	r := NewStaticResolver("zone-c")
	zone, ok := r.Zone(netip.MustParseAddr("10.1.0.5"))
	if !ok || zone != "zone-c" {
		t.Fatalf("got (%q,%v), want (zone-c,true)", zone, ok)
	}
	// VM 模式下 zone 與來源無關。
	zone, ok = r.Zone(netip.MustParseAddr("172.16.0.1"))
	if !ok || zone != "zone-c" {
		t.Fatalf("got (%q,%v), want (zone-c,true)", zone, ok)
	}
}

func readCounter(t *testing.T, vec *prometheus.CounterVec, label string) float64 {
	t.Helper()
	return testutil.ToFloat64(vec.WithLabelValues(label))
}
