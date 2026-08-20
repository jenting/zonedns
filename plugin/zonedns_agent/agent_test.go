package zonedns_agent

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/jenting/zonedns/internal/ednszone"
	"github.com/jenting/zonedns/internal/zonecache"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// fakeUpstream records the query it received and returns one fixed answer.
type fakeUpstream struct {
	seen  []*dns.Msg
	err   error
	calls int

	// A non-zero rcode overrides the response's Rcode. RcodeSuccess happens to be
	// the zero value, so the default remains the original "return one successful
	// answer" behaviour.
	rcode int
	// withAnswer makes the response carry the fixed A record even when the rcode is
	// not a success — used to test how the cache path behaves on an in-band
	// failure.
	withAnswer bool
	// mismatchQuestion changes the response's Question section to a different name,
	// simulating a bug at central that sends an answer to the wrong query.
	mismatchQuestion bool
}

func (f *fakeUpstream) Exchange(_ context.Context, m *dns.Msg) (*dns.Msg, error) {
	f.calls++
	f.seen = append(f.seen, m.Copy())
	if f.err != nil {
		return nil, f.err
	}
	resp := new(dns.Msg)
	resp.SetReply(m)
	if f.mismatchQuestion {
		resp.Question = []dns.Question{{Name: "other.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	}
	if f.rcode != 0 {
		resp.Rcode = f.rcode
	}
	if f.rcode == 0 || f.withAnswer {
		resp.Answer = []dns.RR{test.A("payments.example.com. 30 IN A 203.0.113.10")}
	}
	return resp, nil
}

// writerFrom builds a ResponseWriter whose source IP is ip.
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

// mapResolver is the smallest possible ZoneResolver test double.
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

// An unrecognised source is still forwarded, but must declare no zone — guessing
// one is far more dangerous than declaring none.
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

// When the source is not identified and the query carries a forged zone
// declaration of its own, the agent must strip it — otherwise, at the very moment
// the agent cannot work out the zone, an attacker gets to choose which zone is
// declared, and central believes everything the agent forwards.
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

// With the source identified, the zone the agent determined must override any
// declaration already in the query — a client must not be able to impersonate the
// agent's judgement about its own zone.
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

// This package's reason to exist: queries for the same name from different zones
// must not share a cache entry.
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

// An upstream failure must be SERVFAIL and must not fall through to the next
// plugin — that would bypass zone routing and return a direct address that looks
// perfectly normal.
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

// When upstream responds with an in-band DNS failure such as NXDOMAIN, the client
// must see that real rcode — SetReply must not launder it into NOERROR, or a name
// that genuinely does not exist looks like one that exists with no records.
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

// The same rule applies on the cache-hit path: a message stored in the cache and
// then written back to a client must not have its original rcode laundered away
// by SetReply either.
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

// A source IP equal to the node IP is a sign of masquerading, and must be
// observable.
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

// Central's identity is pinned by mTLS, but that does not guarantee the answer it
// returns belongs to the question just asked. A bug at central — sending another
// query's answer down the wrong connection, say — must not be wrapped up untouched
// and passed to the client as a normal-looking response to a different question.
// It must be handled as an upstream failure, counted by the same metric, and
// never stored in the cache.
func TestServeDNSRejectsMismatchedUpstreamQuestion(t *testing.T) {
	up := &fakeUpstream{mismatchQuestion: true}
	a := newAgent(t, mapResolver{"10.1.0.5": "zone-a"}, up)

	before := testutil.ToFloat64(upstreamErrorsTotal)
	code, err := a.ServeDNS(context.Background(), writerFrom("10.1.0.5"), queryFor("payments.example.com."))
	if err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if code != dns.RcodeServerFailure {
		t.Fatalf("rcode = %d, want SERVFAIL for a reply answering a different question", code)
	}
	if after := testutil.ToFloat64(upstreamErrorsTotal); after != before+1 {
		t.Fatalf("upstreamErrorsTotal = %v, want %v", after, before+1)
	}
	if a.Cache.Len() != 0 {
		t.Fatal("a mismatched reply must not be cached")
	}
}

func TestAnswersQuestion(t *testing.T) {
	q := queryFor("payments.example.com.")

	matching := new(dns.Msg)
	matching.SetReply(q)
	if !answersQuestion(q, matching) {
		t.Fatal("an unmodified reply must be considered a match")
	}

	wrongName := new(dns.Msg)
	wrongName.SetReply(q)
	wrongName.Question = []dns.Question{{Name: "other.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	if answersQuestion(q, wrongName) {
		t.Fatal("a reply for a different qname must not match")
	}

	wrongType := new(dns.Msg)
	wrongType.SetReply(q)
	wrongType.Question = []dns.Question{{Name: q.Question[0].Name, Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}}
	if answersQuestion(q, wrongType) {
		t.Fatal("a reply for a different qtype must not match")
	}

	// DNS names are case-insensitive, so this must not count as a mismatch.
	caseDiffers := new(dns.Msg)
	caseDiffers.SetReply(q)
	caseDiffers.Question = []dns.Question{{Name: strings.ToUpper(q.Question[0].Name), Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	if !answersQuestion(q, caseDiffers) {
		t.Fatal("qname comparison must be case-insensitive")
	}
}

func TestStaticResolver(t *testing.T) {
	r := NewStaticResolver("zone-c")
	zone, ok := r.Zone(netip.MustParseAddr("10.1.0.5"))
	if !ok || zone != "zone-c" {
		t.Fatalf("got (%q,%v), want (zone-c,true)", zone, ok)
	}
	// Under VM mode the zone is independent of the source.
	zone, ok = r.Zone(netip.MustParseAddr("172.16.0.1"))
	if !ok || zone != "zone-c" {
		t.Fatalf("got (%q,%v), want (zone-c,true)", zone, ok)
	}
}

func readCounter(t *testing.T, vec *prometheus.CounterVec, label string) float64 {
	t.Helper()
	return testutil.ToFloat64(vec.WithLabelValues(label))
}
