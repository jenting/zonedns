package zonedns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
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

// nextCalled is a downstream plugin that records whether it was called.
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

// dotWriter simulates a DoT connection: ConnectionState is a method it declares
// itself, not one promoted from an embedded dns.ResponseWriter interface field,
// so passing *dotWriter straight into ServeDNS makes the dns.ConnectionStater
// assertion succeed.
//
// It also records the last message written (Msg), and deliberately does not wrap
// itself in a dnstest.NewRecorder: dnstest.Recorder likewise stores
// dns.ResponseWriter as an interface field, so wrapping dotWriter in one before
// passing it to ServeDNS would leave Msg's method set holding only what the
// interface itself declares, and the ConnectionState assertion would fail. That
// is precisely the "wrapping a ResponseWriter makes DoT certificate extraction
// fail silently" situation described in identity.PeerCertificates and warned
// about by this task — the tests must not walk into the same trap.
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

// dohWriter simulates the ResponseWriter of a DoH connection: it deliberately
// does not implement dns.ConnectionStater, because a real DoH server does not
// give the writer connection state either — the identity must be read from the
// *http.Request in the context (see internal/identity/peercert.go). Should
// ServeDNS ever have a bug that forgets to pass the caller's ctx down to
// SourceZone — reaching for context.Background() by mistake, say — this writer
// makes identity extraction fall straight back to "no certificate", so tests that
// depend on the DoH path really fail instead of quietly getting a certificate
// from the DoT branch and passing anyway.
type dohWriter struct {
	dns.ResponseWriter
	Msg *dns.Msg
}

func (w *dohWriter) WriteMsg(m *dns.Msg) error {
	w.Msg = m
	return w.ResponseWriter.WriteMsg(m)
}

// failingWriter simulates a write failing on the underlying connection — a client
// that has already disconnected, say. It checks that answerGateway neither
// swallows WriteMsg's error into a panic nor reports a failed write as some other
// rcode: ServeDNS must still return (dns.RcodeSuccess, nil) and simply log the
// error (see log.Errorf in zonedns.go).
type failingWriter struct {
	dns.ResponseWriter
	state *tls.ConnectionState
}

func (w *failingWriter) ConnectionState() *tls.ConnectionState { return w.state }
func (w *failingWriter) WriteMsg(*dns.Msg) error               { return errors.New("write failed") }

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

// newRequest builds a query from an authorized agent carrying the given source
// zone.
//
// Named newRequest rather than request because the zonedns package this file
// belongs to imports "github.com/coredns/coredns/request" in zonedns.go under the
// identifier request. Go does not allow one identifier in both the file block
// (imports) and the package block (top-level declarations), so even declared in a
// different file, request as a function name would collide with that import and
// fail to compile.
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

// A gateway answer must carry an OPT record back. Any query reaching this branch
// necessarily carried EDNS0 — the zone declaration travels in an EDNS0 option —
// so a response missing the OPT would be a non-EDNS answer to an EDNS0 query,
// which some resolvers treat as a format error.
func TestServeDNSCrossZoneAnswerPreservesEDNS0(t *testing.T) {
	next := &nextCalled{}
	h := newHandler(t, next)

	r, w := newRequest(t, "payments.example.com.", dns.TypeA, "zone-b")

	if _, err := h.ServeDNS(context.Background(), w, r); err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if opt := w.Msg.IsEdns0(); opt == nil {
		t.Fatal("gateway answer dropped the OPT record from an EDNS0 query")
	}
}

// When answerGateway's call to state.W.WriteMsg fails — a client disconnecting
// mid-flight, say — ServeDNS must neither panic nor return something different
// from the success case. The caller, CoreDNS's server loop, looks only at the
// (rcode, error) pair, and logging the error internally is enough.
func TestServeDNSCrossZoneWriteMsgErrorDoesNotPanic(t *testing.T) {
	next := &nextCalled{}
	h := newHandler(t, next)

	m := new(dns.Msg)
	m.SetQuestion("payments.example.com.", dns.TypeA)
	ednszone.Set(m, ednszone.DefaultCode, "zone-b")
	certs := []*x509.Certificate{testcerts.New(t, testAgentID)}
	w := &failingWriter{state: &tls.ConnectionState{PeerCertificates: certs}}

	code, err := h.ServeDNS(context.Background(), w, m)
	if err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if code != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR", code)
	}
	if next.called {
		t.Fatal("cross-zone query must not reach the next plugin even when the write fails")
	}
}

// The only transport this project supports is DoH (see warnIfDoT in setup.go),
// where identity extraction goes through the *http.Request in the context rather
// than by type-asserting the writer. This test makes sure ServeDNS really passes
// the caller's ctx down to Identity.SourceZone: were it changed to
// context.Background() by accident, every test carrying a DoT ConnectionStater
// would still pass — they take the other branch — and only this test would catch
// the regression.
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

// A query with no client cert takes the non-zone-aware path; that is not an
// error.
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

// `SourceOK: reason == identity.ReasonOK` in zonedns.go is the trust boundary's
// only gate at the ServeDNS layer. Changing it to
// `reason != identity.ReasonNoTLS` still compiles, and would wrongly treat both
// "has a certificate but is not on the authorized list" and "has a certificate and
// made no declaration" as trustworthy. Until now no ServeDNS-level test ever ran
// a cross-zone query with a certificate that was well formed but whose SPIFFE ID
// was absent from the authorized list — only internal/identity exercised that
// reason on its own, while the plugin-level tests used either an authorized
// certificate or none at all. This fills the gap: an unauthorized agent asking
// for a cross-zone name must receive the downstream (ordinary) answer, not the
// gateway VIP — and what is asserted is the response contents, not merely the
// reason or the rcode.
func TestServeDNSUnauthorizedAgentDoesNotGetGatewayAnswer(t *testing.T) {
	next := &nextCalled{}
	h := newHandler(t, next)

	m := new(dns.Msg)
	m.SetQuestion("payments.example.com.", dns.TypeA)
	ednszone.Set(m, ednszone.DefaultCode, "zone-b") // declares cross-zone; believed wrongly, it would produce a gateway answer

	// The certificate is perfectly well formed — exactly one spiffe URI SAN — the
	// SPIFFE ID simply is not on the authorized_agent list newHandler configures,
	// which holds testAgentID alone.
	unauthorizedID := "spiffe://example.org/node/intruder"
	certs := []*x509.Certificate{testcerts.New(t, unauthorizedID)}
	w := &dotWriter{
		ResponseWriter: &test.ResponseWriter{},
		state:          &tls.ConnectionState{PeerCertificates: certs},
	}

	code, err := h.ServeDNS(context.Background(), w, m)
	if err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if code != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR", code)
	}
	if !next.called {
		t.Fatal("unauthorized agent's declaration must be ignored — query must reach the next plugin")
	}
	if w.Msg == nil || len(w.Msg.Answer) != 1 {
		t.Fatalf("answers = %v, want exactly 1", w.Msg)
	}
	a, isA := w.Msg.Answer[0].(*dns.A)
	if !isA {
		t.Fatalf("answer is %T, want *dns.A", w.Msg.Answer[0])
	}
	// It must be downstream's ordinary answer (10.96.0.7, see nextCalled.ServeDNS)
	// and not zone-a's gateway VIP (203.0.113.10) — the latter would mean the
	// unauthorized zone declaration was believed.
	if a.A.String() != "10.96.0.7" {
		t.Fatalf("answer = %s, want the downstream answer 10.96.0.7 (not the gateway VIP)", a.A)
	}
}

// The registry knows this zone but the config has no gateway for it — this must
// SERVFAIL rather than quietly let the query through.
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

// An IPv4 gateway meeting an AAAA query returns NODATA (NOERROR with an empty
// answer) so the client falls back to A as usual. NXDOMAIN would tell the client
// the name does not exist.
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

// Query types other than A/AAAA are left alone — SRV, TXT and the rest are
// answered downstream as usual.
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
