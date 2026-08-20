package dohupstream

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/pkg/doh"
	"github.com/miekg/dns"
)

func query() *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("payments.example.com.", dns.TypeA)
	return m
}

// echoServer returns one fixed answer and hands the query it received to
// inspect.
func echoServer(t *testing.T, inspect func(*dns.Msg)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := doh.RequestToMsg(r)
		if err != nil {
			t.Errorf("server could not parse request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if inspect != nil {
			inspect(req)
		}
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
			A:   []byte{203, 0, 113, 10},
		}}
		packed, _ := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(packed)
	}))
}

func TestExchange(t *testing.T) {
	srv := echoServer(t, nil)
	defer srv.Close()

	c := NewWithHTTPClient(srv.URL, srv.Client())
	got, err := c.Exchange(context.Background(), query())
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if len(got.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(got.Answer))
	}
	if a := got.Answer[0].(*dns.A).A.String(); a != "203.0.113.10" {
		t.Fatalf("answer = %s, want 203.0.113.10", a)
	}
}

// The query upstream sees must preserve the original question and EDNS0
// contents.
func TestExchangePreservesTheQuery(t *testing.T) {
	var seen *dns.Msg
	srv := echoServer(t, func(m *dns.Msg) { seen = m })
	defer srv.Close()

	q := query()
	q.SetEdns0(4096, false)

	if _, err := NewWithHTTPClient(srv.URL, srv.Client()).Exchange(context.Background(), q); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if seen == nil {
		t.Fatal("server never saw a request")
	}
	if seen.Question[0].Name != "payments.example.com." {
		t.Fatalf("qname = %q", seen.Question[0].Name)
	}
	if seen.IsEdns0() == nil {
		t.Fatal("EDNS0 OPT record was dropped in transit")
	}
}

// The response ID must match the original query — RFC 8484 requires an ID of 0
// on the wire, and restoring it is our responsibility.
func TestExchangeRestoresMessageID(t *testing.T) {
	srv := echoServer(t, nil)
	defer srv.Close()

	q := query()
	q.Id = 0x1234

	got, err := NewWithHTTPClient(srv.URL, srv.Client()).Exchange(context.Background(), q)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if got.Id != 0x1234 {
		t.Fatalf("id = %#x, want 0x1234", got.Id)
	}
}

// Exchange must not modify the *dns.Msg the caller passed in. CoreDNS plugins
// reuse one message object across a request's lifetime, and without the internal
// .Copy() a later "simplification" would have Exchange mutate the caller's
// message directly — the ID cleared to 0, the EDNS0 options disturbed — with no
// failing test to say so.
func TestExchangeDoesNotMutateCallerMessage(t *testing.T) {
	srv := echoServer(t, nil)
	defer srv.Close()

	q := query()
	q.Id = 0x1234
	q.SetEdns0(4096, false)

	wantID := q.Id
	wantEdns0 := q.IsEdns0().String()

	if _, err := NewWithHTTPClient(srv.URL, srv.Client()).Exchange(context.Background(), q); err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	if q.Id != wantID {
		t.Fatalf("caller's message ID mutated: got %#x, want %#x", q.Id, wantID)
	}
	if opt := q.IsEdns0(); opt == nil {
		t.Fatal("caller's EDNS0 OPT record was removed")
	} else if opt.String() != wantEdns0 {
		t.Fatalf("caller's EDNS0 OPT record mutated: got %q, want %q", opt.String(), wantEdns0)
	}
}

func TestExchangeNonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	_, err := NewWithHTTPClient(srv.URL, srv.Client()).Exchange(context.Background(), query())
	if err == nil {
		t.Fatal("expected an error for a 503 response")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Fatalf("error should name the status code: %v", err)
	}
}

func TestExchangeHonoursContextCancellation(t *testing.T) {
	srv := echoServer(t, nil)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := NewWithHTTPClient(srv.URL, srv.Client()).Exchange(ctx, query()); err == nil {
		t.Fatal("expected an error from a cancelled context")
	}
}

// An upstream that hangs without answering — a network partition, a firewall
// dropping packets, a central that hung without dropping the connection — must
// not stall Exchange indefinitely, which would hold the calling goroutine and
// its underlying socket forever. The http.Client.Timeout wired in by
// buildHTTPClient must make it fail within a bounded time.
func TestExchangeTimesOutOnHangingUpstream(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	// httptest.Server.Close blocks until every outstanding handler returns —
	// the handler above is stuck on <-block until we close it, so block must
	// be closed (deferred second, so it runs first) before srv.Close (deferred
	// first, so it runs second) or Close itself would hang forever waiting on
	// a handler that never returns.
	defer srv.Close()
	defer close(block)

	hc := srv.Client()
	hc.Timeout = 100 * time.Millisecond

	start := time.Now()
	_, err := NewWithHTTPClient(srv.URL, hc).Exchange(context.Background(), query())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error from a hanging upstream")
	}
	// Leave room for scheduling jitter, but stay far below anything that would
	// count as "stalled indefinitely" — the bound here is ten times the client
	// timeout, well under the order of seconds this package has ever used to
	// simulate a hang.
	if elapsed > time.Second {
		t.Fatalf("Exchange took %s to return an error, want well under 1s (client timeout was 100ms) — "+
			"it appears to have blocked rather than honouring the client's Timeout", elapsed)
	}
}

// buildHTTPClient is the timeout logic split out of NewMTLS so it can be tested
// on its own, without a running SPIRE Workload API.
func TestBuildHTTPClientDefaultsTimeout(t *testing.T) {
	hc := buildHTTPClient(&tls.Config{}, 0)
	if hc.Timeout != defaultQueryTimeout {
		t.Fatalf("Timeout = %s, want the default %s when Config.Timeout is zero", hc.Timeout, defaultQueryTimeout)
	}
}

func TestBuildHTTPClientHonoursConfiguredTimeout(t *testing.T) {
	want := 2 * time.Second
	hc := buildHTTPClient(&tls.Config{}, want)
	if hc.Timeout != want {
		t.Fatalf("Timeout = %s, want the configured %s", hc.Timeout, want)
	}
}

// A missing central SPIFFE ID must fail at construction, never fall back to
// verifying the chain alone.
func TestNewMTLSRequiresCentralSPIFFEID(t *testing.T) {
	_, _, err := NewMTLS(context.Background(), Config{
		URL:             "https://central/dns-query",
		WorkloadAPIAddr: "unix:///nonexistent.sock",
	})
	if err == nil {
		t.Fatal("expected an error when CentralSPIFFEID is empty")
	}
	if !strings.Contains(err.Error(), "central_spiffe_id") {
		t.Fatalf("error should name the missing option: %v", err)
	}
}

// The request path Exchange sends must be exactly "/dns-query".
//
// CoreDNS's doh.NewRequestWithContext appends that path itself, so the URL the
// caller supplies must not carry one. This assumption went untested for a long
// time: the other tests all use httptest's srv.URL, which happens to carry no
// path, and echoServer accepts any path anyway — the two gaps covered for each
// other. In a real deployment a URL with a path is refused by central with an
// HTTP 404.
func TestExchangeRequestsTheDoHPathExactlyOnce(t *testing.T) {
	var seenPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		req, err := doh.RequestToMsg(r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		resp := new(dns.Msg)
		resp.SetReply(req)
		packed, _ := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(packed)
	}))
	defer srv.Close()

	if _, err := NewWithHTTPClient(srv.URL, srv.Client()).Exchange(context.Background(), query()); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if seenPath != "/dns-query" {
		t.Fatalf("request path = %q, want %q", seenPath, "/dns-query")
	}
}

// Given a URL with a path, the path is appended twice. Recorded here because the
// caller's configuration validation exists precisely to prevent it.
func TestExchangeDoublesAPathAlreadyInTheURL(t *testing.T) {
	var seenPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := NewWithHTTPClient(srv.URL+"/dns-query", srv.Client()).Exchange(context.Background(), query())
	if err == nil {
		t.Fatal("expected the doubled path to be rejected by the server")
	}
	if seenPath != "/dns-query/dns-query" {
		t.Fatalf("request path = %q, want %q — the upstream helper is expected to append the path itself",
			seenPath, "/dns-query/dns-query")
	}
}
