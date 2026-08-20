// Package integration tests the node side and the central side wired together.
//
// Why it is needed: the two ends share no code, only the wire format defined by
// internal/ednszone. Each side's unit tests verify that format on its own side,
// so if both sides misunderstand it in the same way, both stay green. The
// mistake surfaces only in a real deployment — and the symptom is usually
// "queries still return answers, they just stop distinguishing zones", with no
// error at all.
//
// This harness runs the real Agent.ServeDNS through a real mTLS handshake into
// the real ZoneDNS.ServeDNS, substituting neither end's logic.
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

// options lets each case override only what it cares about, with consistent
// defaults for the rest.
type options struct {
	agentZone      string // the zone the agent declares
	agentEDNS0Code uint16 // the option code the node side uses
	centralCode    uint16 // the option code central expects
	clientSPIFFEID string // the identity in the certificate the agent presents
	upstreamPath   string // path appended to the upstream URL, to reproduce the doubled-path bug
}

func defaults() options {
	return options{
		agentZone:      "zone-b",
		agentEDNS0Code: ednszone.DefaultCode,
		centralCode:    ednszone.DefaultCode,
		clientSPIFFEID: agentSPIFFEID,
	}
}

// downstream stands in for the ordinary DNS behind central — same-zone names, and
// names that are not zonedns's business, end up here. It returns one fixed
// address so tests can tell zone routing from its absence.
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

// stack is the two ends wired together.
type stack struct {
	agent      agentplugin.Agent
	downstream *downstream
	server     *httptest.Server
	// seenPath records the HTTP path central actually received.
	seenPath string
}

func (s *stack) Close() { s.server.Close() }

// query sends a query from a client's point of view.
//
// It returns the rcode and the message written. The message may be nil — the
// failure path deliberately writes no response of its own, because
// plugin.ClientWrite(RcodeServerFailure) is false and CoreDNS's server produces
// that response instead. Assertions about failure must look at the rcode, not at
// the message contents.
func (s *stack) query(t *testing.T, qname string, qtype uint16, clientIP string) (int, *dns.Msg) {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	return s.queryMsg(t, m, clientIP)
}

// queryMsg sends a query the caller assembled — used to simulate a client
// carrying EDNS0 contents of its own making.
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

// newStack wires the two ends together.
//
// The central side deliberately parses requests with CoreDNS's own doh package
// and applies exactly the path check CoreDNS's DoH server applies
// (r.URL.Path == doh.Path). A permissive test double reproduces the very blind
// spot it exists to prevent: in a real deployment an upstream URL carrying an
// extra path makes central answer 404, and a fake server that accepts any path
// would never reveal it.
func newStack(t *testing.T, opt options) *stack {
	t.Helper()

	ca := testcerts.NewCA(t)
	serverCert := ca.Issue(t, centralSPIFFEID)
	clientCert := ca.Issue(t, opt.clientSPIFFEID)

	// ── Central side: the real ZoneDNS handler
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
		// The same check CoreDNS's DoH server applies, word for word.
		if r.URL.Path != doh.Path {
			http.Error(w, "", http.StatusNotFound)
			return
		}
		req, err := doh.RequestToMsg(r)
		if err != nil {
			http.Error(w, "", http.StatusBadRequest)
			return
		}
		// CoreDNS's DoH server puts the *http.Request into the context, and that is
		// where identity takes the peer certificate from.
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

	// ── Node side: the real Agent, connecting to that server over real mTLS
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

// staticZone resolves every query to the same zone — what is under test here is
// the protocol between the two ends, not how the node side determines the zone
// (podzone has its own tests for that).
type staticZone string

func (z staticZone) Zone(netip.Addr) (string, bool) {
	if z == "" {
		return "", false
	}
	return string(z), true
}

var _ plugin.Handler = (*downstream)(nil)
