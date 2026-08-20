package identity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/jenting/zonedns/internal/ednszone"
	"github.com/jenting/zonedns/internal/testcerts"
	"github.com/miekg/dns"
)

const agentID = "spiffe://example.org/node/n1"

func cfg() Config {
	return NewConfig([]string{agentID}, ednszone.DefaultCode)
}

// query builds a query carrying a source zone declaration; an empty zone adds
// no declaration.
func query(zone string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("payments.example.com.", dns.TypeA)
	if zone != "" {
		ednszone.Set(m, ednszone.DefaultCode, zone)
	}
	return m
}

// tlsWriter builds a DoT writer carrying the given certificates.
func tlsWriter(t *testing.T, uri string) dns.ResponseWriter {
	t.Helper()
	certs := []*x509.Certificate{testcerts.New(t, uri)}
	return &dotWriter{state: &tls.ConnectionState{PeerCertificates: certs}}
}

func TestSourceZoneHappyPath(t *testing.T) {
	zone, reason := cfg().SourceZone(context.Background(), tlsWriter(t, agentID), query("zone-a"))
	if reason != ReasonOK {
		t.Fatalf("reason = %v, want ReasonOK", reason)
	}
	if zone != "zone-a" {
		t.Fatalf("zone = %q, want zone-a", zone)
	}
}

// No TLS means no identity — the ordinary path for a non-zone-aware listener.
func TestSourceZoneNoTLS(t *testing.T) {
	zone, reason := cfg().SourceZone(context.Background(), &plainWriter{}, query("zone-a"))
	if reason != ReasonNoTLS {
		t.Fatalf("reason = %v, want ReasonNoTLS", reason)
	}
	if zone != "" {
		t.Fatalf("zone = %q, want empty", zone)
	}
}

// The core attack: the certificate is valid (the TLS layer verified it) but it
// is not an authorized agent. Its EDNS0 declaration must be ignored entirely.
func TestSourceZoneUnauthorizedAgentDeclarationIgnored(t *testing.T) {
	w := tlsWriter(t, "spiffe://example.org/workload/attacker")
	zone, reason := cfg().SourceZone(context.Background(), w, query("zone-a"))
	if reason != ReasonUnauthorizedAgent {
		t.Fatalf("reason = %v, want ReasonUnauthorizedAgent", reason)
	}
	if zone != "" {
		t.Fatalf("zone = %q, want empty — unauthorized declaration must not leak", zone)
	}
}

// The authorized list must match exactly, never by prefix.
func TestSourceZoneAuthorizedListIsExactMatch(t *testing.T) {
	for _, id := range []string{
		agentID + "/extra",
		"spiffe://example.org/node/n11",
		"spiffe://evil.org/node/n1",
	} {
		w := tlsWriter(t, id)
		zone, reason := cfg().SourceZone(context.Background(), w, query("zone-a"))
		if reason != ReasonUnauthorizedAgent {
			t.Fatalf("id %q: reason = %v, want ReasonUnauthorizedAgent", id, reason)
		}
		if zone != "" {
			t.Fatalf("id %q: zone = %q, want empty", id, zone)
		}
	}
}

func TestSourceZoneAuthorizedAgentWithoutDeclaration(t *testing.T) {
	zone, reason := cfg().SourceZone(context.Background(), tlsWriter(t, agentID), query(""))
	if reason != ReasonNoDeclaration {
		t.Fatalf("reason = %v, want ReasonNoDeclaration", reason)
	}
	if zone != "" {
		t.Fatalf("zone = %q, want empty", zone)
	}
}

func TestSourceZoneRejectsMalformedZone(t *testing.T) {
	for _, bad := range []string{"zone a", "zone/a", "zone..a", "../etc"} {
		m := new(dns.Msg)
		m.SetQuestion("payments.example.com.", dns.TypeA)
		ednszone.Set(m, ednszone.DefaultCode, bad)

		zone, reason := cfg().SourceZone(context.Background(), tlsWriter(t, agentID), m)
		if reason != ReasonNoDeclaration {
			t.Fatalf("zone %q: reason = %v, want ReasonNoDeclaration", bad, reason)
		}
		if zone != "" {
			t.Fatalf("bad zone %q: zone = %q, want empty", bad, zone)
		}
	}
}

// A certificate without a SPIFFE ID must not count as an authorized agent.
func TestSourceZoneCertWithoutSPIFFEID(t *testing.T) {
	zone, reason := cfg().SourceZone(context.Background(), tlsWriter(t, ""), query("zone-a"))
	if reason != ReasonUnauthorizedAgent {
		t.Fatalf("reason = %v, want ReasonUnauthorizedAgent", reason)
	}
	if zone != "" {
		t.Fatalf("zone = %q, want empty", zone)
	}
}

// Only the leaf is examined. An intermediate CA certificate does not count even
// when it carries an authorized SPIFFE ID.
func TestSourceZoneOnlyLeafCertificateCounts(t *testing.T) {
	leaf := testcerts.New(t, "spiffe://example.org/workload/attacker")
	intermediate := testcerts.New(t, agentID)
	w := &dotWriter{state: &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf, intermediate},
	}}

	zone, reason := cfg().SourceZone(context.Background(), w, query("zone-a"))
	if reason != ReasonUnauthorizedAgent {
		t.Fatalf("reason = %v, want ReasonUnauthorizedAgent", reason)
	}
	if zone != "" {
		t.Fatalf("zone = %q, want empty", zone)
	}
}

// An empty authorized list means no agent is authorized, not "let everyone
// through".
func TestSourceZoneEmptyAuthorizedListDeniesAll(t *testing.T) {
	c := NewConfig(nil, ednszone.DefaultCode)
	zone, reason := c.SourceZone(context.Background(), tlsWriter(t, agentID), query("zone-a"))
	if reason != ReasonUnauthorizedAgent {
		t.Fatalf("reason = %v, want ReasonUnauthorizedAgent", reason)
	}
	if zone != "" {
		t.Fatalf("zone = %q, want empty", zone)
	}
}

// When the configured option codes disagree, the declaration must be ignored
// rather than misread.
func TestSourceZoneRespectsConfiguredOptionCode(t *testing.T) {
	c := NewConfig([]string{agentID}, 65002)
	zone, reason := c.SourceZone(context.Background(), tlsWriter(t, agentID), query("zone-a"))
	if reason != ReasonNoDeclaration {
		t.Fatalf("reason = %v, want ReasonNoDeclaration", reason)
	}
	if zone != "" {
		t.Fatalf("zone = %q, want empty", zone)
	}
}

// Reason.String() produces a Prometheus metric label value. Reordering the iota
// would rename the metric without anyone noticing, so every constant's string is
// pinned individually, plus an out-of-range value to pin the default branch.
func TestReasonString(t *testing.T) {
	cases := []struct {
		reason Reason
		want   string
	}{
		{ReasonOK, "ok"},
		{ReasonNoTLS, "no_tls"},
		{ReasonUnauthorizedAgent, "unauthorized_agent"},
		{ReasonNoDeclaration, "no_declaration"},
		{Reason(999), "unknown"},
	}
	for _, c := range cases {
		if got := c.reason.String(); got != c.want {
			t.Fatalf("Reason(%d).String() = %q, want %q", c.reason, got, c.want)
		}
	}
}
