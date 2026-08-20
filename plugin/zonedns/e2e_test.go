package zonedns

import (
	"context"
	"net/netip"
	"testing"

	"github.com/jenting/zonedns/internal/ednszone"
	"github.com/jenting/zonedns/internal/identity"
	"github.com/jenting/zonedns/internal/registry"
	"github.com/jenting/zonedns/internal/zonetable"
	"github.com/miekg/dns"
)

// This file covers the two end-to-end scenarios Task 10 calls for.
//
// The first — the full DoH path: agent certificate, the *http.Request in the
// context, the EDNS0 declaration, the registry lookup, the gateway answer — is
// already walked through step by step by TestServeDNSDoHCrossZoneAnswersGateway
// in zonedns_test.go. That test likewise builds an agent certificate with
// testcerts.New, attaches it to *http.Request.TLS, places it in the ctx under
// dnsserver.HTTPRequestKey{}, declares the EDNS0 zone, and then checks the
// response is the gateway VIP rather than downstream's answer. There is no
// material difference, so the whole construction is not repeated here.
//
// The second — TestEndToEndSameNameDifferentZones in this file — has no existing
// test that asserts both outcomes together against one registry with only the
// source zone differing. TestServeDNSSameZonePassesThrough and
// TestServeDNSCrossZoneAnswersGateway each verify one half, but both call
// newHandler to build their own store rather than sharing one instance. This is
// the whole design's only reason to exist, and deserves to be verified once,
// explicitly, on its own.

// TestEndToEndSameNameDifferentZones checks that one FQDN, one registry snapshot
// and one zone table produce entirely different answers purely because the asking
// agent declared a different source zone: the zone-a client receives downstream's
// ordinary answer, while the zone-b client receives zone-a's gateway VIP and never
// reaches downstream at all.
func TestEndToEndSameNameDifferentZones(t *testing.T) {
	store := registry.NewStore()
	snap, _ := registry.BuildSnapshot([]registry.Entry{
		{SPIFFEIDPath: "/zone/zone-a/ns/prod/sa/payments", DNSNames: []string{"payments.example.com"}},
	})
	store.Replace(snap)

	zones := zonetable.New(map[string]netip.Addr{"zone-a": netip.MustParseAddr("203.0.113.10")})

	// build gives both clients the same store and zone table, differing only in
	// Next — so the two assertions below really compare one registry's response to
	// two source zones, rather than accidentally comparing two registries that
	// happen to hold identical contents.
	build := func(next *nextCalled) ZoneDNS {
		return ZoneDNS{
			Next:     next,
			Identity: identity.NewConfig([]string{testAgentID}, ednszone.DefaultCode),
			Registry: store,
			Zones:    zones,
			TTL:      30,
		}
	}

	// The zone-a client: same zone as payments.example.com, so downstream returns
	// the ordinary answer.
	nextA := &nextCalled{}
	rA, wA := newRequest(t, "payments.example.com.", dns.TypeA, "zone-a")
	if _, err := build(nextA).ServeDNS(context.Background(), wA, rA); err != nil {
		t.Fatalf("zone-a: ServeDNS: %v", err)
	}
	if !nextA.called {
		t.Fatal("zone-a client should have reached the next plugin (same zone as payments.example.com)")
	}
	if a, isA := wA.Msg.Answer[0].(*dns.A); !isA || a.A.String() != "10.96.0.7" {
		t.Fatalf("zone-a answer = %v, want the next plugin's normal answer 10.96.0.7", wA.Msg.Answer)
	}

	// The zone-b client: cross-zone, so the answer is the gateway VIP of the zone
	// payments.example.com belongs to (zone-a), and downstream is not reached.
	nextB := &nextCalled{}
	rB, wB := newRequest(t, "payments.example.com.", dns.TypeA, "zone-b")
	if _, err := build(nextB).ServeDNS(context.Background(), wB, rB); err != nil {
		t.Fatalf("zone-b: ServeDNS: %v", err)
	}
	if nextB.called {
		t.Fatal("zone-b client (cross zone) must not reach the next plugin")
	}
	a, isA := wB.Msg.Answer[0].(*dns.A)
	if !isA || a.A.String() != "203.0.113.10" {
		t.Fatalf("zone-b answer = %v, want the zone-a gateway 203.0.113.10", wB.Msg.Answer)
	}
}
