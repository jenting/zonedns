package integration

import (
	"testing"

	"github.com/coredns/coredns/plugin/pkg/doh"
	"github.com/jenting/zonedns/internal/ednszone"
	"github.com/miekg/dns"
)

// answerIP returns the address of the first A record in a response, or the empty
// string when there is none.
func answerIP(m *dns.Msg) string {
	if m == nil {
		return ""
	}
	for _, rr := range m.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A.String()
		}
	}
	return ""
}

// Cross-zone: the agent declares zone-b, the registry places payments in zone-a,
// so the client must get zone-a's gateway and must not reach downstream.
func TestCrossZoneReturnsDestinationGateway(t *testing.T) {
	s := newStack(t, defaults())

	_, got := s.query(t, "payments.example.com.", dns.TypeA, "10.1.0.5")

	if ip := answerIP(got); ip != zoneAGateway {
		t.Fatalf("answer = %q, want %q", ip, zoneAGateway)
	}
	if s.downstream.called {
		t.Fatal("a cross-zone query must not reach downstream")
	}
}

// Same zone: the agent declares zone-b and orders is in zone-b too, so it goes to
// downstream rather than back as a gateway.
func TestSameZonePassesThrough(t *testing.T) {
	s := newStack(t, defaults())

	_, got := s.query(t, "orders.example.com.", dns.TypeA, "10.1.0.5")

	if !s.downstream.called {
		t.Fatal("a same-zone query should reach downstream")
	}
	if ip := answerIP(got); ip == zoneAGateway || ip == zoneBGateway {
		t.Fatalf("same zone, yet the answer is the gateway address %q", ip)
	}
}

// One name, two different declared zones, and the answers must differ. This is
// the whole system's reason to exist, and the one assertion that needs both ends
// to take part.
func TestSameNameDifferentZonesDiffer(t *testing.T) {
	crossing := newStack(t, defaults()) // zone-b asking for a zone-a name
	_, crossMsg := crossing.query(t, "payments.example.com.", dns.TypeA, "10.1.0.5")
	crossGot := answerIP(crossMsg)

	optSame := defaults()
	optSame.agentZone = "zone-a" // same zone
	sameZone := newStack(t, optSame)
	_, sameMsg := sameZone.query(t, "payments.example.com.", dns.TypeA, "10.1.0.5")
	sameGot := answerIP(sameMsg)

	if crossGot != zoneAGateway {
		t.Fatalf("cross-zone answer = %q, want %q", crossGot, zoneAGateway)
	}
	if sameGot != downstreamIP {
		t.Fatalf("same-zone answer = %q, want %q", sameGot, downstreamIP)
	}
	if crossGot == sameGot {
		t.Fatal("both zones got the same answer — the zone decision is not in effect")
	}
}

// The two ends' edns0_code disagree: central cannot read the declaration and
// silently falls back to non-zone-aware.
//
// This failure is visible only with both ends present — the node side correctly
// sends its declaration, central correctly finds nothing under the code it was
// configured with, and neither side is wrong on its own. The final review caught
// it by reading both configurations; this test turns it into an executable
// assertion.
func TestMismatchedOptionCodeSilentlyDisablesZoneRouting(t *testing.T) {
	opt := defaults()
	opt.agentEDNS0Code = 65001
	opt.centralCode = 65002
	s := newStack(t, opt)

	rcode, got := s.query(t, "payments.example.com.", dns.TypeA, "10.1.0.5")

	if !s.downstream.called {
		t.Fatal("mismatched codes should fall back to the non-zone-aware path and reach downstream")
	}
	if ip := answerIP(got); ip == zoneAGateway {
		t.Fatal("the codes disagree, yet zone routing still happened")
	}
	// Confirm it really fails quietly: the client gets an ordinary response, not an
	// error.
	if rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s; the defining trait of this failure is that it raises no error", dns.RcodeToString[rcode])
	}
}

// An unauthorized agent: the certificate is signed by the same CA and the
// handshake succeeds, but the SPIFFE ID is absent from the authorized list and
// the declaration must be ignored.
func TestUnauthorizedAgentDeclarationIgnored(t *testing.T) {
	opt := defaults()
	opt.clientSPIFFEID = rogueSPIFFEID
	s := newStack(t, opt)

	_, got := s.query(t, "payments.example.com.", dns.TypeA, "10.1.0.5")

	if !s.downstream.called {
		t.Fatal("an unauthorized source's declaration should be ignored and reach downstream")
	}
	if ip := answerIP(got); ip == zoneAGateway {
		t.Fatal("an unauthorized agent obtained a cross-zone answer")
	}
}

// An upstream URL carrying an extra path: the DoH library appends the path
// itself, so writing it once more produces /dns-query/dns-query and central
// refuses with a 404.
//
// This is exactly the bug hit in a real deployment. It escaped every existing
// test because their fake servers accepted any path — which is why the handler
// here deliberately applies the very same path check as CoreDNS.
func TestDoubledDoHPathIsRejected(t *testing.T) {
	opt := defaults()
	opt.upstreamPath = doh.Path
	s := newStack(t, opt)

	rcode, _ := s.query(t, "payments.example.com.", dns.TypeA, "10.1.0.5")

	if s.seenPath != doh.Path+doh.Path {
		t.Fatalf("central received path %q, want %q", s.seenPath, doh.Path+doh.Path)
	}
	if rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %s, want SERVFAIL — an upstream failure must be SERVFAIL and must not degrade into an ordinary answer",
			dns.RcodeToString[rcode])
	}
	if s.downstream.called {
		t.Fatal("an upstream failure must not reach downstream — that would bypass zone routing and return an answer that looks normal")
	}
}

// A client forging its own declaration: the agent must strip it unconditionally,
// and central must see only the agent's zone.
func TestClientForgedDeclarationStrippedOnTheWire(t *testing.T) {
	s := newStack(t, defaults())

	m := new(dns.Msg)
	m.SetQuestion("payments.example.com.", dns.TypeA)
	// The client claims zone-a — the same zone — trying to trade the gateway for a
	// direct address.
	ednszone.Set(m, ednszone.DefaultCode, "zone-a")

	_, got := s.queryMsg(t, m, "10.1.0.5")

	if ip := answerIP(got); ip != zoneAGateway {
		t.Fatalf("answer = %q, want %q — the zone forged by the client changed the result", ip, zoneAGateway)
	}
	if s.downstream.called {
		t.Fatal("the same-zone declaration forged by the client was believed")
	}
}
