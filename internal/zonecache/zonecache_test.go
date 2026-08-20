package zonecache

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

var base = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

// reply builds a response carrying a single A record with a TTL of ttl seconds.
func reply(name string, ttl uint32, ip string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	m.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.ParseIP(ip).To4(),
	}}
	return m
}

// TestZoneIsPartOfTheKey is this package's reason to exist: same name, same
// type, different zone must not interfere.
func TestZoneIsPartOfTheKey(t *testing.T) {
	c, err := New(16)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	c.Put("payments.example.com.", dns.TypeA, "zone-a", reply("payments.example.com.", 30, "10.96.0.7"), base)
	c.Put("payments.example.com.", dns.TypeA, "zone-b", reply("payments.example.com.", 30, "203.0.113.10"), base)

	gotA, ok := c.Get("payments.example.com.", dns.TypeA, "zone-a", base)
	if !ok {
		t.Fatal("zone-a entry missing")
	}
	if gotA.Answer[0].(*dns.A).A.String() != "10.96.0.7" {
		t.Fatalf("zone-a got %s, want 10.96.0.7", gotA.Answer[0].(*dns.A).A)
	}

	gotB, ok := c.Get("payments.example.com.", dns.TypeA, "zone-b", base)
	if !ok {
		t.Fatal("zone-b entry missing")
	}
	if gotB.Answer[0].(*dns.A).A.String() != "203.0.113.10" {
		t.Fatalf("zone-b got %s, want 203.0.113.10 — zone-a's answer leaked across zones",
			gotB.Answer[0].(*dns.A).A)
	}
}

func TestQtypeIsPartOfTheKey(t *testing.T) {
	c, _ := New(16)
	c.Put("payments.example.com.", dns.TypeA, "zone-a", reply("payments.example.com.", 30, "10.96.0.7"), base)

	if _, ok := c.Get("payments.example.com.", dns.TypeAAAA, "zone-a", base); ok {
		t.Fatal("AAAA lookup hit an A entry")
	}
}

func TestNameIsCaseInsensitive(t *testing.T) {
	c, _ := New(16)
	c.Put("payments.example.com.", dns.TypeA, "zone-a", reply("payments.example.com.", 30, "10.96.0.7"), base)

	if _, ok := c.Get("PAYMENTS.Example.COM.", dns.TypeA, "zone-a", base); !ok {
		t.Fatal("case-differing qname missed — DNS names are case-insensitive")
	}
}

// An expired entry must be a miss, never an answer with a zero or negative TTL.
func TestExpiredEntryIsAMiss(t *testing.T) {
	c, _ := New(16)
	c.Put("payments.example.com.", dns.TypeA, "zone-a", reply("payments.example.com.", 30, "10.96.0.7"), base)

	if _, ok := c.Get("payments.example.com.", dns.TypeA, "zone-a", base.Add(31*time.Second)); ok {
		t.Fatal("expired entry was served")
	}
	if _, ok := c.Get("payments.example.com.", dns.TypeA, "zone-a", base.Add(29*time.Second)); !ok {
		t.Fatal("entry expired one second early")
	}
}

// The returned TTL must have the elapsed time subtracted, or downstream keeps
// the answer longer than intended.
func TestTTLIsDecrementedByElapsedTime(t *testing.T) {
	c, _ := New(16)
	c.Put("payments.example.com.", dns.TypeA, "zone-a", reply("payments.example.com.", 30, "10.96.0.7"), base)

	got, ok := c.Get("payments.example.com.", dns.TypeA, "zone-a", base.Add(10*time.Second))
	if !ok {
		t.Fatal("entry missing")
	}
	if ttl := got.Answer[0].Header().Ttl; ttl != 20 {
		t.Fatalf("ttl = %d, want 20", ttl)
	}
}

// The caller must receive a copy — changing the returned value must not
// contaminate the cache.
func TestGetReturnsACopy(t *testing.T) {
	c, _ := New(16)
	c.Put("payments.example.com.", dns.TypeA, "zone-a", reply("payments.example.com.", 30, "10.96.0.7"), base)

	first, _ := c.Get("payments.example.com.", dns.TypeA, "zone-a", base)
	first.Answer[0].Header().Ttl = 9999
	first.Rcode = dns.RcodeServerFailure

	second, _ := c.Get("payments.example.com.", dns.TypeA, "zone-a", base)
	if second.Answer[0].Header().Ttl != 30 {
		t.Fatal("mutating a returned message corrupted the cached entry")
	}
	if second.Rcode != dns.RcodeSuccess {
		t.Fatal("mutating a returned message corrupted the rcode")
	}
}

// A response with no answers (NODATA) has no TTL to follow, so it is not cached.
func TestReplyWithoutAnswersIsNotCached(t *testing.T) {
	c, _ := New(16)
	m := new(dns.Msg)
	m.SetQuestion("payments.example.com.", dns.TypeAAAA)

	c.Put("payments.example.com.", dns.TypeAAAA, "zone-a", m, base)
	if _, ok := c.Get("payments.example.com.", dns.TypeAAAA, "zone-a", base); ok {
		t.Fatal("an answerless reply must not be cached — there is no TTL to honour")
	}
	if c.Len() != 0 {
		t.Fatalf("Len = %d, want 0", c.Len())
	}
}

// The TTL is the smallest one among the answers.
func TestExpiryUsesMinimumTTL(t *testing.T) {
	c, _ := New(16)
	m := reply("payments.example.com.", 30, "10.96.0.7")
	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: "payments.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 5},
		A:   net.ParseIP("10.96.0.8").To4(),
	})
	c.Put("payments.example.com.", dns.TypeA, "zone-a", m, base)

	if _, ok := c.Get("payments.example.com.", dns.TypeA, "zone-a", base.Add(6*time.Second)); ok {
		t.Fatal("entry outlived its smallest TTL")
	}
}

func TestEvictionBoundsSize(t *testing.T) {
	c, _ := New(2)
	for _, z := range []string{"zone-a", "zone-b", "zone-c"} {
		c.Put("payments.example.com.", dns.TypeA, z, reply("payments.example.com.", 30, "10.96.0.7"), base)
	}
	if c.Len() > 2 {
		t.Fatalf("Len = %d, want at most 2", c.Len())
	}
}

func TestNewRejectsNonPositiveSize(t *testing.T) {
	if _, err := New(0); err == nil {
		t.Fatal("expected an error for a zero-sized cache")
	}
}

// At the exact expiry boundary (remaining == 0) Get must fail. The
// implementation must use <= 0, not < 0.
func TestExactBoundaryExpiry(t *testing.T) {
	c, _ := New(16)
	c.Put("payments.example.com.", dns.TypeA, "zone-a", reply("payments.example.com.", 30, "10.96.0.7"), base)

	// At the exact moment of expiry it must fail
	if _, ok := c.Get("payments.example.com.", dns.TypeA, "zone-a", base.Add(30*time.Second)); ok {
		t.Fatal("entry served at exact expiry boundary — must check remaining <= 0, not < 0")
	}
}

// Put refuses to cache a response with a zero TTL.
func TestPutRefusesZeroTTL(t *testing.T) {
	c, _ := New(16)
	m := reply("payments.example.com.", 0, "10.96.0.7")
	c.Put("payments.example.com.", dns.TypeA, "zone-a", m, base)

	if c.Len() != 0 {
		t.Fatal("Put cached an entry with zero minTTL — it must refuse zero-TTL entries")
	}
	if _, ok := c.Get("payments.example.com.", dns.TypeA, "zone-a", base); ok {
		t.Fatal("Get returned a zero-TTL entry that should not have been cached")
	}
}

// TTLs on Ns and Extra records are decremented too, but the TTL field of the
// OPT pseudo-record holds EDNS0 flags and must not be touched.
func TestNsAndExtraRecordsTTLRewritten(t *testing.T) {
	c, _ := New(16)
	m := reply("payments.example.com.", 30, "10.96.0.7")

	// Add an Ns record
	m.Ns = []dns.RR{&dns.NS{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 30},
		Ns:  "ns1.example.com.",
	}}

	// Add an OPT pseudo-record (its TTL field holds the EDNS0 version and flags)
	m.Extra = []dns.RR{&dns.OPT{
		Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 512, Ttl: 0x00008000},
	}}

	c.Put("payments.example.com.", dns.TypeA, "zone-a", m, base)

	got, ok := c.Get("payments.example.com.", dns.TypeA, "zone-a", base.Add(10*time.Second))
	if !ok {
		t.Fatal("entry missing")
	}

	// The Ns record's TTL must be decremented
	if len(got.Ns) == 0 {
		t.Fatal("Ns record missing from copy")
	}
	if ttl := got.Ns[0].Header().Ttl; ttl != 20 {
		t.Fatalf("Ns TTL = %d, want 20 (should be decremented)", ttl)
	}

	// The OPT pseudo-record's TTL field must not change (it holds the EDNS0
	// version and flags)
	if len(got.Extra) == 0 {
		t.Fatal("OPT record missing from copy")
	}
	opt := got.Extra[0].(*dns.OPT)
	if opt.Hdr.Ttl != 0x00008000 {
		t.Fatalf("OPT TTL incorrectly modified to %d, want 0x00008000 (unchanged)", opt.Hdr.Ttl)
	}
}

// Even when the upstream answer's own TTL far exceeds maxTTL (the same-zone
// branch forwards upstream answers untouched, and those TTLs can run to hours),
// the entry must not outlive maxTTL — otherwise, once a name is registered in
// the registry or changes zone, the node keeps returning the old answer until
// that long TTL runs out.
func TestPutCapsTTLAtMax(t *testing.T) {
	c, _ := New(16)
	c.Put("payments.example.com.", dns.TypeA, "zone-a", reply("payments.example.com.", 3600, "10.96.0.7"), base)

	// Freshly stored and still short of maxTTL, it must be a hit, and the returned
	// TTL must follow maxTTL rather than the original 3600 seconds.
	got, ok := c.Get("payments.example.com.", dns.TypeA, "zone-a", base.Add(1*time.Second))
	if !ok {
		t.Fatal("entry missing before the cap")
	}
	wantTTL := uint32(maxTTL/time.Second) - 1
	if ttl := got.Answer[0].Header().Ttl; ttl != wantTTL {
		t.Fatalf("ttl = %d, want %d (capped at maxTTL, not the upstream's 3600s)", ttl, wantTTL)
	}

	// Past maxTTL it must be a miss, even though upstream's own TTL is nowhere
	// near expiry.
	if _, ok := c.Get("payments.example.com.", dns.TypeA, "zone-a", base.Add(maxTTL+time.Second)); ok {
		t.Fatal("entry outlived maxTTL despite an upstream TTL far beyond it")
	}
}

// Zone matching is case-sensitive — a zone label travels from the pod label all
// the way into the SPIFFE ID, and the case must agree throughout.
func TestZoneCaseSensitive(t *testing.T) {
	c, _ := New(16)
	c.Put("payments.example.com.", dns.TypeA, "zone-a", reply("payments.example.com.", 30, "10.96.0.7"), base)

	// Zones differing only in case must be different keys — this must not hit
	if _, ok := c.Get("payments.example.com.", dns.TypeA, "Zone-A", base); ok {
		t.Fatal("zone case folding occurred — zone must be case-sensitive")
	}
	if _, ok := c.Get("payments.example.com.", dns.TypeA, "ZONE-A", base); ok {
		t.Fatal("zone case folding occurred — zone must be case-sensitive")
	}
}
