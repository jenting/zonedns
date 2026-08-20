package ednszone

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func newQuery() *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("payments.example.com.", dns.TypeA)
	return m
}

func TestSetThenGet(t *testing.T) {
	m := newQuery()
	Set(m, DefaultCode, "zone-a")

	got, ok := Get(m, DefaultCode)
	if !ok {
		t.Fatal("Get returned ok=false after Set")
	}
	if got != "zone-a" {
		t.Fatalf("got %q, want %q", got, "zone-a")
	}
}

func TestSetIsIdempotent(t *testing.T) {
	m := newQuery()
	Set(m, DefaultCode, "zone-a")
	Set(m, DefaultCode, "zone-b")

	got, ok := Get(m, DefaultCode)
	if !ok || got != "zone-b" {
		t.Fatalf("got (%q,%v), want (zone-b,true)", got, ok)
	}
	// Two options with the same code must not accumulate
	opt := m.IsEdns0()
	n := 0
	for _, o := range opt.Option {
		if l, isLocal := o.(*dns.EDNS0_LOCAL); isLocal && l.Code == DefaultCode {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("found %d options with code %d, want 1", n, DefaultCode)
	}
}

func TestSetPreservesExistingOPT(t *testing.T) {
	m := newQuery()
	m.SetEdns0(4096, true) // an existing OPT, with the DO bit set
	Set(m, DefaultCode, "zone-a")

	opt := m.IsEdns0()
	if opt == nil {
		t.Fatal("OPT record was removed")
	}
	if opt.UDPSize() != 4096 {
		t.Fatalf("UDPSize = %d, want 4096", opt.UDPSize())
	}
	if !opt.Do() {
		t.Fatal("DO bit was cleared")
	}
}

func TestGetMissing(t *testing.T) {
	if _, ok := Get(newQuery(), DefaultCode); ok {
		t.Fatal("expected ok=false when no OPT present")
	}

	m := newQuery()
	m.SetEdns0(4096, false) // an OPT, but not carrying our option
	if _, ok := Get(m, DefaultCode); ok {
		t.Fatal("expected ok=false when option absent")
	}
}

func TestGetWrongCodeIgnored(t *testing.T) {
	m := newQuery()
	Set(m, 65002, "zone-a")
	if _, ok := Get(m, DefaultCode); ok {
		t.Fatal("option with a different code must not be read")
	}
}

func TestGetRejectsInvalidZone(t *testing.T) {
	for _, bad := range []string{"", "zone a", "zone/a", "zone.a", strings.Repeat("z", MaxLen+1), "zone\x00a"} {
		m := newQuery()
		Set(m, DefaultCode, bad)
		if _, ok := Get(m, DefaultCode); ok {
			t.Fatalf("Get accepted invalid zone %q", bad)
		}
	}
}

// Pack/Unpack lets two EDNS0_LOCAL options with the same code survive (Set
// itself prevents a single caller from stacking them up, but central parses
// bytes off the wire and is not protected by Set). Get must return ok=false
// rather than pick one — see the "multiple EDNS0 options" adversarial case in
// spec §10, and this package's fail-closed principle, shared with
// SPIFFEIDFromCert.
func TestGetRejectsDuplicateOption(t *testing.T) {
	m := newQuery()
	opt := m.IsEdns0()
	if opt == nil {
		m.SetEdns0(dns.DefaultMsgSize, false)
		opt = m.IsEdns0()
	}
	opt.Option = append(opt.Option,
		&dns.EDNS0_LOCAL{Code: DefaultCode, Data: []byte("zone-a")},
		&dns.EDNS0_LOCAL{Code: DefaultCode, Data: []byte("zone-b")},
	)

	// Round-trip through the wire format, to confirm both options really survive
	// Pack/Unpack rather than only holding in an in-memory slice.
	packed, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	unpacked := new(dns.Msg)
	if err := unpacked.Unpack(packed); err != nil {
		t.Fatalf("Unpack: %v", err)
	}

	if _, ok := Get(unpacked, DefaultCode); ok {
		t.Fatal("Get accepted a message with two options carrying the same code")
	}
}

func TestValid(t *testing.T) {
	for _, good := range []string{"zone-a", "z", "zone_1", "ZoneA", strings.Repeat("z", MaxLen)} {
		if !Valid(good) {
			t.Fatalf("Valid(%q) = false, want true", good)
		}
	}
}
