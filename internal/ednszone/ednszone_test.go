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
	// 不可累積出兩個同 code 的 option
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
	m.SetEdns0(4096, true) // 既有的 OPT，帶 DO bit
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
	m.SetEdns0(4096, false) // 有 OPT 但沒有我們的 option
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

// Pack/Unpack 讓兩個帶同一個 code 的 EDNS0_LOCAL option 存活下來（Set 本身
// 防止單一呼叫端疊加出這種訊息，但 central 端解析的是線上位元組，不受 Set
// 保護）。Get 必須回 ok=false 而不是任選其中一個 —— 見 spec §10 的「多個 EDNS0
// option」adversarial 案例，以及本套件與 SPIFFEIDFromCert 一致的 fail-closed
// 原則。
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

	// 往返一次 wire format，確認兩個 option 真的能在 Pack/Unpack 之後存活，
	// 不是只在記憶體內的 slice 上才成立。
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
