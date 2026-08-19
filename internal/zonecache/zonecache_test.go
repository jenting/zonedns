package zonecache

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

var base = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

// reply 建立一筆帶單一 A 記錄的回應，TTL 為 ttl 秒。
func reply(name string, ttl uint32, ip string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	m.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.ParseIP(ip).To4(),
	}}
	return m
}

// TestZoneIsPartOfTheKey 是這個套件存在的理由：同名同型別、不同 zone 必須互不干擾。
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

// 過期的項目必須是 miss，不可回一個 TTL 為 0 或負數的答案。
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

// 回傳的 TTL 必須扣掉已經過的時間，否則下游會把答案留得比我們預期更久。
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

// 呼叫端拿到的必須是副本 —— 改動回傳值不可污染快取。
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

// 沒有 answer 的回應（NODATA）也要能快取，但沒有 TTL 可循，因此不快取。
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

// TTL 取 answer 中最小的一個。
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
