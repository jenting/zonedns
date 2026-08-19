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

// 在過期的精確邊界（remaining == 0）時，Get 必須失敗。實作不能用 < 0，必須用 <= 0。
func TestExactBoundaryExpiry(t *testing.T) {
	c, _ := New(16)
	c.Put("payments.example.com.", dns.TypeA, "zone-a", reply("payments.example.com.", 30, "10.96.0.7"), base)

	// 在精確的過期時刻，必須失敗
	if _, ok := c.Get("payments.example.com.", dns.TypeA, "zone-a", base.Add(30*time.Second)); ok {
		t.Fatal("entry served at exact expiry boundary — must check remaining <= 0, not < 0")
	}
}

// Put 拒絕快取 TTL 為 0 的回應。
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

// Ns 和 Extra 記錄的 TTL 也要扣掉，但 OPT 虛擬紀錄的 TTL 欄位是 EDNS0 旗標，不可改。
func TestNsAndExtraRecordsTTLRewritten(t *testing.T) {
	c, _ := New(16)
	m := reply("payments.example.com.", 30, "10.96.0.7")

	// 加入 Ns 記錄
	m.Ns = []dns.RR{&dns.NS{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 30},
		Ns:  "ns1.example.com.",
	}}

	// 加入 OPT 虛擬紀錄（TTL 欄位存放 EDNS0 擴展版本和旗標）
	m.Extra = []dns.RR{&dns.OPT{
		Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 512, Ttl: 0x00008000},
	}}

	c.Put("payments.example.com.", dns.TypeA, "zone-a", m, base)

	got, ok := c.Get("payments.example.com.", dns.TypeA, "zone-a", base.Add(10*time.Second))
	if !ok {
		t.Fatal("entry missing")
	}

	// Ns 記錄的 TTL 要扣掉時間
	if len(got.Ns) == 0 {
		t.Fatal("Ns record missing from copy")
	}
	if ttl := got.Ns[0].Header().Ttl; ttl != 20 {
		t.Fatalf("Ns TTL = %d, want 20 (should be decremented)", ttl)
	}

	// OPT 虛擬紀錄的 TTL 欄位不能改（包含 EDNS0 擴展版本和旗標）
	if len(got.Extra) == 0 {
		t.Fatal("OPT record missing from copy")
	}
	opt := got.Extra[0].(*dns.OPT)
	if opt.Hdr.Ttl != 0x00008000 {
		t.Fatalf("OPT TTL incorrectly modified to %d, want 0x00008000 (unchanged)", opt.Hdr.Ttl)
	}
}

// 即使上游答案自帶的 TTL 遠超過 maxTTL（例如同 zone 分支直接轉發上游答案，
// TTL 可能長達數小時），實際存活時間也不可超過 maxTTL —— 否則一個名字被登記
// 進 registry 或改了 zone 之後，節點會繼續回覆舊答案直到那個很長的 TTL 走完。
func TestPutCapsTTLAtMax(t *testing.T) {
	c, _ := New(16)
	c.Put("payments.example.com.", dns.TypeA, "zone-a", reply("payments.example.com.", 3600, "10.96.0.7"), base)

	// 剛存進去、還沒到 maxTTL 之前必須是 hit，且回傳的 TTL 以 maxTTL（不是
	// 原始的 3600 秒）為準。
	got, ok := c.Get("payments.example.com.", dns.TypeA, "zone-a", base.Add(1*time.Second))
	if !ok {
		t.Fatal("entry missing before the cap")
	}
	wantTTL := uint32(maxTTL/time.Second) - 1
	if ttl := got.Answer[0].Header().Ttl; ttl != wantTTL {
		t.Fatalf("ttl = %d, want %d (capped at maxTTL, not the upstream's 3600s)", ttl, wantTTL)
	}

	// 過了 maxTTL 之後必須是 miss，即使上游原本給的 TTL 遠遠沒到期。
	if _, ok := c.Get("payments.example.com.", dns.TypeA, "zone-a", base.Add(maxTTL+time.Second)); ok {
		t.Fatal("entry outlived maxTTL despite an upstream TTL far beyond it")
	}
}

// Zone 匹配是大小寫敏感的 —— zone 標籤從 pod label 一路傳到 SPIFFE ID，大小寫必須一致。
func TestZoneCaseSensitive(t *testing.T) {
	c, _ := New(16)
	c.Put("payments.example.com.", dns.TypeA, "zone-a", reply("payments.example.com.", 30, "10.96.0.7"), base)

	// 不同大小寫的 zone 必須是不同的 key —— 不應該命中
	if _, ok := c.Get("payments.example.com.", dns.TypeA, "Zone-A", base); ok {
		t.Fatal("zone case folding occurred — zone must be case-sensitive")
	}
	if _, ok := c.Get("payments.example.com.", dns.TypeA, "ZONE-A", base); ok {
		t.Fatal("zone case folding occurred — zone must be case-sensitive")
	}
}
