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

// query 建立一個帶 source zone 宣告的查詢；zone 為空字串時不加宣告。
func query(zone string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("payments.example.com.", dns.TypeA)
	if zone != "" {
		ednszone.Set(m, ednszone.DefaultCode, zone)
	}
	return m
}

// tlsWriter 建立一個帶指定憑證的 DoT writer。
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

// 沒有 TLS 就沒有身分 — 這是非 zone-aware listener 的正常路徑。
func TestSourceZoneNoTLS(t *testing.T) {
	zone, reason := cfg().SourceZone(context.Background(), &plainWriter{}, query("zone-a"))
	if reason != ReasonNoTLS {
		t.Fatalf("reason = %v, want ReasonNoTLS", reason)
	}
	if zone != "" {
		t.Fatalf("zone = %q, want empty", zone)
	}
}

// 核心攻擊情境：憑證有效（TLS 層驗過），但不是授權的 agent。
// 它的 EDNS0 宣告必須被完全忽略。
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

// 授權清單必須是精確比對，不可用前綴。
func TestSourceZoneAuthorizedListIsExactMatch(t *testing.T) {
	for _, id := range []string{
		agentID + "/extra",
		"spiffe://example.org/node/n11",
		"spiffe://evil.org/node/n1",
	} {
		w := tlsWriter(t, id)
		_, reason := cfg().SourceZone(context.Background(), w, query("zone-a"))
		if reason != ReasonUnauthorizedAgent {
			t.Fatalf("id %q: reason = %v, want ReasonUnauthorizedAgent", id, reason)
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

		_, reason := cfg().SourceZone(context.Background(), tlsWriter(t, agentID), m)
		if reason != ReasonNoDeclaration {
			t.Fatalf("zone %q: reason = %v, want ReasonNoDeclaration", bad, reason)
		}
	}
}

// 憑證沒有 SPIFFE ID 時不可被當成授權 agent。
func TestSourceZoneCertWithoutSPIFFEID(t *testing.T) {
	_, reason := cfg().SourceZone(context.Background(), tlsWriter(t, ""), query("zone-a"))
	if reason != ReasonUnauthorizedAgent {
		t.Fatalf("reason = %v, want ReasonUnauthorizedAgent", reason)
	}
}

// 只檢查葉憑證。中繼 CA 憑證即使帶著授權的 SPIFFE ID 也不算。
func TestSourceZoneOnlyLeafCertificateCounts(t *testing.T) {
	leaf := testcerts.New(t, "spiffe://example.org/workload/attacker")
	intermediate := testcerts.New(t, agentID)
	w := &dotWriter{state: &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf, intermediate},
	}}

	_, reason := cfg().SourceZone(context.Background(), w, query("zone-a"))
	if reason != ReasonUnauthorizedAgent {
		t.Fatalf("reason = %v, want ReasonUnauthorizedAgent", reason)
	}
}

// 空的授權清單表示沒有任何 agent 被授權，不是「全部放行」。
func TestSourceZoneEmptyAuthorizedListDeniesAll(t *testing.T) {
	c := NewConfig(nil, ednszone.DefaultCode)
	_, reason := c.SourceZone(context.Background(), tlsWriter(t, agentID), query("zone-a"))
	if reason != ReasonUnauthorizedAgent {
		t.Fatalf("reason = %v, want ReasonUnauthorizedAgent", reason)
	}
}

// option code 設定不一致時，宣告必須被忽略而非誤讀。
func TestSourceZoneRespectsConfiguredOptionCode(t *testing.T) {
	c := NewConfig([]string{agentID}, 65002)
	_, reason := c.SourceZone(context.Background(), tlsWriter(t, agentID), query("zone-a"))
	if reason != ReasonNoDeclaration {
		t.Fatalf("reason = %v, want ReasonNoDeclaration", reason)
	}
}
