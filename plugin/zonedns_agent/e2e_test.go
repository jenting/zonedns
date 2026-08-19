package zonedns_agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/coredns/coredns/plugin/pkg/doh"
	"github.com/coredns/coredns/plugin/test"
	"github.com/jenting/zonedns/internal/dohupstream"
	"github.com/jenting/zonedns/internal/ednszone"
	"github.com/miekg/dns"
)

// 同一個名字、兩個不同 zone 的 pod，必須得到不同的答案，而且兩次都真的問了上游。
// 這是節點端存在的理由。跟 agent_test.go 裡以 fakeUpstream 直接傳遞 *dns.Msg 的
// 單元測試不同，這裡走真正的 DoH wire 編碼／解碼（httptest server +
// dohupstream.NewWithHTTPClient），驗證的是整條路徑，不是個別函式。
func TestEndToEndSameNameDifferentZones(t *testing.T) {
	var declared []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := doh.RequestToMsg(r)
		if err != nil {
			t.Errorf("parse request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		zone, _ := ednszone.Get(req, ednszone.DefaultCode)
		declared = append(declared, zone)

		// central 的行為：zone-a 是同 zone（回服務位址），其餘回 gateway。
		addr := "203.0.113.10"
		if zone == "zone-a" {
			addr = "10.96.0.7"
		}
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = []dns.RR{test.A("payments.example.com. 30 IN A " + addr)}
		packed, err := resp.Pack()
		if err != nil {
			t.Errorf("pack response: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(packed)
	}))
	defer srv.Close()

	a := newAgent(t, mapResolver{"10.1.0.5": "zone-a", "10.1.0.9": "zone-b"},
		dohupstream.NewWithHTTPClient(srv.URL, srv.Client()))

	recA := writerFrom("10.1.0.5")
	if _, err := a.ServeDNS(context.Background(), recA, queryFor("payments.example.com.")); err != nil {
		t.Fatalf("zone-a: %v", err)
	}
	recB := writerFrom("10.1.0.9")
	if _, err := a.ServeDNS(context.Background(), recB, queryFor("payments.example.com.")); err != nil {
		t.Fatalf("zone-b: %v", err)
	}

	if len(declared) != 2 {
		t.Fatalf("upstream saw %d queries, want 2 — the second zone reused the first's cached answer", len(declared))
	}
	if declared[0] != "zone-a" || declared[1] != "zone-b" {
		t.Fatalf("declared zones = %v, want [zone-a zone-b]", declared)
	}

	gotA := recA.Msg.Answer[0].(*dns.A).A.String()
	gotB := recB.Msg.Answer[0].(*dns.A).A.String()
	if gotA != "10.96.0.7" {
		t.Fatalf("zone-a answer = %s, want 10.96.0.7", gotA)
	}
	if gotB != "203.0.113.10" {
		t.Fatalf("zone-b answer = %s, want 203.0.113.10", gotB)
	}
}
