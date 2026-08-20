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

// One name, two pods in different zones, and the answers must differ — with
// upstream really queried both times. This is the node side's reason to exist.
// Unlike the unit tests in agent_test.go, which pass a *dns.Msg straight through
// a fakeUpstream, this goes through real DoH wire encoding and decoding (an
// httptest server plus dohupstream.NewWithHTTPClient), verifying the whole path
// rather than individual functions.
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

		// Central's behaviour: zone-a is the same zone (the service address comes
		// back), everything else gets the gateway.
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
