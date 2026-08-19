package dohupstream

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/coredns/coredns/plugin/pkg/doh"
	"github.com/miekg/dns"
)

func query() *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("payments.example.com.", dns.TypeA)
	return m
}

// echoServer 回一筆固定答案，並把收到的查詢交給 inspect。
func echoServer(t *testing.T, inspect func(*dns.Msg)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := doh.RequestToMsg(r)
		if err != nil {
			t.Errorf("server could not parse request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if inspect != nil {
			inspect(req)
		}
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
			A:   []byte{203, 0, 113, 10},
		}}
		packed, _ := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(packed)
	}))
}

func TestExchange(t *testing.T) {
	srv := echoServer(t, nil)
	defer srv.Close()

	c := NewWithHTTPClient(srv.URL, srv.Client())
	got, err := c.Exchange(context.Background(), query())
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if len(got.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(got.Answer))
	}
	if a := got.Answer[0].(*dns.A).A.String(); a != "203.0.113.10" {
		t.Fatalf("answer = %s, want 203.0.113.10", a)
	}
}

// 上游看到的查詢必須保留原本的問題與 EDNS0 內容。
func TestExchangePreservesTheQuery(t *testing.T) {
	var seen *dns.Msg
	srv := echoServer(t, func(m *dns.Msg) { seen = m })
	defer srv.Close()

	q := query()
	q.SetEdns0(4096, false)

	if _, err := NewWithHTTPClient(srv.URL, srv.Client()).Exchange(context.Background(), q); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if seen == nil {
		t.Fatal("server never saw a request")
	}
	if seen.Question[0].Name != "payments.example.com." {
		t.Fatalf("qname = %q", seen.Question[0].Name)
	}
	if seen.IsEdns0() == nil {
		t.Fatal("EDNS0 OPT record was dropped in transit")
	}
}

// 回應的 ID 必須對得回原查詢 —— RFC 8484 要求送出時 ID 為 0，還原是我們的責任。
func TestExchangeRestoresMessageID(t *testing.T) {
	srv := echoServer(t, nil)
	defer srv.Close()

	q := query()
	q.Id = 0x1234

	got, err := NewWithHTTPClient(srv.URL, srv.Client()).Exchange(context.Background(), q)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if got.Id != 0x1234 {
		t.Fatalf("id = %#x, want 0x1234", got.Id)
	}
}

// Exchange 不得改動呼叫端傳入的 *dns.Msg —— CoreDNS plugin 在請求生命週期中
// 會重複使用同一個訊息物件，若少了內部的 .Copy()，日後的「簡化」會讓
// Exchange 直接改動呼叫端的訊息（ID 被清成 0、EDNS0 選項被動到），而且不會有
// 任何測試失敗提醒。
func TestExchangeDoesNotMutateCallerMessage(t *testing.T) {
	srv := echoServer(t, nil)
	defer srv.Close()

	q := query()
	q.Id = 0x1234
	q.SetEdns0(4096, false)

	wantID := q.Id
	wantEdns0 := q.IsEdns0().String()

	if _, err := NewWithHTTPClient(srv.URL, srv.Client()).Exchange(context.Background(), q); err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	if q.Id != wantID {
		t.Fatalf("caller's message ID mutated: got %#x, want %#x", q.Id, wantID)
	}
	if opt := q.IsEdns0(); opt == nil {
		t.Fatal("caller's EDNS0 OPT record was removed")
	} else if opt.String() != wantEdns0 {
		t.Fatalf("caller's EDNS0 OPT record mutated: got %q, want %q", opt.String(), wantEdns0)
	}
}

func TestExchangeNonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	_, err := NewWithHTTPClient(srv.URL, srv.Client()).Exchange(context.Background(), query())
	if err == nil {
		t.Fatal("expected an error for a 503 response")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Fatalf("error should name the status code: %v", err)
	}
}

func TestExchangeHonoursContextCancellation(t *testing.T) {
	srv := echoServer(t, nil)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := NewWithHTTPClient(srv.URL, srv.Client()).Exchange(ctx, query()); err == nil {
		t.Fatal("expected an error from a cancelled context")
	}
}

// 缺少 central SPIFFE ID 必須在建立時就失敗，不可退回成只驗憑證鏈。
func TestNewMTLSRequiresCentralSPIFFEID(t *testing.T) {
	_, _, err := NewMTLS(context.Background(), Config{
		URL:             "https://central/dns-query",
		WorkloadAPIAddr: "unix:///nonexistent.sock",
	})
	if err == nil {
		t.Fatal("expected an error when CentralSPIFFEID is empty")
	}
	if !strings.Contains(err.Error(), "central_spiffe_id") {
		t.Fatalf("error should name the missing option: %v", err)
	}
}
