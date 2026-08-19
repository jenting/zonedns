package dohupstream

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

// 一個掛住不回應的上游（網路分斷、防火牆丟包、central 掛死但連線沒斷）不可
// 讓 Exchange 無限期卡住 —— 那會讓呼叫它的 goroutine 與底層 socket 永遠佔用。
// buildHTTPClient 接上的 http.Client.Timeout 必須讓它在有限時間內回錯。
func TestExchangeTimesOutOnHangingUpstream(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	// httptest.Server.Close blocks until every outstanding handler returns —
	// the handler above is stuck on <-block until we close it, so block must
	// be closed (deferred second, so it runs first) before srv.Close (deferred
	// first, so it runs second) or Close itself would hang forever waiting on
	// a handler that never returns.
	defer srv.Close()
	defer close(block)

	hc := srv.Client()
	hc.Timeout = 100 * time.Millisecond

	start := time.Now()
	_, err := NewWithHTTPClient(srv.URL, hc).Exchange(context.Background(), query())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error from a hanging upstream")
	}
	// 給排程餘裕留一點空間，但必須遠低於「無限期卡住」的意思 —— 這裡用
	// client 逾時的 10 倍當上限，遠低於這個套件過去任何一次會拿來模擬掛住的
	// 秒數量級。
	if elapsed > time.Second {
		t.Fatalf("Exchange took %s to return an error, want well under 1s (client timeout was 100ms) — "+
			"it appears to have blocked rather than honouring the client's Timeout", elapsed)
	}
}

// buildHTTPClient 是 NewMTLS 的逾時邏輯拆出來的部分，讓它可以在不需要一個真的
// 在跑的 SPIRE Workload API 的情況下單獨測試。
func TestBuildHTTPClientDefaultsTimeout(t *testing.T) {
	hc := buildHTTPClient(&tls.Config{}, 0)
	if hc.Timeout != defaultQueryTimeout {
		t.Fatalf("Timeout = %s, want the default %s when Config.Timeout is zero", hc.Timeout, defaultQueryTimeout)
	}
}

func TestBuildHTTPClientHonoursConfiguredTimeout(t *testing.T) {
	want := 2 * time.Second
	hc := buildHTTPClient(&tls.Config{}, want)
	if hc.Timeout != want {
		t.Fatalf("Timeout = %s, want the configured %s", hc.Timeout, want)
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

// Exchange 送出的請求路徑必須恰好是 "/dns-query"。
//
// CoreDNS 的 doh.NewRequestWithContext 自己會接上那段路徑，所以呼叫端給的 URL
// 不可再帶路徑。這個假設一直沒有被測到：其他測試都用 httptest 的 srv.URL（剛好
// 不帶路徑），而 echoServer 又接受任何路徑，兩邊互補地遮蔽了它 —— 實際部署時
// 帶路徑的 URL 會被 central 以 HTTP 404 拒絕。
func TestExchangeRequestsTheDoHPathExactlyOnce(t *testing.T) {
	var seenPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		req, err := doh.RequestToMsg(r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		resp := new(dns.Msg)
		resp.SetReply(req)
		packed, _ := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(packed)
	}))
	defer srv.Close()

	if _, err := NewWithHTTPClient(srv.URL, srv.Client()).Exchange(context.Background(), query()); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if seenPath != "/dns-query" {
		t.Fatalf("request path = %q, want %q", seenPath, "/dns-query")
	}
}

// 給了帶路徑的 URL，路徑會被重複附加 —— 記錄這個上游行為，因為呼叫端的設定
// 驗證正是為了擋下它而存在。
func TestExchangeDoublesAPathAlreadyInTheURL(t *testing.T) {
	var seenPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := NewWithHTTPClient(srv.URL+"/dns-query", srv.Client()).Exchange(context.Background(), query())
	if err == nil {
		t.Fatal("expected the doubled path to be rejected by the server")
	}
	if seenPath != "/dns-query/dns-query" {
		t.Fatalf("request path = %q, want %q — the upstream helper is expected to append the path itself",
			seenPath, "/dns-query/dns-query")
	}
}
