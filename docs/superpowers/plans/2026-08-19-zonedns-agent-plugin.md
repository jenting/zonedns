# zonedns Agent Plugin Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 實作 zonedns 的節點端 CoreDNS plugin — 從查詢的 source IP 判定發問 workload 的 zone，以 zone 為 key 快取，並以 DoH over mTLS 帶著 zone 宣告向 central 查詢。

**Architecture:** 一個 CoreDNS plugin（`zonedns_agent`），編譯進自建的 node-local DNS image。三個獨立可測的單元：`podzone`（watch 本機 pod，維護 pod IP → zone）、`zonecache`（以 `(qname, qtype, zone)` 為 key 的答案快取）、`dohupstream`（釘住 central SPIFFE ID 的 mTLS DoH client）。zone 解析抽象成介面，k8s 模式用 `podzone`，VM 模式用設定檔中的固定值。

**Tech Stack:** Go、CoreDNS plugin API、miekg/dns、CoreDNS 的 `plugin/pkg/doh`、go-spiffe/v2（SVID 來源與 SPIFFE ID 釘選）、k8s.io/client-go（本機 pod informer）、hashicorp/golang-lru/v2。

**Spec:** `docs/superpowers/specs/2026-08-18-zonedns-design.md`（§7 為本計畫的範圍，§6.6 為與子專案 1 的契約）

## Global Constraints

- Go module path：`github.com/jenting/zonedns`（子專案 1 已建立，go.mod 已存在且 tidy）
- CoreDNS 版本：`github.com/coredns/coredns v1.14.6`，不可變更 —— 必須與 `sigs.k8s.io/node-local-dns` 連結的版本一致
- EDNS0 option code 一律取自 `internal/ednszone.DefaultCode`，不可另行定義常數
- 共用套件放 `internal/`；plugin 放 `plugin/zonedns_agent/`（**不可**在 `internal/` 下，外部 build 需要匯入）
- **central 的 SPIFFE ID 必須以 `tlsconfig.AuthorizeID` 釘選，且為必填設定**（spec §7.5）
- 新增相依：`k8s.io/client-go`、`k8s.io/api`、`k8s.io/apimachinery`、`github.com/hashicorp/golang-lru/v2`。每次 `go get` 後執行 `go mod tidy`
- 所有 metric 前綴 `zonedns_agent_`，遵循 CoreDNS 的 `plugin.Namespace` 慣例
- 子專案 1 已完成並合併，以下套件可直接使用：`internal/ednszone`、`internal/spiffezone`、`internal/testcerts`

---

### Task 1: `zonecache` — 以 zone 為 key 的答案快取

節點端**必須**有 zone-aware 快取（spec §7.3）：最終答案隨 zone 而異，用既有的 zone-盲
`cache` plugin 會把 zone-a 的答案回給 zone-b 的 pod。

**Files:**
- Create: `internal/zonecache/zonecache.go`
- Test: `internal/zonecache/zonecache_test.go`
- Modify: `go.mod`（加入 `github.com/hashicorp/golang-lru/v2`）

**Interfaces:**
- Consumes: 無
- Produces:
  - `zonecache.Cache` 型別
  - `zonecache.New(maxEntries int) (*Cache, error)`
  - `(*Cache).Get(qname string, qtype uint16, zone string, now time.Time) (*dns.Msg, bool)`
  - `(*Cache).Put(qname string, qtype uint16, zone string, m *dns.Msg, now time.Time)`
  - `(*Cache).Len() int`

- [ ] **Step 1: 加入 LRU 相依**

```bash
go get github.com/hashicorp/golang-lru/v2@latest
go mod tidy
```

`golang-lru/v2` 目前已是 CoreDNS 拉進來的 indirect 相依，這一步只是把它提升為直接相依。

- [ ] **Step 2: 寫失敗的測試**

建立 `internal/zonecache/zonecache_test.go`：

```go
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
		t.Fatal("mutating a returned message corrupted the cached rcode")
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
```

- [ ] **Step 3: 執行測試確認失敗**

Run: `go test ./internal/zonecache/ -v`
Expected: FAIL — `undefined: New`

- [ ] **Step 4: 寫最小實作**

建立 `internal/zonecache/zonecache.go`：

```go
// Package zonecache 是節點端的 DNS 答案快取，以 zone 作為 key 的一部分。
//
// 為什麼不能用 CoreDNS 內建的 cache plugin：它的 key 是 (qname, qtype)，不含發問者
// 的 zone。同一個名字對不同 zone 的 client 有不同的正確答案（同 zone 回服務位址、
// 跨 zone 回 gateway VIP），所以 zone-盲的快取會把某個 zone 的答案回給另一個 zone
// 的 pod —— 而且回得像模像樣，不會有任何錯誤。
package zonecache

import (
	"errors"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/miekg/dns"
)

// Cache 是有大小上限的 zone-aware 答案快取，可安全併發使用。
type Cache struct {
	mu sync.Mutex
	l  *lru.Cache[key, entry]
}

type key struct {
	qname string
	qtype uint16
	zone  string
}

type entry struct {
	msg    *dns.Msg
	expiry time.Time
}

// New 建立可容納 maxEntries 筆的快取。
func New(maxEntries int) (*Cache, error) {
	if maxEntries <= 0 {
		return nil, errors.New("zonecache: maxEntries must be positive")
	}
	l, err := lru.New[key, entry](maxEntries)
	if err != nil {
		return nil, err
	}
	return &Cache{l: l}, nil
}

// makeKey 正規化 qname —— DNS 名稱大小寫不敏感，不正規化會讓同一個名字的不同寫法
// 各佔一個快取項目，並在下游看來像是快取失效。
func makeKey(qname string, qtype uint16, zone string) key {
	return key{qname: strings.ToLower(qname), qtype: qtype, zone: zone}
}

// Put 收下一筆答案。
//
// 沒有 answer 的回應不快取：它沒有可依循的 TTL，而拿 SOA 的 minimum 做否定快取是
// 另一個決策，不在本套件範圍內。存起來的是副本，呼叫端之後改動原訊息不影響快取。
func (c *Cache) Put(qname string, qtype uint16, zone string, m *dns.Msg, now time.Time) {
	if m == nil || len(m.Answer) == 0 {
		return
	}

	minTTL := m.Answer[0].Header().Ttl
	for _, rr := range m.Answer[1:] {
		if t := rr.Header().Ttl; t < minTTL {
			minTTL = t
		}
	}
	if minTTL == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.l.Add(makeKey(qname, qtype, zone), entry{
		msg:    m.Copy(),
		expiry: now.Add(time.Duration(minTTL) * time.Second),
	})
}

// Get 取出未過期的答案，並把每筆記錄的 TTL 扣掉已經過的時間。
//
// 扣 TTL 不是修飾：若照原值回傳，下游 resolver 會從收到的那一刻重新計時，答案實際
// 存活的時間就會比我們設定的長。
func (c *Cache) Get(qname string, qtype uint16, zone string, now time.Time) (*dns.Msg, bool) {
	c.mu.Lock()
	e, ok := c.l.Get(makeKey(qname, qtype, zone))
	c.mu.Unlock()
	if !ok {
		return nil, false
	}

	remaining := e.expiry.Sub(now)
	if remaining <= 0 {
		return nil, false
	}

	out := e.msg.Copy()
	ttl := uint32(remaining / time.Second)
	for _, rr := range out.Answer {
		rr.Header().Ttl = ttl
	}
	for _, rr := range out.Ns {
		rr.Header().Ttl = ttl
	}
	for _, rr := range out.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			rr.Header().Ttl = ttl
		}
	}
	return out, true
}

// Len 回傳目前的項目數。
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.l.Len()
}
```

- [ ] **Step 5: 執行測試確認通過**

Run: `go test ./internal/zonecache/ -race -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/zonecache/
git commit -m "feat(zonecache): add zone-aware answer cache for the node-local agent"
```

---

### Task 2: `dohupstream` — 釘住 central 身分的 mTLS DoH client

**Files:**
- Create: `internal/dohupstream/dohupstream.go`
- Test: `internal/dohupstream/dohupstream_test.go`
- Modify: `go.mod`

**Interfaces:**
- Consumes: 無
- Produces:
  - `dohupstream.Client` 型別
  - `dohupstream.NewWithHTTPClient(url string, hc *http.Client) *Client`
  - `dohupstream.NewMTLS(ctx context.Context, cfg Config) (*Client, func(), error)`
  - `dohupstream.Config` 結構（欄位 `URL`、`WorkloadAPIAddr`、`CentralSPIFFEID`、`DialTimeout`）
  - `(*Client).Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error)`

- [ ] **Step 1: 加入 go-spiffe 相依**

```bash
go get github.com/spiffe/go-spiffe/v2@latest
go mod tidy
```

（子專案 1 已加入過，此步驟通常是 no-op；仍執行以確保。）

- [ ] **Step 2: 寫失敗的測試**

建立 `internal/dohupstream/dohupstream_test.go`：

```go
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
```

- [ ] **Step 3: 執行測試確認失敗**

Run: `go test ./internal/dohupstream/ -v`
Expected: FAIL — `undefined: NewWithHTTPClient`

- [ ] **Step 4: 寫最小實作**

建立 `internal/dohupstream/dohupstream.go`：

```go
// Package dohupstream 是 agent 對 central 的 DoH client。
//
// 傳輸為 DoH over mTLS：agent 以自己的 SVID 出示身分，並且**必須**以 SPIFFE ID
// 釘住 central。只驗證憑證鏈是不夠的 —— 信任域內任何一張 SVID 都能冒充 central，
// 而偽造的 central 可以回傳任意答案（例如宣稱某個同 zone 服務是跨 zone 的，並給出
// 攻擊者控制的位址），agent 對答案沒有獨立查核手段。見 spec §7.5。
package dohupstream

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/coredns/coredns/plugin/pkg/doh"
	"github.com/miekg/dns"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// defaultDialTimeout 限制取得第一份 SVID 的等待時間。
//
// workloadapi.NewX509Source 會一直阻塞到 Workload API 首次回應為止，所以沒有這個
// 上限時，SPIRE agent 尚未就緒會讓 CoreDNS 的設定解析整個卡住，沒有逾時也沒有日誌。
const defaultDialTimeout = 10 * time.Second

// Config 是建立 mTLS client 所需的設定。
type Config struct {
	URL             string
	WorkloadAPIAddr string
	CentralSPIFFEID string
	DialTimeout     time.Duration
}

// Client 對 central 發送 DoH 查詢。
type Client struct {
	url string
	hc  *http.Client
}

// NewWithHTTPClient 以既有的 http.Client 建立 Client。測試用，也讓傳輸層的設定
// 與 DNS 邏輯分離。
func NewWithHTTPClient(url string, hc *http.Client) *Client {
	return &Client{url: url, hc: hc}
}

// NewMTLS 建立以 SPIFFE 身分互相驗證的 Client。
//
// 回傳的 cleanup 必須在關閉時呼叫，以釋放 X509Source。
func NewMTLS(ctx context.Context, cfg Config) (*Client, func(), error) {
	if cfg.CentralSPIFFEID == "" {
		return nil, nil, errors.New("dohupstream: central_spiffe_id is required; " +
			"without it any SVID in the trust domain could impersonate the central server")
	}
	id, err := spiffeid.FromString(cfg.CentralSPIFFEID)
	if err != nil {
		return nil, nil, fmt.Errorf("dohupstream: invalid central_spiffe_id %q: %w", cfg.CentralSPIFFEID, err)
	}

	timeout := cfg.DialTimeout
	if timeout == 0 {
		timeout = defaultDialTimeout
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	source, err := workloadapi.NewX509Source(dialCtx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(cfg.WorkloadAPIAddr)))
	if err != nil {
		return nil, nil, fmt.Errorf("dohupstream: obtain SVID from workload_api %q within %s: %w",
			cfg.WorkloadAPIAddr, timeout, err)
	}

	// 憑證取自 X509Source 而非靜態檔案，SVID 輪替才不需要重新載入設定。
	tlsCfg := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeID(id))
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}

	return &Client{url: cfg.URL, hc: hc}, func() { source.Close() }, nil
}

// Exchange 送出查詢並回傳答案。
func (c *Client) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	// RFC 8484 要求 DoH 查詢的 DNS ID 為 0；回應的 ID 由我們還原，否則呼叫端無法
	// 把答案對回原查詢。
	originalID := m.Id
	outbound := m.Copy()
	outbound.Id = 0

	req, err := doh.NewRequestWithContext(ctx, http.MethodPost, c.url, outbound)
	if err != nil {
		return nil, fmt.Errorf("dohupstream: build request: %w", err)
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dohupstream: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("dohupstream: upstream returned HTTP %d", resp.StatusCode)
	}

	// ResponseToMsg 會關閉 body。
	answer, err := doh.ResponseToMsg(resp)
	if err != nil {
		return nil, fmt.Errorf("dohupstream: decode response: %w", err)
	}
	answer.Id = originalID
	return answer, nil
}
```

- [ ] **Step 5: 執行測試確認通過**

Run: `go test ./internal/dohupstream/ -race -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/dohupstream/
git commit -m "feat(dohupstream): add mTLS DoH client pinned to central's SPIFFE ID"
```

---

### Task 3: `podzone` — 本機 pod IP 到 zone

**Files:**
- Create: `internal/podzone/podzone.go`
- Test: `internal/podzone/podzone_test.go`
- Modify: `go.mod`（加入 `k8s.io/client-go`、`k8s.io/api`、`k8s.io/apimachinery`）

**Interfaces:**
- Consumes: 無
- Produces:
  - `podzone.Watcher` 型別
  - `podzone.New(client kubernetes.Interface, nodeName, zoneLabel string) *Watcher`
  - `(*Watcher).Run(ctx context.Context) error`
  - `(*Watcher).Zone(ip netip.Addr) (string, bool)`
  - `(*Watcher).Ready() bool`
  - `(*Watcher).Len() int`

- [ ] **Step 1: 加入 k8s 相依**

```bash
go get k8s.io/client-go@latest k8s.io/api@latest k8s.io/apimachinery@latest
go mod tidy
```

這是自建 node-local DNS image 上一筆實在的體積成本 —— 上游的 `sigs.k8s.io/node-local-dns`
只相依 `apimachinery`，不含 `client-go`。這件事要寫進部署文件（Task 6）。

- [ ] **Step 2: 寫失敗的測試**

建立 `internal/podzone/podzone_test.go`：

```go
package podzone

import (
	"context"
	"net/netip"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

const (
	nodeName  = "node-1"
	zoneLabel = "zone"
)

func pod(name, ip, zone string, hostNetwork bool) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "prod",
			Labels:    map[string]string{zoneLabel: zone},
		},
		Spec:   corev1.PodSpec{NodeName: nodeName, HostNetwork: hostNetwork},
		Status: corev1.PodStatus{PodIP: ip},
	}
}

// start 啟動 watcher 並等到就緒，回傳停止函式。
func start(t *testing.T, pods ...*corev1.Pod) (*Watcher, func()) {
	t.Helper()

	objs := make([]runtime.Object, 0, len(pods))
	for _, p := range pods {
		objs = append(objs, p)
	}
	client := fake.NewSimpleClientset(objs...)

	w := New(client, nodeName, zoneLabel)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()

	deadline := time.Now().Add(2 * time.Second)
	for !w.Ready() {
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("watcher never became ready")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return w, func() { cancel(); <-done }
}

func TestZoneFromPodIP(t *testing.T) {
	w, stop := start(t, pod("payments-abc", "10.1.0.5", "zone-a", false))
	defer stop()

	zone, ok := w.Zone(netip.MustParseAddr("10.1.0.5"))
	if !ok {
		t.Fatal("pod IP not found")
	}
	if zone != "zone-a" {
		t.Fatalf("zone = %q, want zone-a", zone)
	}
}

func TestUnknownIP(t *testing.T) {
	w, stop := start(t, pod("payments-abc", "10.1.0.5", "zone-a", false))
	defer stop()

	if _, ok := w.Zone(netip.MustParseAddr("10.1.0.99")); ok {
		t.Fatal("an unknown IP must not resolve")
	}
}

// hostNetwork pod 共用節點 IP，無法分辨彼此，因此絕不可進表 —— 否則節點 IP 會
// 對應到某一個 hostNetwork pod 的 zone，而那個對應是任意的。
func TestHostNetworkPodIsNotIndexed(t *testing.T) {
	w, stop := start(t,
		pod("payments-abc", "10.1.0.5", "zone-a", false),
		pod("node-exporter", "192.168.1.10", "zone-b", true),
	)
	defer stop()

	if _, ok := w.Zone(netip.MustParseAddr("192.168.1.10")); ok {
		t.Fatal("a hostNetwork pod was indexed; its IP is the node's and identifies nothing")
	}
	if _, ok := w.Zone(netip.MustParseAddr("10.1.0.5")); !ok {
		t.Fatal("the ordinary pod should still resolve")
	}
}

func TestPodWithoutZoneLabelIsNotIndexed(t *testing.T) {
	p := pod("legacy-abc", "10.1.0.6", "", false)
	delete(p.Labels, zoneLabel)

	w, stop := start(t, p)
	defer stop()

	if _, ok := w.Zone(netip.MustParseAddr("10.1.0.6")); ok {
		t.Fatal("a pod without the zone label must not resolve to an empty zone")
	}
}

func TestPodWithoutIPIsNotIndexed(t *testing.T) {
	w, stop := start(t, pod("pending-abc", "", "zone-a", false))
	defer stop()

	if w.Len() != 0 {
		t.Fatalf("Len = %d, want 0 — a pod with no IP yet has nothing to index", w.Len())
	}
}

// 刪除必須立刻讓映射失效。IP 會被回收給新的 pod，沿用舊值會回答錯誤的 zone。
func TestDeleteRemovesTheMapping(t *testing.T) {
	p := pod("payments-abc", "10.1.0.5", "zone-a", false)
	client := fake.NewSimpleClientset(p)

	w := New(client, nodeName, zoneLabel)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	deadline := time.Now().Add(2 * time.Second)
	for !w.Ready() {
		if time.Now().After(deadline) {
			t.Fatal("watcher never became ready")
		}
		time.Sleep(5 * time.Millisecond)
	}

	if err := client.CoreV1().Pods("prod").Delete(ctx, "payments-abc", metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete: %v", err)
	}

	deadline = time.Now().Add(2 * time.Second)
	for {
		if _, ok := w.Zone(netip.MustParseAddr("10.1.0.5")); !ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("mapping survived the pod's deletion")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// 尚未就緒時一律回 false —— 「還不知道」與「查得到但不在表裡」是不同的答案。
func TestNotReadyResolvesNothing(t *testing.T) {
	w := New(fake.NewSimpleClientset(), nodeName, zoneLabel)
	if w.Ready() {
		t.Fatal("a watcher that has not run must not report ready")
	}
	if _, ok := w.Zone(netip.MustParseAddr("10.1.0.5")); ok {
		t.Fatal("an unready watcher must not resolve")
	}
}
```

- [ ] **Step 3: 執行測試確認失敗**

Run: `go test ./internal/podzone/ -v`
Expected: FAIL — `undefined: New`

- [ ] **Step 4: 寫最小實作**

建立 `internal/podzone/podzone.go`：

```go
// Package podzone 維護本機節點上 pod IP 到 zone 的對照。
//
// 資料來自 Kubernetes API，以 spec.nodeName 過濾成只看本節點的 pod —— 數十筆，
// 不是全 cluster 的 watch。讀到的 zone label 正是產生該 pod SPIFFE ID 所用的同一個
// 值，因此節點端算出的 zone 與 central 從 registry 查到的 zone 由建構方式保證一致。
package podzone

import (
	"context"
	"net/netip"
	"sync"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// Watcher 持有本機 pod 的 IP → zone 對照。
type Watcher struct {
	client    kubernetes.Interface
	nodeName  string
	zoneLabel string

	mu    sync.RWMutex
	byIP  map[netip.Addr]string
	ready bool
}

// New 建立尚未啟動的 Watcher。
func New(client kubernetes.Interface, nodeName, zoneLabel string) *Watcher {
	return &Watcher{
		client:    client,
		nodeName:  nodeName,
		zoneLabel: zoneLabel,
		byIP:      make(map[netip.Addr]string),
	}
}

// Run 啟動 informer 並持續同步，直到 ctx 結束。
func (w *Watcher) Run(ctx context.Context) error {
	factory := informers.NewSharedInformerFactoryWithOptions(w.client, 0,
		informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
			opts.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", w.nodeName).String()
		}))

	informer := factory.Core().V1().Pods().Informer()
	if _, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { w.upsert(obj) },
		UpdateFunc: func(_, obj any) { w.upsert(obj) },
		DeleteFunc: func(obj any) { w.remove(obj) },
	}); err != nil {
		return err
	}

	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		return ctx.Err()
	}

	w.mu.Lock()
	w.ready = true
	w.mu.Unlock()

	<-ctx.Done()

	// informer 停止後，表上的內容就不再跟得上真實狀態。標回未就緒，讓查詢改走
	// 不宣告 zone 的路徑，而不是繼續拿一份會愈來愈舊的對照回答。
	w.mu.Lock()
	w.ready = false
	w.mu.Unlock()
	return nil
}

// upsert 收下一個 pod。
//
// 三種 pod 刻意不進表：
//   - hostNetwork：它的 IP 就是節點 IP，同節點上所有 hostNetwork pod 共用，
//     分辨不出是誰，任何對應都是任意的
//   - 沒有 zone label：不可對應到空字串 zone，那會被下游當成一個真的 zone
//   - 還沒拿到 IP（Pending）：沒有可索引的鍵
func (w *Watcher) upsert(obj any) {
	pod, ok := obj.(*corev1.Pod)
	if !ok || pod.Spec.HostNetwork || pod.Status.PodIP == "" {
		return
	}
	zone, ok := pod.Labels[w.zoneLabel]
	if !ok || zone == "" {
		return
	}
	ip, err := netip.ParseAddr(pod.Status.PodIP)
	if err != nil {
		return
	}

	w.mu.Lock()
	w.byIP[ip] = zone
	w.mu.Unlock()
}

// remove 移除一個 pod 的對照。
//
// 立即移除是必要的：pod IP 會被回收給新的 pod，沿用舊值會讓新 pod 拿到前一個
// 租用者的 zone —— 而那個答案看起來完全正常。
func (w *Watcher) remove(obj any) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		// informer 在 relist 時可能給出 DeletedFinalStateUnknown。
		tombstone, isTombstone := obj.(cache.DeletedFinalStateUnknown)
		if !isTombstone {
			return
		}
		pod, ok = tombstone.Obj.(*corev1.Pod)
		if !ok {
			return
		}
	}
	if pod.Status.PodIP == "" {
		return
	}
	ip, err := netip.ParseAddr(pod.Status.PodIP)
	if err != nil {
		return
	}

	w.mu.Lock()
	delete(w.byIP, ip)
	w.mu.Unlock()
}

// Zone 查出該 IP 所屬的 zone。
//
// 尚未就緒時一律回 false：啟動期間的查詢會走非 zone-aware 路徑，而不是猜一個
// 可能錯誤的 zone。
func (w *Watcher) Zone(ip netip.Addr) (string, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if !w.ready {
		return "", false
	}
	zone, ok := w.byIP[ip]
	return zone, ok
}

// Ready 回報 informer 是否已完成首次同步。
func (w *Watcher) Ready() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.ready
}

// Len 回傳目前索引的 pod 數。
func (w *Watcher) Len() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.byIP)
}
```

- [ ] **Step 5: 執行測試確認通過**

Run: `go test ./internal/podzone/ -race -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/podzone/
git commit -m "feat(podzone): index local pod IPs to zones via a node-scoped informer"
```

---

### Task 4: plugin 的查詢路徑

**Files:**
- Create: `plugin/zonedns_agent/agent.go`
- Create: `plugin/zonedns_agent/resolver.go`
- Create: `plugin/zonedns_agent/metrics.go`
- Test: `plugin/zonedns_agent/agent_test.go`

**Interfaces:**
- Consumes: `zonecache.Cache`、`dohupstream.Client`、`ednszone.Set`、`ednszone.DefaultCode`
- Produces:
  - `zonedns_agent.ZoneResolver` 介面（方法 `Zone(netip.Addr) (string, bool)`）
  - `zonedns_agent.StaticResolver` 型別與 `NewStaticResolver(zone string) StaticResolver`
  - `zonedns_agent.Upstream` 介面（方法 `Exchange(context.Context, *dns.Msg) (*dns.Msg, error)`）
  - `zonedns_agent.Agent` 結構（欄位 `Next`、`Resolver`、`Cache`、`Upstream`、`EDNS0Code`、`NodeIP`）
  - `(Agent).Name() string`
  - `(Agent).ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error)`

- [ ] **Step 1: 寫失敗的測試**

建立 `plugin/zonedns_agent/agent_test.go`：

```go
package zonedns_agent

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/jenting/zonedns/internal/ednszone"
	"github.com/jenting/zonedns/internal/zonecache"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// fakeUpstream 記錄它收到的查詢並回一筆固定答案。
type fakeUpstream struct {
	seen  []*dns.Msg
	err   error
	calls int
}

func (f *fakeUpstream) Exchange(_ context.Context, m *dns.Msg) (*dns.Msg, error) {
	f.calls++
	f.seen = append(f.seen, m.Copy())
	if f.err != nil {
		return nil, f.err
	}
	resp := new(dns.Msg)
	resp.SetReply(m)
	resp.Answer = []dns.RR{test.A("payments.example.com. 30 IN A 203.0.113.10")}
	return resp, nil
}

// writerFrom 建立一個 source IP 為 ip 的 ResponseWriter。
func writerFrom(ip string) *dnstest.Recorder {
	w := &test.ResponseWriter{}
	w.RemoteIP = ip
	return dnstest.NewRecorder(w)
}

func newAgent(t *testing.T, resolver ZoneResolver, up Upstream) Agent {
	t.Helper()
	c, err := zonecache.New(64)
	if err != nil {
		t.Fatalf("zonecache.New: %v", err)
	}
	return Agent{
		Next:      test.ErrorHandler(),
		Resolver:  resolver,
		Cache:     c,
		Upstream:  up,
		EDNS0Code: ednszone.DefaultCode,
		NodeIP:    netip.MustParseAddr("192.168.1.10"),
	}
}

func queryFor(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	return m
}

// mapResolver 是最小的 ZoneResolver 測試替身。
type mapResolver map[string]string

func (m mapResolver) Zone(ip netip.Addr) (string, bool) {
	z, ok := m[ip.String()]
	return z, ok
}

func TestServeDNSDeclaresTheSourceZone(t *testing.T) {
	up := &fakeUpstream{}
	a := newAgent(t, mapResolver{"10.1.0.5": "zone-a"}, up)

	code, err := a.ServeDNS(context.Background(), writerFrom("10.1.0.5"), queryFor("payments.example.com."))
	if err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if code != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR", code)
	}
	if up.calls != 1 {
		t.Fatalf("upstream calls = %d, want 1", up.calls)
	}

	zone, ok := ednszone.Get(up.seen[0], ednszone.DefaultCode)
	if !ok {
		t.Fatal("upstream query carried no zone declaration")
	}
	if zone != "zone-a" {
		t.Fatalf("declared zone = %q, want zone-a", zone)
	}
}

// 認不出來源時仍要轉發，但不可宣告任何 zone —— 猜一個 zone 比不宣告危險得多。
func TestServeDNSUnknownSourceDeclaresNothing(t *testing.T) {
	up := &fakeUpstream{}
	a := newAgent(t, mapResolver{}, up)

	if _, err := a.ServeDNS(context.Background(), writerFrom("10.1.0.99"), queryFor("payments.example.com.")); err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if up.calls != 1 {
		t.Fatalf("upstream calls = %d, want 1 — the query must still be answered", up.calls)
	}
	if _, ok := ednszone.Get(up.seen[0], ednszone.DefaultCode); ok {
		t.Fatal("a zone was declared for a source we could not identify")
	}
}

// 這是本套件存在的理由：同名查詢、不同 zone，不可共用快取。
func TestCacheIsKeyedByZone(t *testing.T) {
	up := &fakeUpstream{}
	a := newAgent(t, mapResolver{"10.1.0.5": "zone-a", "10.1.0.9": "zone-b"}, up)

	if _, err := a.ServeDNS(context.Background(), writerFrom("10.1.0.5"), queryFor("payments.example.com.")); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := a.ServeDNS(context.Background(), writerFrom("10.1.0.9"), queryFor("payments.example.com.")); err != nil {
		t.Fatalf("second: %v", err)
	}
	if up.calls != 2 {
		t.Fatalf("upstream calls = %d, want 2 — the second zone reused the first zone's cached answer", up.calls)
	}
}

func TestCacheHitAvoidsUpstream(t *testing.T) {
	up := &fakeUpstream{}
	a := newAgent(t, mapResolver{"10.1.0.5": "zone-a"}, up)

	for i := 0; i < 3; i++ {
		if _, err := a.ServeDNS(context.Background(), writerFrom("10.1.0.5"), queryFor("payments.example.com.")); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if up.calls != 1 {
		t.Fatalf("upstream calls = %d, want 1", up.calls)
	}
}

// 上游失敗必須是 SERVFAIL，不可交給下一個 plugin —— 那會繞過 zone 路由並回一個
// 看起來正常的直連位址。
func TestUpstreamErrorIsServfail(t *testing.T) {
	up := &fakeUpstream{err: errors.New("central unreachable")}
	a := newAgent(t, mapResolver{"10.1.0.5": "zone-a"}, up)

	code, err := a.ServeDNS(context.Background(), writerFrom("10.1.0.5"), queryFor("payments.example.com."))
	if err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if code != dns.RcodeServerFailure {
		t.Fatalf("rcode = %d, want SERVFAIL", code)
	}
}

// source IP 等於節點 IP 是 masquerade 的徵兆，必須可觀測。
func TestNodeIPSourceIsCounted(t *testing.T) {
	up := &fakeUpstream{}
	a := newAgent(t, mapResolver{}, up)

	before := readCounter(t, zoneResolutionTotal, "node_ip")
	if _, err := a.ServeDNS(context.Background(), writerFrom("192.168.1.10"), queryFor("payments.example.com.")); err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if after := readCounter(t, zoneResolutionTotal, "node_ip"); after != before+1 {
		t.Fatalf("node_ip counter = %v, want %v", after, before+1)
	}
}

func TestStaticResolver(t *testing.T) {
	r := NewStaticResolver("zone-c")
	zone, ok := r.Zone(netip.MustParseAddr("10.1.0.5"))
	if !ok || zone != "zone-c" {
		t.Fatalf("got (%q,%v), want (zone-c,true)", zone, ok)
	}
	// VM 模式下 zone 與來源無關。
	zone, ok = r.Zone(netip.MustParseAddr("172.16.0.1"))
	if !ok || zone != "zone-c" {
		t.Fatalf("got (%q,%v), want (zone-c,true)", zone, ok)
	}
}

func readCounter(t *testing.T, vec *prometheus.CounterVec, label string) float64 {
	t.Helper()
	return testutil.ToFloat64(vec.WithLabelValues(label))
}
```

- [ ] **Step 2: 執行測試確認失敗**

Run: `go test ./plugin/zonedns_agent/ -v`
Expected: FAIL — `undefined: Agent`

- [ ] **Step 3: 寫 resolver**

建立 `plugin/zonedns_agent/resolver.go`：

```go
package zonedns_agent

import "net/netip"

// ZoneResolver 從查詢的來源位址判定發問 workload 的 zone。
//
// 抽成介面是因為 k8s 與 VM 兩種部署的判定方式本質不同：k8s 上每個 pod 有自己的 IP
// 且同節點可混多個 zone，所以要逐查詢判斷；VM 上整台機器屬於同一個 zone，開機時
// 決定一次即可。
type ZoneResolver interface {
	// Zone 回傳該來源位址所屬的 zone。認不出來時回 ok=false —— 呼叫端必須把它
	// 當成「不宣告 zone」，而不是猜一個。
	Zone(src netip.Addr) (zone string, ok bool)
}

// StaticResolver 是 VM 模式的解析器：整台機器一個 zone，與來源位址無關。
type StaticResolver struct {
	zone string
}

// NewStaticResolver 建立固定回傳 zone 的解析器。
func NewStaticResolver(zone string) StaticResolver {
	return StaticResolver{zone: zone}
}

// Zone 實作 ZoneResolver。
func (s StaticResolver) Zone(netip.Addr) (string, bool) {
	if s.zone == "" {
		return "", false
	}
	return s.zone, true
}
```

- [ ] **Step 4: 寫 metrics**

建立 `plugin/zonedns_agent/metrics.go`：

```go
package zonedns_agent

import (
	"github.com/coredns/coredns/plugin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// zoneResolutionTotal 依判定結果分類。
	//
	// result="node_ip" 是最重要的一個：它表示查詢的 source IP 就是節點自己的 IP。
	// 正常情況下 pod 的查詢帶著 pod IP 抵達（node-local DNS 走 link-local 位址，
	// 不經 DNAT），所以這個數字跳升代表節點上有東西在做 SNAT/masquerade，而那會
	// 讓整個節點退化成單一 zone —— 靜默地。
	zoneResolutionTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns_agent",
		Name:      "zone_resolution_total",
		Help:      "Count of source zone resolution attempts by outcome.",
	}, []string{"result"})

	// cacheTotal 區分命中與未命中。
	cacheTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns_agent",
		Name:      "cache_total",
		Help:      "Count of zone-aware cache lookups by outcome.",
	}, []string{"result"})

	// upstreamErrorsTotal 記錄對 central 的查詢失敗次數。
	upstreamErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns_agent",
		Name:      "upstream_errors_total",
		Help:      "Count of failed DoH exchanges with the central server.",
	})

	// resolverReady 為 0 時所有查詢都不宣告 zone。
	resolverReady = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns_agent",
		Name:      "resolver_ready",
		Help:      "1 when the zone resolver has loaded its data, 0 otherwise.",
	})
)
```

- [ ] **Step 5: 寫 ServeDNS**

建立 `plugin/zonedns_agent/agent.go`：

```go
// Package zonedns_agent 是 zone-based DNS 的節點端 CoreDNS plugin。
//
// 它判定發問 workload 的 zone，以該 zone 為快取 key 的一部分，並在向 central 查詢
// 時把 zone 宣告在 EDNS0 option 裡。它只負責參與 zone 路由的網域（由 Corefile 的
// server block 界定），其餘查詢完全不經過它。
package zonedns_agent

import (
	"context"
	"net/netip"
	"time"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/jenting/zonedns/internal/ednszone"
	"github.com/jenting/zonedns/internal/zonecache"
	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin("zonedns_agent")

// timeNow 讓快取的過期判斷可在測試中控制。
var timeNow = time.Now

// Upstream 對 central 發送查詢。
type Upstream interface {
	Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error)
}

// Agent 是 plugin 的處理器。
type Agent struct {
	Next      plugin.Handler
	Resolver  ZoneResolver
	Cache     *zonecache.Cache
	Upstream  Upstream
	EDNS0Code uint16

	// NodeIP 是本機節點的位址，只用於偵測 masquerade。查詢的 source IP 等於它，
	// 代表 pod IP 在途中被改寫了。
	NodeIP netip.Addr
}

// Name 實作 plugin.Handler。
func (a Agent) Name() string { return "zonedns_agent" }

// ServeDNS 實作 plugin.Handler。
func (a Agent) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	zone, haveZone := a.resolveZone(state.IP())

	now := timeNow()
	if cached, ok := a.Cache.Get(state.Name(), state.QType(), zone, now); ok {
		cacheTotal.WithLabelValues("hit").Inc()
		cached.SetReply(r)
		if err := w.WriteMsg(cached); err != nil {
			log.Warningf("write cached reply for %q: %v", state.Name(), err)
		}
		return dns.RcodeSuccess, nil
	}
	cacheTotal.WithLabelValues("miss").Inc()

	outbound := r.Copy()
	if haveZone {
		ednszone.Set(outbound, a.EDNS0Code, zone)
	}

	answer, err := a.Upstream.Exchange(ctx, outbound)
	if err != nil {
		upstreamErrorsTotal.Inc()
		log.Errorf("upstream exchange for %q failed: %v", state.Name(), err)
		return dns.RcodeServerFailure, nil
	}

	a.Cache.Put(state.Name(), state.QType(), zone, answer, now)

	answer.SetReply(r)
	if err := w.WriteMsg(answer); err != nil {
		log.Warningf("write reply for %q: %v", state.Name(), err)
	}
	return dns.RcodeSuccess, nil
}

// resolveZone 判定來源的 zone 並記錄結果。
//
// 認不出來源時回 ok=false，呼叫端會照常轉發但不宣告 zone。這是刻意的：central 對
// 沒有宣告的查詢會走非 zone-aware 路徑並回一般答案，而在 zone 之間網路隔離的前提
// 下，那個答案要嘛可用、要嘛連不上 —— 都比猜錯 zone 把流量導向錯誤的 gateway 好。
func (a Agent) resolveZone(srcIP string) (string, bool) {
	src, err := netip.ParseAddr(srcIP)
	if err != nil {
		zoneResolutionTotal.WithLabelValues("bad_source").Inc()
		return "", false
	}
	if a.NodeIP.IsValid() && src == a.NodeIP {
		// 節點上有東西在改寫 source IP，或這是一個 hostNetwork 的 workload。
		// 兩種情況都無法分辨是哪個 workload 在問。
		zoneResolutionTotal.WithLabelValues("node_ip").Inc()
		return "", false
	}

	zone, ok := a.Resolver.Zone(src)
	if !ok {
		zoneResolutionTotal.WithLabelValues("unknown").Inc()
		return "", false
	}
	zoneResolutionTotal.WithLabelValues("ok").Inc()
	return zone, true
}
```

- [ ] **Step 6: 執行測試確認通過**

```bash
go get github.com/prometheus/client_golang@latest
go mod tidy
go test ./plugin/zonedns_agent/ -race -v
```

Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add go.mod go.sum plugin/zonedns_agent/
git commit -m "feat(zonedns_agent): resolve source zone, cache per zone, declare upstream"
```

---

### Task 5: setup — Corefile 解析與模式選擇

**Files:**
- Create: `plugin/zonedns_agent/setup.go`
- Test: `plugin/zonedns_agent/setup_test.go`

**Interfaces:**
- Consumes: Task 4 的全部型別、`podzone.New`、`dohupstream.NewMTLS`、`zonecache.New`
- Produces:
  - `zonedns_agent.CheckDirectiveOrder(directives []string) error`

- [ ] **Step 1: 寫失敗的測試**

建立 `plugin/zonedns_agent/setup_test.go`：

```go
package zonedns_agent

import (
	"strings"
	"testing"

	"github.com/coredns/caddy"
)

func TestCheckDirectiveOrder(t *testing.T) {
	if err := CheckDirectiveOrder([]string{"zonedns_agent", "cache", "forward"}); err != nil {
		t.Fatalf("valid order rejected: %v", err)
	}
}

// 順序錯了必須是啟動失敗：cache 排在前面時，zone-盲的快取會把某個 zone 的答案
// 回給另一個 zone 的 pod，而執行期看不出任何異狀。
func TestCheckDirectiveOrderRejectsCacheFirst(t *testing.T) {
	err := CheckDirectiveOrder([]string{"cache", "zonedns_agent", "forward"})
	if err == nil {
		t.Fatal("expected an error when cache precedes zonedns_agent")
	}
	if !strings.Contains(err.Error(), "cache") {
		t.Fatalf("error should name the offending directive: %v", err)
	}
}

func TestCheckDirectiveOrderMissingPlugin(t *testing.T) {
	if err := CheckDirectiveOrder([]string{"cache", "forward"}); err == nil {
		t.Fatal("expected an error when zonedns_agent is absent")
	}
}

func TestParseVMMode(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone zone-c
		upstream https://central.example.org/dns-query
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
		cache_size 4096
	}`)

	cfg, err := parseConfig(c)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.mode != modeVM {
		t.Fatalf("mode = %v, want vm", cfg.mode)
	}
	if cfg.zone != "zone-c" {
		t.Fatalf("zone = %q, want zone-c", cfg.zone)
	}
	if cfg.cacheSize != 4096 {
		t.Fatalf("cacheSize = %d, want 4096", cfg.cacheSize)
	}
}

func TestParseK8sMode(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode k8s
		node_name node-1
		zone_label zone
		upstream https://central.example.org/dns-query
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)

	cfg, err := parseConfig(c)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.mode != modeK8s {
		t.Fatalf("mode = %v, want k8s", cfg.mode)
	}
	if cfg.nodeName != "node-1" {
		t.Fatalf("nodeName = %q, want node-1", cfg.nodeName)
	}
	if cfg.zoneLabel != "zone" {
		t.Fatalf("zoneLabel = %q, want zone", cfg.zoneLabel)
	}
}

// central_spiffe_id 沒有安全的預設值：少了它就只剩憑證鏈驗證，信任域內任何一張
// SVID 都能冒充 central。
func TestParseRequiresCentralSPIFFEID(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone zone-c
		upstream https://central.example.org/dns-query
		workload_api unix:///run/spire/sockets/agent.sock
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected an error when central_spiffe_id is missing")
	}
}

func TestParseVMModeRequiresZone(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		upstream https://central.example.org/dns-query
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected an error when vm mode has no zone")
	}
}

func TestParseVMModeRejectsMalformedZone(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone zone.c
		upstream https://central.example.org/dns-query
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected an error for a zone name that the wire format cannot carry")
	}
}

func TestParseK8sModeRequiresNodeName(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode k8s
		upstream https://central.example.org/dns-query
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected an error when k8s mode has no node_name")
	}
}

func TestParseRejectsUnknownMode(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode kubernetes
		upstream https://central.example.org/dns-query
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected an error for an unrecognised mode")
	}
}

func TestParseRejectsNonPositiveCacheSize(t *testing.T) {
	for _, v := range []string{"0", "-1"} {
		c := caddy.NewTestController("dns", `zonedns_agent {
			mode vm
			zone zone-c
			upstream https://central.example.org/dns-query
			central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
			workload_api unix:///run/spire/sockets/agent.sock
			cache_size `+v+`
		}`)
		if _, err := parseConfig(c); err == nil {
			t.Fatalf("cache_size %s was accepted", v)
		}
	}
}

func TestParseRejectsMalformedCacheSize(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone zone-c
		upstream https://central.example.org/dns-query
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
		cache_size 4096abc
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("trailing garbage in cache_size was accepted")
	}
}
```

- [ ] **Step 2: 執行測試確認失敗**

Run: `go test ./plugin/zonedns_agent/ -run 'TestCheck|TestParse' -v`
Expected: FAIL — `undefined: CheckDirectiveOrder`

- [ ] **Step 3: 寫實作**

建立 `plugin/zonedns_agent/setup.go`：

```go
package zonedns_agent

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strconv"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/jenting/zonedns/internal/dohupstream"
	"github.com/jenting/zonedns/internal/ednszone"
	"github.com/jenting/zonedns/internal/podzone"
	"github.com/jenting/zonedns/internal/zonecache"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type mode int

const (
	modeUnset mode = iota
	modeK8s
	modeVM
)

const defaultCacheSize = 4096

func init() { plugin.Register("zonedns_agent", setup) }

type config struct {
	mode            mode
	zone            string // vm 模式
	nodeName        string // k8s 模式
	zoneLabel       string // k8s 模式
	upstreamURL     string
	centralSPIFFEID string
	workloadAPI     string
	cacheSize       int
	edns0Code       uint16
	nodeIP          netip.Addr
}

// CheckDirectiveOrder 確認 zonedns_agent 排在 cache 之前。
//
// 這是正確性要求而非偏好：既有的 cache plugin 以 (qname, qtype) 為 key，不含發問者
// 的 zone。若它排在前面，zone-a 的 pod 問過之後，zone-b 的 pod 會拿到同一份答案 ——
// 而且拿得像模像樣，執行期沒有任何徵兆。順序由編譯期的 plugin.cfg 決定，所以這是
// 建置設定的檢查。
func CheckDirectiveOrder(directives []string) error {
	agentAt, cacheAt := -1, -1
	for i, d := range directives {
		switch d {
		case "zonedns_agent":
			agentAt = i
		case "cache":
			cacheAt = i
		}
	}
	if agentAt < 0 {
		return fmt.Errorf("zonedns_agent is not registered in dnsserver.Directives; add it to plugin.cfg before cache")
	}
	if cacheAt >= 0 && cacheAt < agentAt {
		return fmt.Errorf("zonedns_agent must be ordered before cache in plugin.cfg, but cache is at %d and zonedns_agent at %d; "+
			"with cache first, a pod in one zone would receive an answer cached for another", cacheAt, agentAt)
	}
	return nil
}

func setup(c *caddy.Controller) error {
	if err := CheckDirectiveOrder(dnsserver.Directives); err != nil {
		return plugin.Error("zonedns_agent", err)
	}

	cfg, err := parseConfig(c)
	if err != nil {
		return plugin.Error("zonedns_agent", err)
	}

	cache, err := zonecache.New(cfg.cacheSize)
	if err != nil {
		return plugin.Error("zonedns_agent", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	up, cleanup, err := dohupstream.NewMTLS(ctx, dohupstream.Config{
		URL:             cfg.upstreamURL,
		WorkloadAPIAddr: cfg.workloadAPI,
		CentralSPIFFEID: cfg.centralSPIFFEID,
	})
	if err != nil {
		cancel()
		return plugin.Error("zonedns_agent", err)
	}

	var resolver ZoneResolver
	switch cfg.mode {
	case modeVM:
		resolver = NewStaticResolver(cfg.zone)
		resolverReady.Set(1)
	case modeK8s:
		restCfg, err := rest.InClusterConfig()
		if err != nil {
			cancel()
			cleanup()
			return plugin.Error("zonedns_agent", fmt.Errorf("in-cluster config: %w", err))
		}
		client, err := kubernetes.NewForConfig(restCfg)
		if err != nil {
			cancel()
			cleanup()
			return plugin.Error("zonedns_agent", fmt.Errorf("kubernetes client: %w", err))
		}
		w := podzone.New(client, cfg.nodeName, cfg.zoneLabel)
		resolver = w
		resolverReady.Set(0)
		c.OnStartup(func() error {
			go func() {
				if err := w.Run(ctx); err != nil {
					log.Errorf("pod watcher stopped: %v", err)
				}
			}()
			go func() {
				<-ctx.Done()
				resolverReady.Set(0)
			}()
			return nil
		})
	}

	c.OnShutdown(func() error {
		cancel()
		cleanup()
		return nil
	})

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return Agent{
			Next:      next,
			Resolver:  resolver,
			Cache:     cache,
			Upstream:  up,
			EDNS0Code: cfg.edns0Code,
			NodeIP:    cfg.nodeIP,
		}
	})
	return nil
}

func parseConfig(c *caddy.Controller) (*config, error) {
	cfg := &config{
		cacheSize: defaultCacheSize,
		edns0Code: ednszone.DefaultCode,
		zoneLabel: "zone",
	}
	if v := os.Getenv("NODE_IP"); v != "" {
		if addr, err := netip.ParseAddr(v); err == nil {
			cfg.nodeIP = addr
		}
	}

	for c.Next() {
		for c.NextBlock() {
			switch c.Val() {
			case "mode":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				switch c.Val() {
				case "k8s":
					cfg.mode = modeK8s
				case "vm":
					cfg.mode = modeVM
				default:
					return nil, c.Errf("unknown mode %q; expected k8s or vm", c.Val())
				}

			case "zone":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				cfg.zone = c.Val()

			case "node_name":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				cfg.nodeName = c.Val()

			case "zone_label":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				cfg.zoneLabel = c.Val()

			case "upstream":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				cfg.upstreamURL = c.Val()

			case "central_spiffe_id":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				cfg.centralSPIFFEID = c.Val()

			case "workload_api":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				cfg.workloadAPI = c.Val()

			case "cache_size":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				n, err := strconv.Atoi(c.Val())
				if err != nil {
					return nil, c.Errf("invalid cache_size %q: %v", c.Val(), err)
				}
				if n <= 0 {
					return nil, c.Errf("cache_size must be positive, got %d", n)
				}
				cfg.cacheSize = n

			case "node_ip":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				addr, err := netip.ParseAddr(c.Val())
				if err != nil {
					return nil, c.Errf("invalid node_ip %q: %v", c.Val(), err)
				}
				cfg.nodeIP = addr

			default:
				return nil, c.Errf("unknown property %q", c.Val())
			}
		}
	}

	if cfg.mode == modeUnset {
		return nil, c.Err("mode is required (k8s or vm)")
	}
	if cfg.upstreamURL == "" {
		return nil, c.Err("upstream is required")
	}
	// central_spiffe_id 沒有安全的預設值：少了它就只剩憑證鏈驗證，信任域內任何
	// 一張 SVID 都能冒充 central 並回傳任意答案。
	if cfg.centralSPIFFEID == "" {
		return nil, c.Err("central_spiffe_id is required; without it any SVID in the trust domain could impersonate the central server")
	}
	if cfg.workloadAPI == "" {
		return nil, c.Err("workload_api is required")
	}

	switch cfg.mode {
	case modeVM:
		if cfg.zone == "" {
			return nil, c.Err("vm mode requires zone")
		}
		// zone 名稱必須是線上格式承載得了的 —— 否則 central 會靜默忽略宣告，
		// 這台 VM 的查詢會永遠拿到不分 zone 的答案。
		if !ednszone.Valid(cfg.zone) {
			return nil, c.Errf("zone %q is not a valid zone name (letters, digits, '-' and '_' only, at most %d bytes)",
				cfg.zone, ednszone.MaxLen)
		}
	case modeK8s:
		if cfg.nodeName == "" {
			return nil, c.Err("k8s mode requires node_name")
		}
	}

	return cfg, nil
}
```

- [ ] **Step 4: 執行測試確認通過**

Run: `go test ./plugin/zonedns_agent/ -race -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add plugin/zonedns_agent/
git commit -m "feat(zonedns_agent): parse Corefile, select k8s or vm mode, enforce ordering"
```

---

### Task 6: 端到端驗證與部署文件

**Files:**
- Create: `plugin/zonedns_agent/e2e_test.go`
- Modify: `docs/deployment.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: 全部前述套件
- Produces: 無新的程式介面

- [ ] **Step 1: 寫端到端測試**

建立 `plugin/zonedns_agent/e2e_test.go`：

```go
package zonedns_agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/coredns/coredns/plugin/pkg/doh"
	"github.com/coredns/coredns/plugin/test"
	"github.com/jenting/zonedns/internal/dohupstream"
	"github.com/jenting/zonedns/internal/ednszone"
	"github.com/jenting/zonedns/internal/zonecache"
	"github.com/miekg/dns"
)

// 同一個名字、兩個不同 zone 的 pod，必須得到不同的答案，而且兩次都真的問了上游。
// 這是節點端存在的理由。
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
		packed, _ := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(packed)
	}))
	defer srv.Close()

	c, err := zonecache.New(64)
	if err != nil {
		t.Fatalf("zonecache.New: %v", err)
	}
	a := Agent{
		Next:      test.ErrorHandler(),
		Resolver:  mapResolver{"10.1.0.5": "zone-a", "10.1.0.9": "zone-b"},
		Cache:     c,
		Upstream:  dohupstream.NewWithHTTPClient(srv.URL, srv.Client()),
		EDNS0Code: ednszone.DefaultCode,
		NodeIP:    netip.MustParseAddr("192.168.1.10"),
	}

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
```

- [ ] **Step 2: 執行測試確認通過**

Run: `go test ./plugin/zonedns_agent/ -race -run TestEndToEnd -v`
Expected: PASS

- [ ] **Step 3: 更新部署文件**

在 `docs/deployment.md` 末端加入節點端的章節。內容必須涵蓋：

**建置** —— `zonedns_agent` 編譯進自建的 node-local DNS image。取得
`sigs.k8s.io/node-local-dns` 原始碼，在 `cmd/node-cache/main.go` 的 blank import
區塊加入 `_ "github.com/jenting/zonedns/plugin/zonedns_agent"`，並把
`"zonedns_agent"` 插進 `dnsserver.Directives`，**位置必須在 `"cache"` 之前**
（否則 plugin 啟動時會拒絕啟動）。用該專案既有的 `Makefile` 與
`Dockerfile.node-cache` 建置。

**image 體積** —— 明確寫出：上游的 node-local-dns 只相依 `k8s.io/apimachinery`，
不含 `client-go`。k8s 模式需要 `client-go` 做本機 pod 的 informer，因此自建 image
會明顯大於上游版本。VM 模式不需要，但 binary 是同一份。

**DaemonSet 的變更** —— 只有三處：`image` 指向自建 registry；ServiceAccount 加上
pods 的 `get/list/watch` RBAC；Corefile ConfigMap 加一個 server block。部署形態
（DaemonSet、每節點一份、link-local 位址、iptables 規則、pod 的 resolv.conf）完全
不變。

**Corefile（k8s）**：

```
cluster.local:53 { ... 既有設定完全不動 ... }

example.com:53 {
    zonedns_agent {
        mode              k8s
        node_name         # 由 downward API 注入的 NODE_NAME
        zone_label        zone
        upstream          https://central.example.org/dns-query
        central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
        workload_api      unix:///run/spire/sockets/agent.sock
        cache_size        4096
    }
}

.:53 { ... 既有 cache + forward 完全不動 ... }
```

**Corefile（VM）**：與上相同，但 `mode vm` 加 `zone <該 VM 的 zone>`，不需要
`node_name` 與 `zone_label`。

**RBAC** —— 需要的最小權限：

```yaml
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]
```

**必要的告警**（metric 名稱以 `plugin/zonedns_agent/metrics.go` 為準，不可憑記憶
撰寫，實作時請讀該檔確認 Prometheus 實際渲染出的名稱）：

| 條件 | 意義 |
|---|---|
| `zone_resolution_total{result="node_ip"}` 有非零增長 | 節點上有東西在做 SNAT/masquerade，改寫了查詢的 source IP。整個節點會靜默退化成不分 zone |
| `zone_resolution_total{result="unknown"}` 持續增長 | 有 pod 沒有 zone label，或 informer 落後於 pod 建立 |
| `resolver_ready == 0` 超過一個啟動週期 | pod watcher 未同步，所有查詢都不宣告 zone |
| `upstream_errors_total` 有非零增長 | 對 central 的 DoH 失敗；查詢會回 SERVFAIL |
| `cache_total{result="miss"}` 佔比異常高 | 快取容量不足，或 TTL 過短 |

**兩端必須成對維護的設定** —— agent 自身 SVID 的 SPIFFE ID 必須出現在 central 的
`authorized_agent` 清單中；central 的 SPIFFE ID 必須填在 agent 的
`central_spiffe_id`。任一邊漏掉，zone 路由都會靜默停止運作。

- [ ] **Step 4: 更新 README**

在 `README.md` 的元件表格加入節點端的列：

| 路徑 | 說明 |
|---|---|
| `plugin/zonedns_agent` | 節點端 CoreDNS plugin：判定來源 zone、以 zone 為 key 快取、向 central 宣告 |
| `internal/podzone` | 本機 pod IP → zone（node-scoped informer） |
| `internal/zonecache` | 以 `(qname, qtype, zone)` 為 key 的答案快取 |
| `internal/dohupstream` | 釘住 central SPIFFE ID 的 mTLS DoH client |

並在說明中補上：節點端與中心端共用 `internal/ednszone` 定義的線上格式，這是兩者
唯一的相容性介面。

- [ ] **Step 5: 執行完整測試與靜態檢查**

```bash
gofmt -l .
go vet ./...
go build ./...
go test ./... -race -cover
```

Expected: `gofmt -l .` 無輸出；vet 與 build 無警告；全部測試通過。

- [ ] **Step 6: Commit**

```bash
git add plugin/zonedns_agent/e2e_test.go docs/deployment.md README.md
git commit -m "test(zonedns_agent): add end-to-end coverage and node-side deployment docs"
```
