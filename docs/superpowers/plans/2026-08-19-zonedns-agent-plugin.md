# zonedns Agent Plugin Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement zonedns's node-side CoreDNS plugin — determine the asking workload's zone from a query's source IP, key the cache by that zone, and query central over DoH with mTLS carrying the zone declaration.

**Architecture:** One CoreDNS plugin, `zonedns_agent`, compiled into a self-built node-local DNS image. Three independently testable units: `podzone` (watches local pods and maintains pod IP → zone), `zonecache` (an answer cache keyed by `(qname, qtype, zone)`) and `dohupstream` (an mTLS DoH client pinning central's SPIFFE ID). Zone resolution is abstracted behind an interface: k8s mode uses `podzone`, VM mode a fixed value from configuration.

**Tech Stack:** Go, the CoreDNS plugin API, miekg/dns, CoreDNS's `plugin/pkg/doh`, go-spiffe/v2 (the SVID source and SPIFFE ID pinning), k8s.io/client-go (the local pod informer), hashicorp/golang-lru/v2.

**Spec:** `docs/superpowers/specs/2026-08-18-zonedns-design.md` — §7 is this plan's scope, §6.6 is the contract with subproject 1

## Global Constraints

- Go module path: `github.com/jenting/zonedns`, created by subproject 1; go.mod already exists and is tidy
- CoreDNS version: `github.com/coredns/coredns v1.14.6`, not to be changed — it must match the version `sigs.k8s.io/node-local-dns` links against
- The EDNS0 option code always comes from `internal/ednszone.DefaultCode`; no separate constant may be defined
- Shared packages go in `internal/`; the plugin goes in `plugin/zonedns_agent/` and **must not** be under `internal/`, because external builds need to import it
- **Central's SPIFFE ID must be pinned with `tlsconfig.AuthorizeID`, and the setting is required** (spec §7.5)
- New dependencies: `k8s.io/client-go`, `k8s.io/api`, `k8s.io/apimachinery`, `github.com/hashicorp/golang-lru/v2`. Run `go mod tidy` after every `go get`
- Every metric carries the `zonedns_agent_` prefix, following CoreDNS's `plugin.Namespace` convention
- Subproject 1 is complete and merged, so these packages are available directly: `internal/ednszone`, `internal/spiffezone`, `internal/testcerts`

---

### Task 1: `zonecache` — an answer cache keyed by zone

The node side **must** have a zone-aware cache (spec §7.3): the final answer
varies by zone, and the existing zone-blind `cache` plugin would hand zone-a's
answer to a zone-b pod.

**Files:**
- Create: `internal/zonecache/zonecache.go`
- Test: `internal/zonecache/zonecache_test.go`
- Modify: `go.mod` — add `github.com/hashicorp/golang-lru/v2`

**Interfaces:**
- Consumes: nothing
- Produces:
  - the `zonecache.Cache` type
  - `zonecache.New(maxEntries int) (*Cache, error)`
  - `(*Cache).Get(qname string, qtype uint16, zone string, now time.Time) (*dns.Msg, bool)`
  - `(*Cache).Put(qname string, qtype uint16, zone string, m *dns.Msg, now time.Time)`
  - `(*Cache).Len() int`

- [ ] **Step 1: Add the LRU dependency**

```bash
go get github.com/hashicorp/golang-lru/v2@latest
go mod tidy
```

`golang-lru/v2` is already an indirect dependency pulled in by CoreDNS; this step
only promotes it to a direct one.

- [ ] **Step 2: Write the failing test**

Create `internal/zonecache/zonecache_test.go`:

```go
package zonecache

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

var base = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

// reply builds a response carrying a single A record with a TTL of ttl seconds.
func reply(name string, ttl uint32, ip string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	m.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.ParseIP(ip).To4(),
	}}
	return m
}

// TestZoneIsPartOfTheKey is this package's reason to exist: same name, same
// type, different zone must not interfere.
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

// An expired entry must be a miss, never an answer with a zero or negative TTL.
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

// The returned TTL must have the elapsed time subtracted, or downstream keeps
// the answer longer than intended.
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

// The caller must receive a copy — changing the returned value must not
// contaminate the cache.
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

// A response with no answers (NODATA) has no TTL to follow, so it is not cached.
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

// The TTL is the smallest one among the answers.
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

- [ ] **Step 3: Run the test and confirm it fails**

Run: `go test ./internal/zonecache/ -v`
Expected: FAIL — `undefined: New`

- [ ] **Step 4: Write the minimal implementation**

Create `internal/zonecache/zonecache.go`:

```go
// Package zonecache is the node-side DNS answer cache, keyed in part by zone.
//
// Why CoreDNS's built-in cache plugin will not do: its key is (qname, qtype) and
// does not include the asking workload's zone. One name has different correct
// answers for clients in different zones — the service address within a zone,
// the gateway VIP across zones — so a zone-blind cache hands one zone's answer
// to a pod in another. And it hands it over convincingly, with no error at
// all.
package zonecache

import (
	"errors"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/miekg/dns"
)

// Cache is a size-bounded, zone-aware answer cache, safe for concurrent use.
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

// New builds a cache holding up to maxEntries entries.
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

// makeKey normalises qname. DNS names are case-insensitive, and without
// normalisation each spelling of one name would occupy its own entry, looking
// downstream like a cache that keeps missing.
func makeKey(qname string, qtype uint16, zone string) key {
	return key{qname: strings.ToLower(qname), qtype: qtype, zone: zone}
}

// Put takes in one answer.
//
// A response with no answers is not cached: there is no TTL to follow, and
// negative caching off the SOA minimum is a separate decision outside this
// package's scope. What is stored is a copy, so later changes by the caller to
// the original message do not reach the cache.
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

// Get returns an answer that has not expired, with the elapsed time subtracted
// from every record's TTL.
//
// Subtracting is not cosmetic: returned at their original values, a downstream
// resolver would restart the clock the moment it received them, and the answer
// would live longer than intended.
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

// Len returns the current entry count.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.l.Len()
}
```

- [ ] **Step 5: Run the test and confirm it passes**

Run: `go test ./internal/zonecache/ -race -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/zonecache/
git commit -m "feat(zonecache): add zone-aware answer cache for the node-local agent"
```

---

### Task 2: `dohupstream` — an mTLS DoH client pinning central's identity

**Files:**
- Create: `internal/dohupstream/dohupstream.go`
- Test: `internal/dohupstream/dohupstream_test.go`
- Modify: `go.mod`

**Interfaces:**
- Consumes: nothing
- Produces:
  - the `dohupstream.Client` type
  - `dohupstream.NewWithHTTPClient(url string, hc *http.Client) *Client`
  - `dohupstream.NewMTLS(ctx context.Context, cfg Config) (*Client, func(), error)`
  - the `dohupstream.Config` struct, with fields `URL`, `WorkloadAPIAddr`, `CentralSPIFFEID` and `DialTimeout`
  - `(*Client).Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error)`

- [ ] **Step 1: Add the go-spiffe dependency**

```bash
go get github.com/spiffe/go-spiffe/v2@latest
go mod tidy
```

(Subproject 1 already added it, so this is normally a no-op; run it anyway to be
sure.)

- [ ] **Step 2: Write the failing test**

Create `internal/dohupstream/dohupstream_test.go`:

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

// echoServer returns one fixed answer and hands the query it received to
// inspect.
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

// The query upstream sees must preserve the original question and EDNS0
// contents.
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

// The response ID must match the original query — RFC 8484 requires an ID of 0
// on the wire, and restoring it is our responsibility.
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

// A missing central SPIFFE ID must fail at construction, never fall back to
// verifying the chain alone.
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

- [ ] **Step 3: Run the test and confirm it fails**

Run: `go test ./internal/dohupstream/ -v`
Expected: FAIL — `undefined: NewWithHTTPClient`

- [ ] **Step 4: Write the minimal implementation**

Create `internal/dohupstream/dohupstream.go`:

```go
// Package dohupstream is the agent's DoH client for talking to central.
//
// The transport is DoH over mTLS: the agent presents its own SVID and MUST pin
// central by SPIFFE ID. Verifying the certificate chain alone is not enough —
// any SVID in the trust domain could impersonate central, and a forged central
// can return whatever it likes (claiming a same-zone service is cross-zone and
// handing back an attacker-controlled address, say), with no independent way for
// the agent to check the answer. See spec §7.5.
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

// defaultDialTimeout bounds the wait for the first SVID.
//
// workloadapi.NewX509Source blocks until the Workload API first responds, so
// without this bound a SPIRE agent that is not yet ready would stall CoreDNS's
// whole configuration parse, with neither a timeout nor a log line.
const defaultDialTimeout = 10 * time.Second

// Config is what building an mTLS client requires.
type Config struct {
	URL             string
	WorkloadAPIAddr string
	CentralSPIFFEID string
	DialTimeout     time.Duration
}

// Client sends DoH queries to central.
type Client struct {
	url string
	hc  *http.Client
}

// NewWithHTTPClient builds a Client over an existing http.Client. For tests, and
// to keep transport configuration separate from DNS logic.
func NewWithHTTPClient(url string, hc *http.Client) *Client {
	return &Client{url: url, hc: hc}
}

// NewMTLS builds a Client that authenticates both ways by SPIFFE identity.
//
// The returned cleanup must be called on shutdown to release the X509Source.
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

	// Certificates come from the X509Source rather than static files, so SVID
	// rotation needs no configuration reload.
	tlsCfg := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeID(id))
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}

	return &Client{url: cfg.URL, hc: hc}, func() { source.Close() }, nil
}

// Exchange sends a query and returns the answer.
func (c *Client) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	// RFC 8484 requires the DNS ID of a DoH query to be 0. We restore the ID on the
	// response, or the caller cannot match the answer back to its query.
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

	// ResponseToMsg closes the body.
	answer, err := doh.ResponseToMsg(resp)
	if err != nil {
		return nil, fmt.Errorf("dohupstream: decode response: %w", err)
	}
	answer.Id = originalID
	return answer, nil
}
```

- [ ] **Step 5: Run the test and confirm it passes**

Run: `go test ./internal/dohupstream/ -race -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/dohupstream/
git commit -m "feat(dohupstream): add mTLS DoH client pinned to central's SPIFFE ID"
```

---

### Task 3: `podzone` — local pod IP to zone

**Files:**
- Create: `internal/podzone/podzone.go`
- Test: `internal/podzone/podzone_test.go`
- Modify: `go.mod` — add `k8s.io/client-go`, `k8s.io/api`, `k8s.io/apimachinery`

**Interfaces:**
- Consumes: nothing
- Produces:
  - the `podzone.Watcher` type
  - `podzone.New(client kubernetes.Interface, nodeName, zoneLabel string) *Watcher`
  - `(*Watcher).Run(ctx context.Context) error`
  - `(*Watcher).Zone(ip netip.Addr) (string, bool)`
  - `(*Watcher).Ready() bool`
  - `(*Watcher).Len() int`

- [ ] **Step 1: Add the Kubernetes dependencies**

```bash
go get k8s.io/client-go@latest k8s.io/api@latest k8s.io/apimachinery@latest
go mod tidy
```

This is a real size cost on the self-built node-local DNS image — upstream
`sigs.k8s.io/node-local-dns` depends only on `apimachinery`, not `client-go`.
It must be written into the deployment doc (Task 6).

- [ ] **Step 2: Write the failing test**

Create `internal/podzone/podzone_test.go`:

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

// start runs the watcher, waits until it is ready, and returns a stop function.
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

// hostNetwork pods share the node IP and cannot be told apart, so they must
// never enter the table — otherwise the node IP would map to one hostNetwork
// pod's zone, and which one is arbitrary.
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

// Deletion must invalidate the mapping at once. IPs are recycled to new pods,
// and keeping the old value answers with the wrong zone.
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

// Before it is ready it always returns false — "not known yet" and "resolvable
// but absent from the table" are different answers.
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

- [ ] **Step 3: Run the test and confirm it fails**

Run: `go test ./internal/podzone/ -v`
Expected: FAIL — `undefined: New`

- [ ] **Step 4: Write the minimal implementation**

Create `internal/podzone/podzone.go`:

```go
// Package podzone maintains the pod IP to zone mapping for the local node.
//
// The data comes from the Kubernetes API, filtered by spec.nodeName to this
// node's pods alone — a few dozen, not a cluster-wide watch. The zone label it
// reads is the very value used to produce that pod's SPIFFE ID, so the zone the
// node computes and the zone central looks up in the registry agree by
// construction.
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

// Watcher holds the IP to zone mapping for local pods.
type Watcher struct {
	client    kubernetes.Interface
	nodeName  string
	zoneLabel string

	mu    sync.RWMutex
	byIP  map[netip.Addr]string
	ready bool
}

// New builds a Watcher that has not started yet.
func New(client kubernetes.Interface, nodeName, zoneLabel string) *Watcher {
	return &Watcher{
		client:    client,
		nodeName:  nodeName,
		zoneLabel: zoneLabel,
		byIP:      make(map[netip.Addr]string),
	}
}

// Run starts the informer and keeps it synced until ctx ends.
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

	// Once the informer stops, the table no longer tracks reality. Mark it
	// not-ready so queries take the path that declares no zone, rather than keep
	// answering from a mapping that only grows staler.
	w.mu.Lock()
	w.ready = false
	w.mu.Unlock()
	return nil
}

// upsert takes in a pod.
//
// Three kinds of pod are deliberately left out of the table:
//   - hostNetwork: its IP is the node IP, shared by every hostNetwork pod on the
//     node, so they cannot be told apart and any mapping would be arbitrary
//   - no zone label: it must not map to the empty-string zone, which downstream
//     would treat as a real zone
//   - no IP yet (Pending): there is no key to index by
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

// remove drops a pod's mapping.
//
// Removing immediately is necessary: pod IPs are recycled to new pods, and
// keeping the old value would give the new pod the previous tenant's zone — an
// answer that looks entirely normal.
func (w *Watcher) remove(obj any) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		// On a relist the informer may hand over a DeletedFinalStateUnknown.
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

// Zone finds the zone an IP belongs to.
//
// Before the watcher is ready it always returns false: queries during startup
// take the non-zone-aware path rather than guess a zone that could be wrong.
func (w *Watcher) Zone(ip netip.Addr) (string, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if !w.ready {
		return "", false
	}
	zone, ok := w.byIP[ip]
	return zone, ok
}

// Ready reports whether the informer has completed its first sync.
func (w *Watcher) Ready() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.ready
}

// Len returns the number of pods currently indexed.
func (w *Watcher) Len() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.byIP)
}
```

- [ ] **Step 5: Run the test and confirm it passes**

Run: `go test ./internal/podzone/ -race -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/podzone/
git commit -m "feat(podzone): index local pod IPs to zones via a node-scoped informer"
```

---

### Task 4: the plugin's query path

**Files:**
- Create: `plugin/zonedns_agent/agent.go`
- Create: `plugin/zonedns_agent/resolver.go`
- Create: `plugin/zonedns_agent/metrics.go`
- Test: `plugin/zonedns_agent/agent_test.go`

**Interfaces:**
- Consumes: `zonecache.Cache`, `dohupstream.Client`, `ednszone.Set`, `ednszone.DefaultCode`
- Produces:
  - the `zonedns_agent.ZoneResolver` interface, with the method `Zone(netip.Addr) (string, bool)`
  - the `zonedns_agent.StaticResolver` type and `NewStaticResolver(zone string) StaticResolver`
  - the `zonedns_agent.Upstream` interface, with the method `Exchange(context.Context, *dns.Msg) (*dns.Msg, error)`
  - the `zonedns_agent.Agent` struct, with fields `Next`, `Resolver`, `Cache`, `Upstream`, `EDNS0Code` and `NodeIP`
  - `(Agent).Name() string`
  - `(Agent).ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error)`

- [ ] **Step 1: Write the failing test**

Create `plugin/zonedns_agent/agent_test.go`:

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

// fakeUpstream records the query it received and returns one fixed answer.
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

// writerFrom builds a ResponseWriter whose source IP is ip.
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

// mapResolver is the smallest possible ZoneResolver test double.
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

// An unrecognised source is still forwarded, but must declare no zone — guessing
// one is far more dangerous than declaring none.
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

// This package's reason to exist: queries for the same name from different zones
// must not share a cache entry.
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

// An upstream failure must be SERVFAIL and must not fall through to the next
// plugin — that would bypass zone routing and return a direct address that looks
// perfectly normal.
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

// A source IP equal to the node IP is a sign of masquerading, and must be
// observable.
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
	// Under VM mode the zone is independent of the source.
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

- [ ] **Step 2: Run the test and confirm it fails**

Run: `go test ./plugin/zonedns_agent/ -v`
Expected: FAIL — `undefined: Agent`

- [ ] **Step 3: Write the resolver**

Create `plugin/zonedns_agent/resolver.go`:

```go
package zonedns_agent

import "net/netip"

// ZoneResolver determines the asking workload's zone from a query's source
// address.
//
// It is an interface because the two deployments determine it in fundamentally
// different ways: on Kubernetes every pod has its own IP and one node can mix
// several zones, so each query must be judged on its own; on a VM the whole
// machine belongs to one zone, settled once at startup.
type ZoneResolver interface {
	// Zone returns the zone a source address belongs to. An unrecognised source
	// returns ok=false, and the caller must take that as "declare no zone" rather
	// than guess one.
	Zone(src netip.Addr) (zone string, ok bool)
}

// StaticResolver is the VM-mode resolver: one zone for the whole machine,
// independent of the source address.
type StaticResolver struct {
	zone string
}

// NewStaticResolver builds a resolver that always returns zone.
func NewStaticResolver(zone string) StaticResolver {
	return StaticResolver{zone: zone}
}

// Zone implements ZoneResolver.
func (s StaticResolver) Zone(netip.Addr) (string, bool) {
	if s.zone == "" {
		return "", false
	}
	return s.zone, true
}
```

- [ ] **Step 4: Write the metrics**

Create `plugin/zonedns_agent/metrics.go`:

```go
package zonedns_agent

import (
	"github.com/coredns/coredns/plugin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// zoneResolutionTotal is broken down by outcome.
	//
	// result="node_ip" is the one that matters most: it means a query's source IP
	// was the node's own. Normally a pod's query arrives carrying the pod IP —
	// node-local DNS uses a link-local address and no DNAT — so a jump in this
	// number means something on the node is doing SNAT or masquerading, which
	// collapses the whole node into a single zone. Silently.
	zoneResolutionTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns_agent",
		Name:      "zone_resolution_total",
		Help:      "Count of source zone resolution attempts by outcome.",
	}, []string{"result"})

	// cacheTotal separates hits from misses.
	cacheTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns_agent",
		Name:      "cache_total",
		Help:      "Count of zone-aware cache lookups by outcome.",
	}, []string{"result"})

	// upstreamErrorsTotal counts failed queries to central.
	upstreamErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns_agent",
		Name:      "upstream_errors_total",
		Help:      "Count of failed DoH exchanges with the central server.",
	})

	// While resolverReady is 0, no query declares a zone.
	resolverReady = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns_agent",
		Name:      "resolver_ready",
		Help:      "1 when the zone resolver has loaded its data, 0 otherwise.",
	})
)
```

- [ ] **Step 5: Write ServeDNS**

Create `plugin/zonedns_agent/agent.go`:

```go
// Package zonedns_agent is the node-side CoreDNS plugin for zone-based DNS.
//
// It determines the asking workload's zone, makes that zone part of the cache
// key, and declares it in an EDNS0 option when querying central. It handles only
// the domains that take part in zone routing, as delimited by the Corefile's
// server block; every other query bypasses it entirely.
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

// timeNow lets tests control how cache expiry is judged.
var timeNow = time.Now

// Upstream sends queries to central.
type Upstream interface {
	Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error)
}

// Agent is the plugin's handler.
type Agent struct {
	Next      plugin.Handler
	Resolver  ZoneResolver
	Cache     *zonecache.Cache
	Upstream  Upstream
	EDNS0Code uint16

	// NodeIP is this node's own address, used only to detect masquerading. A query
	// whose source IP equals it had its pod IP rewritten along the way.
	NodeIP netip.Addr
}

// Name implements plugin.Handler.
func (a Agent) Name() string { return "zonedns_agent" }

// ServeDNS implements plugin.Handler.
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

// resolveZone determines the source's zone and records the outcome.
//
// An unrecognised source returns ok=false, and the caller forwards as usual
// without declaring a zone. This is deliberate: central takes the non-zone-aware
// path for an undeclared query and returns the ordinary answer, and given that
// zones are network-isolated, that answer is either usable or unreachable —
// either of which beats guessing the wrong zone and sending traffic to the wrong
// gateway.
func (a Agent) resolveZone(srcIP string) (string, bool) {
	src, err := netip.ParseAddr(srcIP)
	if err != nil {
		zoneResolutionTotal.WithLabelValues("bad_source").Inc()
		return "", false
	}
	if a.NodeIP.IsValid() && src == a.NodeIP {
		// Either something on the node is rewriting the source IP, or this is a
		// hostNetwork workload. In neither case can we tell which workload is
		// asking.
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

- [ ] **Step 6: Run the test and confirm it passes**

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

### Task 5: setup — parsing the Corefile and choosing the mode

**Files:**
- Create: `plugin/zonedns_agent/setup.go`
- Test: `plugin/zonedns_agent/setup_test.go`

**Interfaces:**
- Consumes: every type from Task 4, plus `podzone.New`, `dohupstream.NewMTLS` and `zonecache.New`
- Produces:
  - `zonedns_agent.CheckDirectiveOrder(directives []string) error`

- [ ] **Step 1: Write the failing test**

Create `plugin/zonedns_agent/setup_test.go`:

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

// A wrong order must fail startup: with cache first, a zone-blind cache hands one
// zone's answer to a pod in another, and nothing looks amiss at runtime.
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

// central_spiffe_id has no safe default: without it only chain verification
// remains, and any SVID in the trust domain could impersonate central.
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

- [ ] **Step 2: Run the test and confirm it fails**

Run: `go test ./plugin/zonedns_agent/ -run 'TestCheck|TestParse' -v`
Expected: FAIL — `undefined: CheckDirectiveOrder`

- [ ] **Step 3: Write the implementation**

Create `plugin/zonedns_agent/setup.go`:

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
	zone            string // vm mode
	nodeName        string // k8s mode
	zoneLabel       string // k8s mode
	upstreamURL     string
	centralSPIFFEID string
	workloadAPI     string
	cacheSize       int
	edns0Code       uint16
	nodeIP          netip.Addr
}

// CheckDirectiveOrder confirms that zonedns_agent sorts before cache.
//
// This is a correctness requirement, not a preference: the existing cache plugin
// keys on (qname, qtype) and does not include the asking workload's zone. If it
// sorts first, then once a zone-a pod has asked, a zone-b pod receives that same
// answer — convincingly, with no sign of it at runtime. The order comes from
// plugin.cfg at compile time, making this a check on the build configuration.
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
	// central_spiffe_id has no safe default: without it only chain verification
	// remains, and any SVID in the trust domain could impersonate central and return
	// whatever it liked.
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
		// The zone name must be something the wire format can carry — otherwise
		// central silently ignores the declaration and this VM's queries receive
		// zone-blind answers forever.
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

- [ ] **Step 4: Run the test and confirm it passes**

Run: `go test ./plugin/zonedns_agent/ -race -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add plugin/zonedns_agent/
git commit -m "feat(zonedns_agent): parse Corefile, select k8s or vm mode, enforce ordering"
```

---

### Task 6: end-to-end verification and the deployment doc

**Files:**
- Create: `plugin/zonedns_agent/e2e_test.go`
- Modify: `docs/deployment.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: all of the packages above
- Produces: no new programmatic interface

- [ ] **Step 1: Write the end-to-end test**

Create `plugin/zonedns_agent/e2e_test.go`:

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

// One name, two pods in different zones, and the answers must differ — with
// upstream really queried both times. This is the node side's reason to exist.
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

- [ ] **Step 2: Run the test and confirm it passes**

Run: `go test ./plugin/zonedns_agent/ -race -run TestEndToEnd -v`
Expected: PASS

- [ ] **Step 3: Update the deployment doc**

Add the node-side sections at the end of `docs/deployment.md`. They must cover:

**Building** — `zonedns_agent` compiles into a self-built node-local DNS image.
Fetch the `sigs.k8s.io/node-local-dns` source, add
`_ "github.com/jenting/zonedns/plugin/zonedns_agent"` to the blank import block
in `cmd/node-cache/main.go`, and insert `"zonedns_agent"` into
`dnsserver.Directives` **before `"cache"`**, or the plugin refuses to start.
Build with that project's existing `Makefile` and `Dockerfile.node-cache`.

**Image size** — state it plainly: upstream node-local-dns depends only on
`k8s.io/apimachinery` and does not include `client-go`. k8s mode needs
`client-go` for the local pod informer, so the self-built image is noticeably
larger than upstream's. VM mode does not need it, but the binary is the same
one.

**Changes to the DaemonSet** — three only: `image` points at the self-built
registry; the ServiceAccount gains `get/list/watch` RBAC on pods; the Corefile
ConfigMap gains one server block. The deployment shape — a DaemonSet, one per
node, the link-local address, the iptables rules, pods' resolv.conf — is entirely
unchanged.

**Corefile（k8s）**：

```
cluster.local:53 { ... existing configuration entirely untouched ... }

example.com:53 {
    zonedns_agent {
        mode              k8s
        node_name         # NODE_NAME, injected by the downward API
        zone_label        zone
        upstream          https://central.example.org/dns-query
        central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
        workload_api      unix:///run/spire/sockets/agent.sock
        cache_size        4096
    }
}

.:53 { ... existing cache + forward entirely untouched ... }
```

**Corefile (VM)**: the same as above, but with `mode vm` plus
`zone <this VM's zone>`, and neither `node_name` nor `zone_label`.

**RBAC** — the minimum permissions needed:

```yaml
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]
```

**Required alerts** — take the metric names from
`plugin/zonedns_agent/metrics.go` rather than from memory; read that file while
implementing to confirm the names Prometheus actually renders:

| Condition | Meaning |
|---|---|
| Non-zero growth in `zone_resolution_total{result="node_ip"}` | Something on the node is doing SNAT/masquerading and has rewritten queries' source IPs. The whole node silently degrades to not distinguishing zones |
| Sustained growth in `zone_resolution_total{result="unknown"}` | Some pod has no zone label, or the informer is lagging behind pod creation |
| `resolver_ready == 0` for longer than one startup cycle | The pod watcher has not synced and no query declares a zone |
| Non-zero growth in `upstream_errors_total` | DoH to central is failing; queries return SERVFAIL |
| An unusually high proportion of `cache_total{result="miss"}` | The cache is too small, or the TTL too short |

**Settings that must be maintained as a pair** — the SPIFFE ID of the agent's own
SVID must appear in central's `authorized_agent` list, and central's SPIFFE ID
must be set as the agent's `central_spiffe_id`. Miss either side and zone routing
stops working silently.

- [ ] **Step 4: Update the README**

Add the node-side rows to the components table in `README.md`:

| Path | What it does |
|---|---|
| `plugin/zonedns_agent` | The node-side CoreDNS plugin: determines the source zone, keys the cache by it, declares it to central |
| `internal/podzone` | Local pod IP → zone (a node-scoped informer) |
| `internal/zonecache` | An answer cache keyed by `(qname, qtype, zone)` |
| `internal/dohupstream` | The mTLS DoH client that pins central's SPIFFE ID |

And add to the prose: the node side and the central side share the wire format
defined by `internal/ednszone`, which is the sole compatibility interface between
them.

- [ ] **Step 5: Run the full test suite and static checks**

```bash
gofmt -l .
go vet ./...
go build ./...
go test ./... -race -cover
```

Expected: `gofmt -l .` prints nothing; vet and build are clean; the whole suite
passes.

- [ ] **Step 6: Commit**

```bash
git add plugin/zonedns_agent/e2e_test.go docs/deployment.md README.md
git commit -m "test(zonedns_agent): add end-to-end coverage and node-side deployment docs"
```
