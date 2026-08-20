# zonedns Central Plugin Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement zonedns's central CoreDNS plugin — terminate mTLS DoH, verify the agent's identity, and decide from the source zone and dest zone whether to return the ordinary answer or the zone gateway VIP.

**Architecture:** One CoreDNS plugin, `zonedns`, composing four independently testable units: `identity` (the trust boundary, deriving the source zone from the peer cert plus EDNS0), `registry` (polls the SPIRE Entry API and maintains FQDN → dest zone), `zonetable` (the zone → gateway VIP configuration) and `decision` (a pure function). The plugin must sort before `cache`, and that constraint is enforced at startup.

**Tech Stack:** Go, the CoreDNS plugin API, miekg/dns, spire-api-sdk (the Entry API over gRPC), go-spiffe/v2 (the SVID source and SPIFFE ID parsing), the Prometheus client.

**Spec:** `docs/superpowers/specs/2026-08-18-zonedns-design.md`

## Global Constraints

- Go module path: `github.com/jenting/zonedns`
- Go version: 1.25, matching `sigs.k8s.io/node-local-dns`'s `go 1.25.0`, since subproject 2 shares these packages
- CoreDNS version: `github.com/coredns/coredns v1.14.6`, matching node-local-dns's pin
- The EDNS0 option code defaults to `65001` (the local/experimental range is 65001–65534) and can be overridden by configuration
- The TTL of a cross-zone answer defaults to `30` seconds and can be overridden by configuration
- SPIFFE ID path format: `/zone/<zone>/...`, with the zone as the path's second segment
- **`zonedns` must sort before `cache` in `dnsserver.Directives`**, and startup fails when it does not
- Shared packages go in `internal/`; subproject 2 is in the same module and can import them normally
- Every metric carries the `zonedns_` prefix, with the subsystem following CoreDNS convention

---

### Task 1: project skeleton plus `spiffezone`, extracting the zone from a SPIFFE ID

**Files:**
- Create: `go.mod`
- Create: `internal/spiffezone/spiffezone.go`
- Test: `internal/spiffezone/spiffezone_test.go`

**Interfaces:**
- Consumes: nothing (this is the first task)
- Produces:
  - `spiffezone.FromPath(path string) (string, error)`
  - `spiffezone.FromID(id string) (string, error)`
  - `spiffezone.ErrNoZone error`

- [ ] **Step 1: Create the module**

```bash
cd /Users/jenting/go/src/github.com/jenting/zonedns
go mod init github.com/jenting/zonedns
go mod edit -go=1.25
```

- [ ] **Step 2: Write the failing test**

Create `internal/spiffezone/spiffezone_test.go`:

```go
package spiffezone

import (
	"errors"
	"testing"
)

func TestFromPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		want    string
		wantErr error
	}{
		{"k8s workload", "/zone/zone-a/ns/prod/sa/payments", "zone-a", nil},
		{"vm workload", "/zone/zone-c/vm/billing-01", "zone-c", nil},
		{"zone only", "/zone/zone-b", "zone-b", nil},
		{"no leading slash", "zone/zone-a/ns/prod", "zone-a", nil},
		{"missing zone segment", "/ns/prod/sa/payments", "", ErrNoZone},
		{"zone key but no value", "/zone", "", ErrNoZone},
		{"zone key with empty value", "/zone//ns/prod", "", ErrNoZone},
		{"empty path", "", "", ErrNoZone},
		{"zone not first segment", "/ns/prod/zone/zone-a", "", ErrNoZone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FromPath(tt.path)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFromID(t *testing.T) {
	got, err := FromID("spiffe://example.org/zone/zone-a/ns/prod/sa/payments")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "zone-a" {
		t.Fatalf("got %q, want %q", got, "zone-a")
	}
}

func TestFromIDRejectsNonSPIFFE(t *testing.T) {
	if _, err := FromID("https://example.org/zone/zone-a"); err == nil {
		t.Fatal("expected error for non-spiffe scheme")
	}
}
```

- [ ] **Step 3: Run the test and confirm it fails**

Run: `go test ./internal/spiffezone/ -v`
Expected: FAIL — `undefined: FromPath`

- [ ] **Step 4: Write the minimal implementation**

Create `internal/spiffezone/spiffezone.go`:

```go
// Package spiffezone extracts the zone from a SPIFFE ID.
//
// The convention: the zone is the first key/value pair in the SPIFFE ID path,
// of the form /zone/<zone>/... Both the central plugin (for the dest zone) and
// the agent plugin (for the source zone) rely on this convention, so it lives
// in a shared package — two independent copies could drift apart in how they
// parse it.
package spiffezone

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ErrNoZone reports that the path contains no valid zone segment.
var ErrNoZone = errors.New("spiffezone: no zone segment in path")

// FromPath extracts the zone from the path of a SPIFFE ID.
func FromPath(path string) (string, error) {
	segs := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(segs) < 2 || segs[0] != "zone" || segs[1] == "" {
		return "", ErrNoZone
	}
	return segs[1], nil
}

// FromID extracts the zone from a complete SPIFFE ID.
func FromID(id string) (string, error) {
	u, err := url.Parse(id)
	if err != nil {
		return "", fmt.Errorf("spiffezone: parse %q: %w", id, err)
	}
	if u.Scheme != "spiffe" {
		return "", fmt.Errorf("spiffezone: %q is not a spiffe ID", id)
	}
	return FromPath(u.Path)
}
```

- [ ] **Step 5: Run the test and confirm it passes**

Run: `go test ./internal/spiffezone/ -v`
Expected: PASS, every subtest green

- [ ] **Step 6: Commit**

```bash
git add go.mod internal/spiffezone/
git commit -m "feat(spiffezone): extract zone from SPIFFE ID path"
```

---

### Task 2: `ednszone` — encoding and decoding the EDNS0 contract

This is the **sole compatibility interface** between subprojects 1 and 2 (spec
§6.6). Both ends use this package, so encoding and decoding are written together
and tested together, and neither side can change without the other.

**Files:**
- Create: `internal/ednszone/ednszone.go`
- Test: `internal/ednszone/ednszone_test.go`
- Modify: `go.mod` — add `github.com/miekg/dns`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `ednszone.DefaultCode uint16 = 65001`
  - `ednszone.Get(m *dns.Msg, code uint16) (string, bool)`
  - `ednszone.Set(m *dns.Msg, code uint16, zone string)`
  - `ednszone.Valid(zone string) bool`
  - `ednszone.MaxLen int = 63`

- [ ] **Step 1: Add the dependency**

```bash
go get github.com/miekg/dns@latest
```

- [ ] **Step 2: Write the failing test**

Create `internal/ednszone/ednszone_test.go`:

```go
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
	// Two options with the same code must not accumulate
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
	m.SetEdns0(4096, true) // an existing OPT, with the DO bit set
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
	m.SetEdns0(4096, false) // an OPT, but not carrying our option
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

func TestValid(t *testing.T) {
	for _, good := range []string{"zone-a", "z", "zone_1", "ZoneA", strings.Repeat("z", MaxLen)} {
		if !Valid(good) {
			t.Fatalf("Valid(%q) = false, want true", good)
		}
	}
}
```

- [ ] **Step 3: Run the test and confirm it fails**

Run: `go test ./internal/ednszone/ -v`
Expected: FAIL — `undefined: Set`

- [ ] **Step 4: Write the minimal implementation**

Create `internal/ednszone/ednszone.go`:

```go
// Package ednszone defines the wire format that carries the source zone between
// the agent and central.
//
// This is the only compatibility interface between the two subprojects (spec
// §6.6): the agent writes with Set, central reads with Get. Encoding and
// decoding deliberately live in one package and are tested together, so that
// neither end can change the format on its own.
//
// EDNS0 rather than EDNS Client Subnet: ECS means a network prefix, not an
// identity, and intermediate resolvers rewrite it per RFC 7871. An option code
// from the local/experimental range: IANA reserves that range (65001-65534) for
// private use, so it cannot collide with a standard option.
package ednszone

import (
	"github.com/miekg/dns"
)

// DefaultCode is the default EDNS0 option code, taken from IANA's
// local/experimental range.
const DefaultCode uint16 = 65001

// MaxLen bounds the length of a zone string, matching the limit on a Kubernetes
// label value.
const MaxLen = 63

// Valid reports whether a zone string is well formed.
//
// The decoding side runs this check too: even when the declaration comes from a
// verified agent, the string itself is external input and must not go straight
// into a map lookup or a log line.
func Valid(zone string) bool {
	if zone == "" || len(zone) > MaxLen {
		return false
	}
	for i := 0; i < len(zone); i++ {
		c := zone[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '_':
		default:
			return false
		}
	}
	return true
}

// Set writes the source zone onto a message, creating an OPT record if needed.
//
// An existing OPT record is preserved along with its UDP size and DO bit, and an
// older option with the same code is replaced rather than appended — otherwise a
// retry or forwarding path could accumulate several declarations that contradict
// each other.
func Set(m *dns.Msg, code uint16, zone string) {
	opt := m.IsEdns0()
	if opt == nil {
		m.SetEdns0(dns.DefaultMsgSize, false)
		opt = m.IsEdns0()
	}

	kept := opt.Option[:0]
	for _, o := range opt.Option {
		if l, isLocal := o.(*dns.EDNS0_LOCAL); isLocal && l.Code == code {
			continue
		}
		kept = append(kept, o)
	}
	opt.Option = append(kept, &dns.EDNS0_LOCAL{Code: code, Data: []byte(zone)})
}

// Get reads the source zone. An invalid zone returns ok=false, handled the same
// way as one that is absent.
func Get(m *dns.Msg, code uint16) (string, bool) {
	opt := m.IsEdns0()
	if opt == nil {
		return "", false
	}
	for _, o := range opt.Option {
		l, isLocal := o.(*dns.EDNS0_LOCAL)
		if !isLocal || l.Code != code {
			continue
		}
		zone := string(l.Data)
		if !Valid(zone) {
			return "", false
		}
		return zone, true
	}
	return "", false
}
```

- [ ] **Step 5: Run the test and confirm it passes**

Run: `go test ./internal/ednszone/ -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/ednszone/
git commit -m "feat(ednszone): define EDNS0 wire contract for source zone"
```

---

### Task 3: `zonetable` — zone to gateway VIP

**Files:**
- Create: `internal/zonetable/zonetable.go`
- Test: `internal/zonetable/zonetable_test.go`

**Interfaces:**
- Consumes: nothing
- Produces:
  - the `zonetable.Table` type
  - `zonetable.New(entries map[string]netip.Addr) *Table`
  - `(*Table).Gateway(zone string) (netip.Addr, bool)`
  - `(*Table).Len() int`

- [ ] **Step 1: Write the failing test**

Create `internal/zonetable/zonetable_test.go`:

```go
package zonetable

import (
	"net/netip"
	"testing"
)

func TestGateway(t *testing.T) {
	tbl := New(map[string]netip.Addr{
		"zone-a": netip.MustParseAddr("203.0.113.10"),
		"zone-b": netip.MustParseAddr("203.0.113.11"),
	})

	got, ok := tbl.Gateway("zone-a")
	if !ok {
		t.Fatal("zone-a not found")
	}
	if got.String() != "203.0.113.10" {
		t.Fatalf("got %s, want 203.0.113.10", got)
	}
}

func TestGatewayMissing(t *testing.T) {
	tbl := New(map[string]netip.Addr{"zone-a": netip.MustParseAddr("203.0.113.10")})

	// An unconfigured zone must return false so the decision layer produces a
	// SERVFAIL rather than silently letting the query through.
	if _, ok := tbl.Gateway("zone-z"); ok {
		t.Fatal("unconfigured zone must not resolve")
	}
}

func TestEmptyTable(t *testing.T) {
	tbl := New(nil)
	if tbl.Len() != 0 {
		t.Fatalf("Len = %d, want 0", tbl.Len())
	}
	if _, ok := tbl.Gateway("zone-a"); ok {
		t.Fatal("empty table must not resolve anything")
	}
}

func TestNewCopiesInput(t *testing.T) {
	src := map[string]netip.Addr{"zone-a": netip.MustParseAddr("203.0.113.10")}
	tbl := New(src)
	src["zone-a"] = netip.MustParseAddr("198.51.100.1")

	got, _ := tbl.Gateway("zone-a")
	if got.String() != "203.0.113.10" {
		t.Fatalf("table aliased its input map: got %s", got)
	}
}
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `go test ./internal/zonetable/ -v`
Expected: FAIL — `undefined: New`

- [ ] **Step 3: Write the minimal implementation**

Create `internal/zonetable/zonetable.go`:

```go
// Package zonetable holds the mapping from zone to zone gateway VIP.
//
// The data comes from the config file, the entry count is on the order of the
// number of zones (a few dozen), and it never changes after startup — so the
// table is read-only and needs no locking. Reloading config builds a new Table
// that replaces the old one.
package zonetable

import "net/netip"

// Table is a read-only mapping from zone to gateway VIP.
type Table struct {
	gw map[string]netip.Addr
}

// New builds a Table. The input map is copied, so later changes by the caller
// do not affect the Table that was built.
func New(entries map[string]netip.Addr) *Table {
	gw := make(map[string]netip.Addr, len(entries))
	for z, a := range entries {
		gw[z] = a
	}
	return &Table{gw: gw}
}

// Gateway returns the gateway VIP for a zone.
//
// A miss returns ok=false. The caller must treat that as a configuration error
// (SERVFAIL) and must not fall back to an ordinary answer — see spec §6.4,
// fourth row.
func (t *Table) Gateway(zone string) (netip.Addr, bool) {
	a, ok := t.gw[zone]
	return a, ok
}

// Len returns the number of configured zones.
func (t *Table) Len() int { return len(t.gw) }
```

- [ ] **Step 4: Run the test and confirm it passes**

Run: `go test ./internal/zonetable/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/zonetable/
git commit -m "feat(zonetable): map zone to gateway VIP"
```

---

### Task 4: `decision` — the pure decision function

Implements the five-row decision table of spec §6.4. This is the plugin's core
logic, deliberately a pure function with no I/O so it can be tested
exhaustively.

**Files:**
- Create: `internal/decision/decision.go`
- Test: `internal/decision/decision_test.go`

**Interfaces:**
- Consumes: nothing
- Produces:
  - the `decision.Action` type with the constants `ActionPassThrough`, `ActionAnswerGateway` and `ActionServFail`
  - the `decision.Decision` struct, with fields `Action Action` and `Gateway netip.Addr`
  - the `decision.Input` struct, with fields `SourceZone string`, `SourceOK bool`, `DestZone string` and `DestOK bool`
  - `decision.Decide(in Input, gateway func(string) (netip.Addr, bool)) Decision`

- [ ] **Step 1: Write the failing test**

Create `internal/decision/decision_test.go`:

```go
package decision

import (
	"net/netip"
	"testing"
)

var gwA = netip.MustParseAddr("203.0.113.10")

// gateways stands in for zonetable: only zone-a has a gateway configured.
func gateways(zone string) (netip.Addr, bool) {
	if zone == "zone-a" {
		return gwA, true
	}
	return netip.Addr{}, false
}

func TestDecideTable(t *testing.T) {
	tests := []struct {
		name string
		in   Input
		want Decision
	}{
		{
			"same zone passes through",
			Input{SourceZone: "zone-a", SourceOK: true, DestZone: "zone-a", DestOK: true},
			Decision{Action: ActionPassThrough},
		},
		{
			"cross zone answers gateway",
			Input{SourceZone: "zone-b", SourceOK: true, DestZone: "zone-a", DestOK: true},
			Decision{Action: ActionAnswerGateway, Gateway: gwA},
		},
		{
			"dest not in registry passes through",
			Input{SourceZone: "zone-b", SourceOK: true, DestOK: false},
			Decision{Action: ActionPassThrough},
		},
		{
			"cross zone without gateway config servfails",
			Input{SourceZone: "zone-a", SourceOK: true, DestZone: "zone-z", DestOK: true},
			Decision{Action: ActionServFail},
		},
		{
			"unknown source passes through even when dest is known",
			Input{SourceOK: false, DestZone: "zone-a", DestOK: true},
			Decision{Action: ActionPassThrough},
		},
		{
			"unknown source passes through when dest unknown too",
			Input{SourceOK: false, DestOK: false},
			Decision{Action: ActionPassThrough},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Decide(tt.in, gateways)
			if got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

// The same-zone path must not consult the gateway table — if it did, a zone
// with no configured gateway would wrongly SERVFAIL.
func TestSameZoneDoesNotConsultGatewayTable(t *testing.T) {
	called := false
	gw := func(string) (netip.Addr, bool) {
		called = true
		return netip.Addr{}, false
	}
	in := Input{SourceZone: "zone-z", SourceOK: true, DestZone: "zone-z", DestOK: true}
	if got := Decide(in, gw); got.Action != ActionPassThrough {
		t.Fatalf("got %v, want ActionPassThrough", got.Action)
	}
	if called {
		t.Fatal("gateway table consulted on the same-zone path")
	}
}
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `go test ./internal/decision/ -v`
Expected: FAIL — `undefined: Decide`

- [ ] **Step 3: Write the minimal implementation**

Create `internal/decision/decision.go`:

```go
// Package decision implements zonedns's core decision logic (spec §6.4).
//
// Deliberately a pure function with no I/O: the caller looks up all external
// state and passes it in. That lets the decision table be tested exhaustively,
// and keeps "what to do in which situation" in one place rather than scattered
// through ServeDNS.
package decision

import "net/netip"

// Action is the action a decision calls for.
type Action int

const (
	// ActionPassThrough hands the query to the next plugin in the chain.
	ActionPassThrough Action = iota
	// ActionAnswerGateway answers directly with the zone gateway VIP.
	ActionAnswerGateway
	// ActionServFail returns SERVFAIL.
	ActionServFail
)

func (a Action) String() string {
	switch a {
	case ActionPassThrough:
		return "passthrough"
	case ActionAnswerGateway:
		return "gateway"
	case ActionServFail:
		return "servfail"
	default:
		return "unknown"
	}
}

// Input is everything needed to make a decision.
type Input struct {
	SourceZone string
	SourceOK   bool // whether a trustworthy source zone was obtained
	DestZone   string
	DestOK     bool // whether the FQDN is present in the registry
}

// Decision is the result. Gateway is meaningful only when Action is
// ActionAnswerGateway.
type Decision struct {
	Action  Action
	Gateway netip.Addr
}

// Decide implements the decision table in spec §6.4.
//
// gateway looks up the gateway VIP for a zone (normally
// zonetable.Table.Gateway).
func Decide(in Input, gateway func(string) (netip.Addr, bool)) Decision {
	// Source zone unknown — this is the ordinary non-zone-aware path, not an error.
	if !in.SourceOK {
		return Decision{Action: ActionPassThrough}
	}
	// This name is not ours to handle (an external domain, say).
	if !in.DestOK {
		return Decision{Action: ActionPassThrough}
	}
	// Same zone — let downstream return the ordinary answer. The gateway table
	// is deliberately not consulted: a same-zone lookup needs no gateway at all,
	// and consulting it would make a zone with no configured gateway SERVFAIL
	// when its own workloads talk to each other.
	if in.DestZone == in.SourceZone {
		return Decision{Action: ActionPassThrough}
	}
	// Cross-zone — a gateway must be configured.
	gw, ok := gateway(in.DestZone)
	if !ok {
		// The registry says this zone exists but the config file has no gateway
		// for it. That is a missing configuration, and silently returning the
		// ordinary answer would break zone isolation without a sound — so this
		// path deliberately does not fail open.
		return Decision{Action: ActionServFail}
	}
	return Decision{Action: ActionAnswerGateway, Gateway: gw}
}
```

- [ ] **Step 4: Run the test and confirm it passes**

Run: `go test ./internal/decision/ -v`
Expected: PASS, all six subtests green

- [ ] **Step 5: Commit**

```bash
git add internal/decision/
git commit -m "feat(decision): implement zone routing decision table"
```

---

### Task 5: `identity` — obtaining the peer certificate

Handles the difference between how DoT and DoH obtain a client certificate (spec
§6.1). It is a task of its own because of one detail that is easy to get wrong:
DoH must take the HTTP request from the context and must not type-assert the
`dns.ResponseWriter`, since an upstream plugin may have wrapped it.

**Files:**
- Create: `internal/identity/peercert.go`
- Test: `internal/identity/peercert_test.go`
- Test: `internal/identity/testdata_test.go` — the test certificate generator
- Modify: `go.mod` — add `github.com/coredns/coredns`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `identity.PeerCertificates(ctx context.Context, w dns.ResponseWriter) ([]*x509.Certificate, bool)`
  - `identity.SPIFFEIDFromCert(cert *x509.Certificate) (string, bool)`
  - the test helper `newTestCert(t *testing.T, uri string) *x509.Certificate`

- [ ] **Step 1: Add the CoreDNS dependency**

```bash
go get github.com/coredns/coredns@v1.14.6
```

- [ ] **Step 2: Write the test certificate generator**

Create `internal/identity/testdata_test.go`:

```go
package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"
)

// newTestCert produces a certificate carrying the given URI SAN. An empty uri
// means no URI SAN at all.
func newTestCert(t *testing.T, uri string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	if uri != "" {
		u, err := url.Parse(uri)
		if err != nil {
			t.Fatalf("parse uri %q: %v", uri, err)
		}
		tmpl.URIs = []*url.URL{u}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}
```

- [ ] **Step 3: Write the failing test**

Create `internal/identity/peercert_test.go`:

```go
package identity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"testing"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/miekg/dns"
)

// plainWriter simulates an ordinary, non-TLS ResponseWriter.
type plainWriter struct{ dns.ResponseWriter }

// dotWriter simulates a DoT ResponseWriter and implements dns.ConnectionStater.
type dotWriter struct {
	dns.ResponseWriter
	state *tls.ConnectionState
}

func (w *dotWriter) ConnectionState() *tls.ConnectionState { return w.state }

func TestPeerCertificatesFromDoT(t *testing.T) {
	cert := newTestCert(t, "spiffe://example.org/node/n1")
	w := &dotWriter{state: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}}

	got, ok := PeerCertificates(context.Background(), w)
	if !ok {
		t.Fatal("ok = false, want true")
	}
	if len(got) != 1 || !got[0].Equal(cert) {
		t.Fatal("returned certificate does not match")
	}
}

func TestPeerCertificatesFromDoH(t *testing.T) {
	cert := newTestCert(t, "spiffe://example.org/node/n1")
	req := &http.Request{TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}}
	// CoreDNS's DoH server puts the *http.Request into the context
	// (server_https.go). Taking it from there rather than type-asserting the
	// writer is what keeps an upstream plugin's wrapping from affecting it.
	ctx := context.WithValue(context.Background(), dnsserver.HTTPRequestKey{}, req)

	got, ok := PeerCertificates(ctx, &plainWriter{})
	if !ok {
		t.Fatal("ok = false, want true")
	}
	if len(got) != 1 || !got[0].Equal(cert) {
		t.Fatal("returned certificate does not match")
	}
}

func TestPeerCertificatesNoTLS(t *testing.T) {
	if _, ok := PeerCertificates(context.Background(), &plainWriter{}); ok {
		t.Fatal("plain UDP/TCP connection must not yield certificates")
	}
}

func TestPeerCertificatesTLSWithoutClientCert(t *testing.T) {
	w := &dotWriter{state: &tls.ConnectionState{}} // TLS, but no client cert
	if _, ok := PeerCertificates(context.Background(), w); ok {
		t.Fatal("TLS without a client certificate must yield ok=false")
	}

	req := &http.Request{TLS: &tls.ConnectionState{}}
	ctx := context.WithValue(context.Background(), dnsserver.HTTPRequestKey{}, req)
	if _, ok := PeerCertificates(ctx, &plainWriter{}); ok {
		t.Fatal("DoH without a client certificate must yield ok=false")
	}
}

func TestPeerCertificatesPlainHTTPRequest(t *testing.T) {
	req := &http.Request{} // HTTP with no TLS
	ctx := context.WithValue(context.Background(), dnsserver.HTTPRequestKey{}, req)
	if _, ok := PeerCertificates(ctx, &plainWriter{}); ok {
		t.Fatal("non-TLS HTTP request must yield ok=false")
	}
}

func TestSPIFFEIDFromCert(t *testing.T) {
	cert := newTestCert(t, "spiffe://example.org/node/n1")
	got, ok := SPIFFEIDFromCert(cert)
	if !ok {
		t.Fatal("ok = false, want true")
	}
	if got != "spiffe://example.org/node/n1" {
		t.Fatalf("got %q", got)
	}
}

func TestSPIFFEIDFromCertRejectsNonSPIFFE(t *testing.T) {
	if _, ok := SPIFFEIDFromCert(newTestCert(t, "https://example.org/node/n1")); ok {
		t.Fatal("non-spiffe URI SAN must be rejected")
	}
	if _, ok := SPIFFEIDFromCert(newTestCert(t, "")); ok {
		t.Fatal("certificate without URI SAN must be rejected")
	}
}
```

- [ ] **Step 4: Run the test and confirm it fails**

Run: `go test ./internal/identity/ -v`
Expected: FAIL — `undefined: PeerCertificates`

- [ ] **Step 5: Write the minimal implementation**

Create `internal/identity/peercert.go`:

```go
// Package identity is zonedns's trust boundary (spec §6.1).
//
// Whether the whole of zone isolation can be bypassed depends on nothing but
// this package being correct. Any change must come with a review of whether the
// tests here still cover the corresponding attack.
package identity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/miekg/dns"
)

// PeerCertificates returns the client certificate chain for this query.
//
// The two transports differ in how it is obtained:
//
//   - DoH: CoreDNS's HTTPS server puts the *http.Request into the context. It is
//     taken from the context rather than by type-asserting the writer — an
//     upstream plugin (metrics, for one) may have wrapped the ResponseWriter, in
//     which case the assertion fails, and it fails by quietly returning false.
//     Zone verification would be entirely disabled without a single error.
//   - DoT: the writer implements dns.ConnectionStater.
//
// Returns ok=false when there is no TLS, or TLS but no certificate presented.
// The caller must treat that as the ordinary non-zone-aware path, not an
// error.
func PeerCertificates(ctx context.Context, w dns.ResponseWriter) ([]*x509.Certificate, bool) {
	if req, isDoH := ctx.Value(dnsserver.HTTPRequestKey{}).(*http.Request); isDoH && req != nil {
		return certsFromState(req.TLS)
	}
	if cs, isDoT := w.(dns.ConnectionStater); isDoT {
		return certsFromState(cs.ConnectionState())
	}
	return nil, false
}

func certsFromState(st *tls.ConnectionState) ([]*x509.Certificate, bool) {
	if st == nil || len(st.PeerCertificates) == 0 {
		return nil, false
	}
	return st.PeerCertificates, true
}

// SPIFFEIDFromCert returns the certificate's SPIFFE ID (its URI SAN).
//
// Only the spiffe scheme is accepted: a certificate may carry any URI SAN, and
// without checking the scheme one carrying an https:// URI could pass itself off
// as a source of identity.
func SPIFFEIDFromCert(cert *x509.Certificate) (string, bool) {
	for _, u := range cert.URIs {
		if u != nil && u.Scheme == "spiffe" {
			return u.String(), true
		}
	}
	return "", false
}
```

- [ ] **Step 6: Run the test and confirm it passes**

Run: `go test ./internal/identity/ -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add go.mod go.sum internal/identity/
git commit -m "feat(identity): extract peer certificate for DoT and DoH"
```

---

### Task 6: `identity.SourceZone` — the complete trust boundary

Chains Task 5's certificate extraction, the authorized agent list comparison and
the EDNS0 read into the five steps of spec §6.1. **This is the most densely
tested place in the project** — every bypass must have a test of its own.

**Files:**
- Create: `internal/identity/identity.go`
- Test: `internal/identity/identity_test.go`

**Interfaces:**
- Consumes:
  - `identity.PeerCertificates` and `identity.SPIFFEIDFromCert` (Task 5)
  - `ednszone.Get` and `ednszone.DefaultCode` (Task 2)
- Produces:
  - the `identity.Reason` type with the constants `ReasonOK`, `ReasonNoTLS`, `ReasonUnauthorizedAgent` and `ReasonNoDeclaration`
  - the `identity.Config` struct, with fields `AuthorizedAgents []string` and `EDNS0Code uint16`
  - `identity.NewConfig(agents []string, code uint16) Config`
  - `(Config).SourceZone(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (string, Reason)`

- [ ] **Step 1: Write the failing test**

Create `internal/identity/identity_test.go`:

```go
package identity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/jenting/zonedns/internal/ednszone"
	"github.com/miekg/dns"
)

const agentID = "spiffe://example.org/node/n1"

func cfg() Config {
	return NewConfig([]string{agentID}, ednszone.DefaultCode)
}

// query builds a query carrying a source zone declaration; an empty zone adds
// no declaration.
func query(zone string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("payments.example.com.", dns.TypeA)
	if zone != "" {
		ednszone.Set(m, ednszone.DefaultCode, zone)
	}
	return m
}

// tlsWriter builds a DoT writer carrying the given certificates.
func tlsWriter(t *testing.T, uri string) dns.ResponseWriter {
	t.Helper()
	certs := []*x509.Certificate{newTestCert(t, uri)}
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

// No TLS means no identity — the ordinary path for a non-zone-aware listener.
func TestSourceZoneNoTLS(t *testing.T) {
	zone, reason := cfg().SourceZone(context.Background(), &plainWriter{}, query("zone-a"))
	if reason != ReasonNoTLS {
		t.Fatalf("reason = %v, want ReasonNoTLS", reason)
	}
	if zone != "" {
		t.Fatalf("zone = %q, want empty", zone)
	}
}

// The core attack: the certificate is valid (the TLS layer verified it) but it
// is not an authorized agent. Its EDNS0 declaration must be ignored entirely.
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

// The authorized list must match exactly, never by prefix.
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

// A certificate without a SPIFFE ID must not count as an authorized agent.
func TestSourceZoneCertWithoutSPIFFEID(t *testing.T) {
	_, reason := cfg().SourceZone(context.Background(), tlsWriter(t, ""), query("zone-a"))
	if reason != ReasonUnauthorizedAgent {
		t.Fatalf("reason = %v, want ReasonUnauthorizedAgent", reason)
	}
}

// Only the leaf is examined. An intermediate CA certificate does not count even
// when it carries an authorized SPIFFE ID.
func TestSourceZoneOnlyLeafCertificateCounts(t *testing.T) {
	leaf := newTestCert(t, "spiffe://example.org/workload/attacker")
	intermediate := newTestCert(t, agentID)
	w := &dotWriter{state: &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf, intermediate},
	}}

	_, reason := cfg().SourceZone(context.Background(), w, query("zone-a"))
	if reason != ReasonUnauthorizedAgent {
		t.Fatalf("reason = %v, want ReasonUnauthorizedAgent", reason)
	}
}

// An empty authorized list means no agent is authorized, not "let everyone
// through".
func TestSourceZoneEmptyAuthorizedListDeniesAll(t *testing.T) {
	c := NewConfig(nil, ednszone.DefaultCode)
	_, reason := c.SourceZone(context.Background(), tlsWriter(t, agentID), query("zone-a"))
	if reason != ReasonUnauthorizedAgent {
		t.Fatalf("reason = %v, want ReasonUnauthorizedAgent", reason)
	}
}

// When the configured option codes disagree, the declaration must be ignored
// rather than misread.
func TestSourceZoneRespectsConfiguredOptionCode(t *testing.T) {
	c := NewConfig([]string{agentID}, 65002)
	_, reason := c.SourceZone(context.Background(), tlsWriter(t, agentID), query("zone-a"))
	if reason != ReasonNoDeclaration {
		t.Fatalf("reason = %v, want ReasonNoDeclaration", reason)
	}
}
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `go test ./internal/identity/ -run TestSourceZone -v`
Expected: FAIL — `undefined: NewConfig`

- [ ] **Step 3: Write the minimal implementation**

Create `internal/identity/identity.go`:

```go
package identity

import (
	"context"

	"github.com/jenting/zonedns/internal/ednszone"
	"github.com/miekg/dns"
)

// Reason explains why SourceZone did (or did not) produce a result. Callers use
// it as a metric label.
type Reason int

const (
	// ReasonOK: a trustworthy source zone was obtained.
	ReasonOK Reason = iota
	// ReasonNoTLS: the connection carries no client certificate — the ordinary
	// non-zone-aware path.
	ReasonNoTLS
	// ReasonUnauthorizedAgent: the certificate is valid but absent from the
	// authorized list. This is an attack signal and must be alerted on.
	ReasonUnauthorizedAgent
	// ReasonNoDeclaration: the agent is authorized but carried no declaration, or
	// declared an invalid zone.
	ReasonNoDeclaration
)

func (r Reason) String() string {
	switch r {
	case ReasonOK:
		return "ok"
	case ReasonNoTLS:
		return "no_tls"
	case ReasonUnauthorizedAgent:
		return "unauthorized_agent"
	case ReasonNoDeclaration:
		return "no_declaration"
	default:
		return "unknown"
	}
}

// Config configures the trust boundary.
type Config struct {
	authorized map[string]struct{}
	code       uint16
}

// NewConfig builds a Config.
//
// An empty agents list means "no agent is authorized", not "let everyone
// through" — a missing configuration must deny rather than open up.
func NewConfig(agents []string, code uint16) Config {
	set := make(map[string]struct{}, len(agents))
	for _, a := range agents {
		set[a] = struct{}{}
	}
	return Config{authorized: set, code: code}
}

// SourceZone obtains a trustworthy source zone for this query, implementing the
// five steps of spec §6.1.
//
// The order of the steps must not be rearranged — in particular, the agent is
// confirmed authorized before the EDNS0 declaration is read. Reading it earlier
// would let an unauthorized party's declaration flow into the logic that
// follows.
func (c Config) SourceZone(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (string, Reason) {
	// Steps 1 and 2: obtain the client certificate. The chain itself has already
	// been verified by the TLS layer against the SPIRE trust bundle, so it is not
	// verified again here.
	certs, ok := PeerCertificates(ctx, w)
	if !ok {
		return "", ReasonNoTLS
	}

	// Step 3: look only at the leaf. Whatever identity an intermediate carries has
	// nothing to do with the caller.
	id, ok := SPIFFEIDFromCert(certs[0])
	if !ok {
		return "", ReasonUnauthorizedAgent
	}
	if _, authorized := c.authorized[id]; !authorized {
		return "", ReasonUnauthorizedAgent
	}

	// Steps 4 and 5: read the declaration only once authorization passes.
	// ednszone.Get validates the format and returns false when it is invalid.
	zone, ok := ednszone.Get(r, c.code)
	if !ok {
		return "", ReasonNoDeclaration
	}
	return zone, ReasonOK
}
```

- [ ] **Step 4: Run the test and confirm it passes**

Run: `go test ./internal/identity/ -v`
Expected: PASS, the whole suite green

- [ ] **Step 5: Add the race check**

Run: `go test ./internal/identity/ -race -v`
Expected: PASS, with no race reported

- [ ] **Step 6: Commit**

```bash
git add internal/identity/
git commit -m "feat(identity): enforce trust boundary for source zone declaration"
```

---

### Task 7: `registry` — the in-memory snapshot and conflict handling

Start with the part that does not depend on SPIRE: building a snapshot from a set
of entries, normalising DNS names, detecting conflicts, and providing
thread-safe atomic replacement. Task 8 connects the real SPIRE polling.

**Files:**
- Create: `internal/registry/registry.go`
- Test: `internal/registry/registry_test.go`

**Interfaces:**
- Consumes: `spiffezone.FromPath` (Task 1)
- Produces:
  - the `registry.Entry` struct, with fields `SPIFFEIDPath string` and `DNSNames []string`
  - the `registry.Snapshot` type
  - `registry.BuildSnapshot(entries []Entry) (*Snapshot, Stats)`
  - the `registry.Stats` struct, with fields `Names int`, `Conflicts int` and `Skipped int`
  - `(*Snapshot).Lookup(fqdn string) (string, bool)`
  - the `registry.Store` type
  - `registry.NewStore() *Store`
  - `(*Store).Replace(s *Snapshot)`
  - `(*Store).Lookup(fqdn string) (string, bool)`
  - `(*Store).Ready() bool`

- [ ] **Step 1: Write the failing test**

Create `internal/registry/registry_test.go`:

```go
package registry

import (
	"sync"
	"testing"
)

func TestLookupNormalizesName(t *testing.T) {
	snap, _ := BuildSnapshot([]Entry{
		{SPIFFEIDPath: "/zone/zone-a/ns/prod/sa/payments", DNSNames: []string{"payments.example.com"}},
	})

	// A DNS query carries a trailing dot and arbitrary case, while the registry's
	// keys come from SPIRE entries and carry none.
	for _, q := range []string{
		"payments.example.com.",
		"payments.example.com",
		"PAYMENTS.Example.COM.",
	} {
		zone, ok := snap.Lookup(q)
		if !ok {
			t.Fatalf("Lookup(%q) not found", q)
		}
		if zone != "zone-a" {
			t.Fatalf("Lookup(%q) = %q, want zone-a", q, zone)
		}
	}
}

func TestLookupMissing(t *testing.T) {
	snap, _ := BuildSnapshot(nil)
	if _, ok := snap.Lookup("nope.example.com."); ok {
		t.Fatal("empty snapshot must not resolve")
	}
}

func TestBuildSnapshotSkipsEntriesWithoutZone(t *testing.T) {
	snap, stats := BuildSnapshot([]Entry{
		{SPIFFEIDPath: "/ns/prod/sa/legacy", DNSNames: []string{"legacy.example.com"}},
		{SPIFFEIDPath: "/zone/zone-a/ns/prod/sa/payments", DNSNames: []string{"payments.example.com"}},
	})

	if _, ok := snap.Lookup("legacy.example.com."); ok {
		t.Fatal("entry without a zone segment must not enter the registry")
	}
	if _, ok := snap.Lookup("payments.example.com."); !ok {
		t.Fatal("valid entry missing from snapshot")
	}
	if stats.Skipped != 1 {
		t.Fatalf("Skipped = %d, want 1", stats.Skipped)
	}
	if stats.Names != 1 {
		t.Fatalf("Names = %d, want 1", stats.Names)
	}
}

// Two entries declaring one name into different zones: neither may be picked,
// and the name becomes unresolvable entirely.
func TestBuildSnapshotConflictMakesNameUnresolvable(t *testing.T) {
	snap, stats := BuildSnapshot([]Entry{
		{SPIFFEIDPath: "/zone/zone-a/ns/prod/sa/payments", DNSNames: []string{"payments.example.com"}},
		{SPIFFEIDPath: "/zone/zone-b/ns/staging/sa/payments", DNSNames: []string{"payments.example.com"}},
	})

	if _, ok := snap.Lookup("payments.example.com."); ok {
		t.Fatal("conflicting name must not resolve to either zone")
	}
	if stats.Conflicts != 1 {
		t.Fatalf("Conflicts = %d, want 1", stats.Conflicts)
	}
}

// Several replicas in one zone sharing a name is normal and not a conflict.
func TestBuildSnapshotSameZoneIsNotConflict(t *testing.T) {
	snap, stats := BuildSnapshot([]Entry{
		{SPIFFEIDPath: "/zone/zone-a/ns/prod/sa/payments", DNSNames: []string{"payments.example.com"}},
		{SPIFFEIDPath: "/zone/zone-a/ns/prod/sa/payments", DNSNames: []string{"payments.example.com"}},
	})

	zone, ok := snap.Lookup("payments.example.com.")
	if !ok || zone != "zone-a" {
		t.Fatalf("got (%q,%v), want (zone-a,true)", zone, ok)
	}
	if stats.Conflicts != 0 {
		t.Fatalf("Conflicts = %d, want 0", stats.Conflicts)
	}
}

func TestBuildSnapshotMultipleNamesPerEntry(t *testing.T) {
	snap, stats := BuildSnapshot([]Entry{{
		SPIFFEIDPath: "/zone/zone-a/ns/prod/sa/payments",
		DNSNames:     []string{"payments.example.com", "pay.example.com"},
	}})

	for _, n := range []string{"payments.example.com.", "pay.example.com."} {
		if _, ok := snap.Lookup(n); !ok {
			t.Fatalf("%s missing", n)
		}
	}
	if stats.Names != 2 {
		t.Fatalf("Names = %d, want 2", stats.Names)
	}
}

func TestBuildSnapshotIgnoresEmptyDNSName(t *testing.T) {
	snap, _ := BuildSnapshot([]Entry{{
		SPIFFEIDPath: "/zone/zone-a/ns/prod/sa/payments",
		DNSNames:     []string{"", "payments.example.com"},
	}})
	if _, ok := snap.Lookup("."); ok {
		t.Fatal("empty DNS name must not become a registry key")
	}
	if _, ok := snap.Lookup("payments.example.com."); !ok {
		t.Fatal("valid name missing")
	}
}

// A Store that is not ready always returns false — during startup the query must
// take the non-zone-aware path rather than guess.
func TestStoreNotReady(t *testing.T) {
	st := NewStore()
	if st.Ready() {
		t.Fatal("a fresh store must not report ready")
	}
	if _, ok := st.Lookup("payments.example.com."); ok {
		t.Fatal("unready store must not resolve")
	}
}

func TestStoreReplace(t *testing.T) {
	st := NewStore()
	snap, _ := BuildSnapshot([]Entry{
		{SPIFFEIDPath: "/zone/zone-a/ns/prod/sa/payments", DNSNames: []string{"payments.example.com"}},
	})
	st.Replace(snap)

	if !st.Ready() {
		t.Fatal("store must report ready after Replace")
	}
	zone, ok := st.Lookup("payments.example.com.")
	if !ok || zone != "zone-a" {
		t.Fatalf("got (%q,%v), want (zone-a,true)", zone, ok)
	}
}

func TestStoreConcurrentReadWrite(t *testing.T) {
	st := NewStore()
	snapA, _ := BuildSnapshot([]Entry{
		{SPIFFEIDPath: "/zone/zone-a/ns/prod/sa/payments", DNSNames: []string{"payments.example.com"}},
	})
	snapB, _ := BuildSnapshot([]Entry{
		{SPIFFEIDPath: "/zone/zone-b/ns/prod/sa/payments", DNSNames: []string{"payments.example.com"}},
	})
	st.Replace(snapA)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				if i%2 == 0 {
					st.Lookup("payments.example.com.")
				} else if j%2 == 0 {
					st.Replace(snapA)
				} else {
					st.Replace(snapB)
				}
			}
		}(i)
	}
	wg.Wait()
}
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `go test ./internal/registry/ -v`
Expected: FAIL — `undefined: BuildSnapshot`

- [ ] **Step 3: Write the minimal implementation**

Create `internal/registry/registry.go`:

```go
// Package registry maintains the mapping from FQDN to dest zone (spec §6.2).
//
// The data comes from SPIRE Server registration entries: an entry's dns_names
// supply the names, and its spiffe_id path supplies the zone. This package only
// turns a set of entries into a queryable snapshot; how the entries are fetched
// is in spire.go.
package registry

import (
	"strings"
	"sync/atomic"

	"github.com/jenting/zonedns/internal/spiffezone"
)

// Entry holds the SPIRE registration entry fields needed to build a snapshot.
type Entry struct {
	SPIFFEIDPath string
	DNSNames     []string
}

// Stats describes the outcome of building one snapshot, for use as metrics.
type Stats struct {
	Names     int // resolvable names
	Conflicts int // names removed because their zones conflicted
	Skipped   int // entries skipped for having no zone segment in the SPIFFE ID
}

// Snapshot is a read-only mapping as of one point in time.
type Snapshot struct {
	zoneOf map[string]string
}

// normalize turns a DNS name into a uniform lookup key: lowercase, no trailing
// dot.
//
// It is needed because the two sides differ in format — a DNS query's qname
// carries a trailing dot and arbitrary case, while a SPIRE entry's dns_names are
// ordinary strings without one.
func normalize(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// BuildSnapshot builds a snapshot from a set of entries.
//
// When one name is declared into different zones, the name is removed entirely
// rather than one of them being picked — any choice could be the wrong one, and
// a wrong zone sends traffic to the wrong gateway. The returned Stats let the
// caller publish the conflict count as a metric to alert on.
func BuildSnapshot(entries []Entry) (*Snapshot, Stats) {
	var stats Stats
	zoneOf := make(map[string]string)
	conflicting := make(map[string]struct{})

	for _, e := range entries {
		zone, err := spiffezone.FromPath(e.SPIFFEIDPath)
		if err != nil {
			stats.Skipped++
			continue
		}
		for _, raw := range e.DNSNames {
			name := normalize(raw)
			if name == "" {
				continue
			}
			if prev, seen := zoneOf[name]; seen && prev != zone {
				conflicting[name] = struct{}{}
				continue
			}
			zoneOf[name] = zone
		}
	}

	for name := range conflicting {
		delete(zoneOf, name)
	}

	stats.Names = len(zoneOf)
	stats.Conflicts = len(conflicting)
	return &Snapshot{zoneOf: zoneOf}, stats
}

// Lookup finds the zone an FQDN belongs to.
func (s *Snapshot) Lookup(fqdn string) (string, bool) {
	zone, ok := s.zoneOf[normalize(fqdn)]
	return zone, ok
}

// Store holds the snapshot currently in effect, supporting concurrent reads and
// atomic replacement.
//
// The read path runs on every DNS query, so this uses an atomic.Pointer rather
// than a mutex: replacement is rare (once per poll interval) and reads are
// frequent.
type Store struct {
	cur atomic.Pointer[Snapshot]
}

// NewStore creates a Store that is not yet ready.
func NewStore() *Store { return &Store{} }

// Replace installs a new snapshot and brings the Store into the ready state.
func (st *Store) Replace(s *Snapshot) { st.cur.Store(s) }

// Ready reports whether a snapshot is present.
func (st *Store) Ready() bool { return st.cur.Load() != nil }

// Lookup queries the current snapshot.
//
// Before the Store is ready it always returns false: during startup, or when the
// first poll fails, queries take the non-zone-aware path and get the ordinary
// answer rather than a guessed zone that could be wrong.
func (st *Store) Lookup(fqdn string) (string, bool) {
	s := st.cur.Load()
	if s == nil {
		return "", false
	}
	return s.Lookup(fqdn)
}
```

- [ ] **Step 4: Run the test and confirm it passes**

Run: `go test ./internal/registry/ -race -v`
Expected: PASS, including the concurrency tests, with no race reported

- [ ] **Step 5: Commit**

```bash
git add internal/registry/
git commit -m "feat(registry): build FQDN to zone snapshots with conflict detection"
```

---

### Task 8: `registry/spire` — the SPIRE Entry API poller

**Files:**
- Create: `internal/registry/spire.go`
- Test: `internal/registry/spire_test.go`
- Modify: `go.mod` — add `github.com/spiffe/spire-api-sdk`

**Interfaces:**
- Consumes: `registry.Entry`, `registry.BuildSnapshot` and `registry.Store` (Task 7)
- Produces:
  - the `registry.EntryLister` interface: `ListEntries(ctx context.Context, pageToken string) ([]Entry, string, error)`
  - the `registry.Poller` type
  - `registry.NewPoller(lister EntryLister, store *Store, interval time.Duration) *Poller`
  - `(*Poller).PollOnce(ctx context.Context) (Stats, error)`
  - `(*Poller).Run(ctx context.Context)`
  - `registry.NewSPIRELister(client entryv1.EntryClient) EntryLister`

- [ ] **Step 1: Add the SPIRE SDK dependency**

```bash
go get github.com/spiffe/spire-api-sdk@latest
```

- [ ] **Step 2: Write the failing test**

Create `internal/registry/spire_test.go`:

```go
package registry

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakeLister returns prearranged pages in order and can inject errors.
type fakeLister struct {
	pages [][]Entry
	err   error
	calls int
}

func (f *fakeLister) ListEntries(_ context.Context, token string) ([]Entry, string, error) {
	f.calls++
	if f.err != nil {
		return nil, "", f.err
	}
	idx := 0
	if token != "" {
		// tokens have the form "page-<n>"
		idx = int(token[len(token)-1] - '0')
	}
	if idx >= len(f.pages) {
		return nil, "", nil
	}
	next := ""
	if idx+1 < len(f.pages) {
		next = "page-" + string(rune('0'+idx+1))
	}
	return f.pages[idx], next, nil
}

func TestPollOnceFollowsPagination(t *testing.T) {
	lister := &fakeLister{pages: [][]Entry{
		{{SPIFFEIDPath: "/zone/zone-a/ns/prod/sa/payments", DNSNames: []string{"payments.example.com"}}},
		{{SPIFFEIDPath: "/zone/zone-b/ns/prod/sa/orders", DNSNames: []string{"orders.example.com"}}},
	}}
	store := NewStore()
	p := NewPoller(lister, store, time.Minute)

	stats, err := p.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if stats.Names != 2 {
		t.Fatalf("Names = %d, want 2 — pagination was not followed", stats.Names)
	}
	if lister.calls != 2 {
		t.Fatalf("calls = %d, want 2", lister.calls)
	}

	if z, ok := store.Lookup("orders.example.com."); !ok || z != "zone-b" {
		t.Fatalf("second page missing from store: (%q,%v)", z, ok)
	}
}

// A failed poll must keep the previous snapshot — a brief SPIRE outage must not
// cost DNS its zone routing everywhere.
func TestPollOnceKeepsPreviousSnapshotOnError(t *testing.T) {
	lister := &fakeLister{pages: [][]Entry{
		{{SPIFFEIDPath: "/zone/zone-a/ns/prod/sa/payments", DNSNames: []string{"payments.example.com"}}},
	}}
	store := NewStore()
	p := NewPoller(lister, store, time.Minute)

	if _, err := p.PollOnce(context.Background()); err != nil {
		t.Fatalf("first poll: %v", err)
	}

	lister.err = errors.New("spire unavailable")
	if _, err := p.PollOnce(context.Background()); err == nil {
		t.Fatal("expected error from failing poll")
	}

	zone, ok := store.Lookup("payments.example.com.")
	if !ok || zone != "zone-a" {
		t.Fatalf("previous snapshot was lost: (%q,%v)", zone, ok)
	}
}

// When the very first poll fails the Store must stay not-ready rather than
// become an empty snapshot. An empty snapshot makes every query "resolvable but
// absent from the registry", which means something different from "not known
// yet".
func TestPollOnceLeavesStoreUnreadyOnFirstFailure(t *testing.T) {
	lister := &fakeLister{err: errors.New("spire unavailable")}
	store := NewStore()
	p := NewPoller(lister, store, time.Minute)

	if _, err := p.PollOnce(context.Background()); err == nil {
		t.Fatal("expected error")
	}
	if store.Ready() {
		t.Fatal("store must stay unready after a failed first poll")
	}
}

func TestRunStopsOnContextCancel(t *testing.T) {
	lister := &fakeLister{pages: [][]Entry{{}}}
	p := NewPoller(lister, NewStore(), 10*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return after context cancellation")
	}
}
```

- [ ] **Step 3: Run the test and confirm it fails**

Run: `go test ./internal/registry/ -run 'TestPoll|TestRun' -v`
Expected: FAIL — `undefined: NewPoller`

- [ ] **Step 4: Write the minimal implementation**

Create `internal/registry/spire.go`:

```go
package registry

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	clog "github.com/coredns/coredns/plugin/pkg/log"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
)

var log = clog.NewWithPlugin("zonedns")

// pollErrors counts consecutive failures, read out by the plugin layer as a
// metric.
var pollErrors atomic.Int64

// ConsecutivePollErrors returns the number of consecutive polling failures. Zero
// means the most recent poll succeeded.
func ConsecutivePollErrors() int64 { return pollErrors.Load() }

// EntryLister fetches one page of registration entries.
//
// It is an interface so the polling logic — pagination, error handling, snapshot
// replacement — can be tested without gRPC.
type EntryLister interface {
	ListEntries(ctx context.Context, pageToken string) ([]Entry, string, error)
}

// pageSize is how many entries are requested from SPIRE at a time.
const pageSize = 500

type spireLister struct {
	client entryv1.EntryClient
}

// NewSPIRELister implements EntryLister over the SPIRE Entry API.
//
// Note that the Entry API has no watch or stream RPC: ListEntries is a paginated
// unary call, and the one streaming RPC (SyncAuthorizedEntries) exists for an
// agent to sync the entries it is authorized for — it cannot list them all. So
// this polls rather than watches.
//
// Calling this API requires an admin SVID: the SPIRE registration entry for the
// host central runs on must set admin: true.
func NewSPIRELister(client entryv1.EntryClient) EntryLister {
	return &spireLister{client: client}
}

func (l *spireLister) ListEntries(ctx context.Context, pageToken string) ([]Entry, string, error) {
	resp, err := l.client.ListEntries(ctx, &entryv1.ListEntriesRequest{
		PageSize:  pageSize,
		PageToken: pageToken,
		// Request only the two fields needed, so selectors and other bulk we do not
		// use are not pulled across.
		OutputMask: &types.EntryMask{
			SpiffeId: true,
			DnsNames: true,
		},
	})
	if err != nil {
		return nil, "", fmt.Errorf("registry: list entries: %w", err)
	}

	out := make([]Entry, 0, len(resp.Entries))
	for _, e := range resp.Entries {
		if e.SpiffeId == nil {
			continue
		}
		out = append(out, Entry{
			SPIFFEIDPath: e.SpiffeId.Path,
			DNSNames:     e.DnsNames,
		})
	}
	return out, resp.NextPageToken, nil
}

// Poller periodically pulls SPIRE's entries into a new snapshot in the Store.
type Poller struct {
	lister   EntryLister
	store    *Store
	interval time.Duration
}

// NewPoller builds a Poller.
func NewPoller(lister EntryLister, store *Store, interval time.Duration) *Poller {
	return &Poller{lister: lister, store: store, interval: interval}
}

// PollOnce fetches every entry and replaces the snapshot.
//
// On failure it does NOT touch the existing snapshot: a brief SPIRE outage must
// not make all zone routing disappear. When the very first poll fails the Store
// stays not-ready rather than becoming an empty snapshot, because "not known
// yet" and "resolvable but absent from the registry" mean different things, and
// the latter would silently drop every cross-zone query back to the ordinary
// answer.
func (p *Poller) PollOnce(ctx context.Context) (Stats, error) {
	var all []Entry
	token := ""
	for {
		page, next, err := p.lister.ListEntries(ctx, token)
		if err != nil {
			return Stats{}, err
		}
		all = append(all, page...)
		if next == "" {
			break
		}
		token = next
	}

	snap, stats := BuildSnapshot(all)
	p.store.Replace(snap)
	return stats, nil
}

// Run polls at the configured interval until ctx ends, polling once immediately
// at startup.
func (p *Poller) Run(ctx context.Context) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		if _, err := p.PollOnce(ctx); err != nil {
			pollErrors.Add(1)
			log.Warningf("registry poll failed, keeping previous snapshot: %v", err)
		} else {
			pollErrors.Store(0)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
```

- [ ] **Step 5: Run the test and confirm it passes**

Run: `go test ./internal/registry/ -race -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/registry/
git commit -m "feat(registry): poll SPIRE Entry API with pagination and failure tolerance"
```

---

### Task 9: assembling the plugin — setup, ServeDNS, the order check, metrics

Wires the previous eight tasks into an actual CoreDNS plugin.

**Files:**
- Create: `plugin/zonedns/zonedns.go`
- Create: `plugin/zonedns/setup.go`
- Create: `plugin/zonedns/metrics.go`
- Test: `plugin/zonedns/zonedns_test.go`
- Test: `plugin/zonedns/setup_test.go`

**Interfaces:**
- Consumes: `identity.Config`, `registry.Store`, `zonetable.Table`, `decision.Decide`, `ednszone.DefaultCode`
- Produces:
  - the `zonedns.ZoneDNS` struct, with fields `Next plugin.Handler`, `Identity identity.Config`, `Registry *registry.Store`, `Zones *zonetable.Table` and `TTL uint32`
  - `(ZoneDNS).Name() string`
  - `(ZoneDNS).ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error)`
  - `zonedns.CheckDirectiveOrder(directives []string) error`

- [ ] **Step 1: Write the failing test for the order check**

Create `plugin/zonedns/setup_test.go`:

```go
package zonedns

import (
	"strings"
	"testing"

	"github.com/coredns/caddy"
)

func TestCheckDirectiveOrder(t *testing.T) {
	if err := CheckDirectiveOrder([]string{"zonedns", "cache", "forward"}); err != nil {
		t.Fatalf("valid order rejected: %v", err)
	}
}

// A wrong order must fail startup, not merely warn — with cache first, a
// cross-zone client receives a same-zone answer cached for somebody else, and
// there is no sign of it at runtime.
func TestCheckDirectiveOrderRejectsCacheFirst(t *testing.T) {
	err := CheckDirectiveOrder([]string{"cache", "zonedns", "forward"})
	if err == nil {
		t.Fatal("expected error when cache precedes zonedns")
	}
	if !strings.Contains(err.Error(), "cache") {
		t.Fatalf("error should name the offending directive: %v", err)
	}
}

func TestCheckDirectiveOrderMissingZonedns(t *testing.T) {
	if err := CheckDirectiveOrder([]string{"cache", "forward"}); err == nil {
		t.Fatal("expected error when zonedns is absent from Directives")
	}
}

// Without cache present the order does not matter.
func TestCheckDirectiveOrderWithoutCache(t *testing.T) {
	if err := CheckDirectiveOrder([]string{"zonedns", "forward"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseCorefile(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns {
		spire_server unix:///tmp/spire-server/private/api.sock
		poll_interval 30s
		authorized_agent spiffe://example.org/node/n1
		authorized_agent spiffe://example.org/node/n2
		edns0_code 65001
		ttl 30
		gateway zone-a 203.0.113.10
		gateway zone-b 203.0.113.11
	}`)

	cfg, err := parseConfig(c)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if len(cfg.authorizedAgents) != 2 {
		t.Fatalf("authorizedAgents = %d, want 2", len(cfg.authorizedAgents))
	}
	if cfg.ttl != 30 {
		t.Fatalf("ttl = %d, want 30", cfg.ttl)
	}
	if cfg.zones.Len() != 2 {
		t.Fatalf("zones = %d, want 2", cfg.zones.Len())
	}
	if got, ok := cfg.zones.Gateway("zone-a"); !ok || got.String() != "203.0.113.10" {
		t.Fatalf("gateway zone-a = (%s,%v)", got, ok)
	}
}

// No authorized agent means this plugin can never be zone-aware: a
// misconfiguration, not a legitimate setup.
func TestParseCorefileRequiresAuthorizedAgent(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns {
		spire_server unix:///tmp/spire-server/private/api.sock
		gateway zone-a 203.0.113.10
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected error when no authorized_agent is configured")
	}
}

func TestParseCorefileRejectsBadGatewayAddress(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns {
		spire_server unix:///tmp/spire-server/private/api.sock
		authorized_agent spiffe://example.org/node/n1
		gateway zone-a not-an-ip
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected error for malformed gateway address")
	}
}
```

- [ ] **Step 2: Write the failing test for ServeDNS**

Create `plugin/zonedns/zonedns_test.go`:

```go
package zonedns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/netip"
	"testing"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/test"
	"github.com/jenting/zonedns/internal/ednszone"
	"github.com/jenting/zonedns/internal/identity"
	"github.com/jenting/zonedns/internal/registry"
	"github.com/jenting/zonedns/internal/zonetable"
	"github.com/miekg/dns"
)

const testAgentID = "spiffe://example.org/node/n1"

// nextCalled is a downstream plugin that records whether it was called.
type nextCalled struct{ called bool }

func (n *nextCalled) Name() string { return "next" }
func (n *nextCalled) ServeDNS(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	n.called = true
	m := new(dns.Msg)
	m.SetReply(r)
	m.Answer = []dns.RR{test.A("payments.example.com. 5 IN A 10.96.0.7")}
	w.WriteMsg(m)
	return dns.RcodeSuccess, nil
}

type dotWriter struct {
	dns.ResponseWriter
	state *tls.ConnectionState
}

func (w *dotWriter) ConnectionState() *tls.ConnectionState { return w.state }

func newHandler(t *testing.T, next plugin.Handler) ZoneDNS {
	t.Helper()

	store := registry.NewStore()
	snap, _ := registry.BuildSnapshot([]registry.Entry{
		{SPIFFEIDPath: "/zone/zone-a/ns/prod/sa/payments", DNSNames: []string{"payments.example.com"}},
		{SPIFFEIDPath: "/zone/zone-z/ns/prod/sa/lonely", DNSNames: []string{"lonely.example.com"}},
	})
	store.Replace(snap)

	return ZoneDNS{
		Next:     next,
		Identity: identity.NewConfig([]string{testAgentID}, ednszone.DefaultCode),
		Registry: store,
		Zones: zonetable.New(map[string]netip.Addr{
			"zone-a": netip.MustParseAddr("203.0.113.10"),
		}),
		TTL: 30,
	}
}

// request builds a query from an authorized agent carrying the given source
// zone.
func request(t *testing.T, qname string, qtype uint16, zone string) (*dns.Msg, dns.ResponseWriter) {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	if zone != "" {
		ednszone.Set(m, ednszone.DefaultCode, zone)
	}
	certs := []*x509.Certificate{newTestCertForAgent(t, testAgentID)}
	w := &dotWriter{
		ResponseWriter: &test.ResponseWriter{},
		state:          &tls.ConnectionState{PeerCertificates: certs},
	}
	return m, w
}

func TestServeDNSCrossZoneAnswersGateway(t *testing.T) {
	next := &nextCalled{}
	h := newHandler(t, next)

	r, w := request(t, "payments.example.com.", dns.TypeA, "zone-b")
	rec := dnstest.NewRecorder(w)

	code, err := h.ServeDNS(context.Background(), rec, r)
	if err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if code != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR", code)
	}
	if next.called {
		t.Fatal("cross-zone query must not reach the next plugin")
	}
	if len(rec.Msg.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(rec.Msg.Answer))
	}
	a, isA := rec.Msg.Answer[0].(*dns.A)
	if !isA {
		t.Fatalf("answer is %T, want *dns.A", rec.Msg.Answer[0])
	}
	if a.A.String() != "203.0.113.10" {
		t.Fatalf("answer = %s, want 203.0.113.10", a.A)
	}
	if a.Hdr.Ttl != 30 {
		t.Fatalf("ttl = %d, want 30", a.Hdr.Ttl)
	}
}

func TestServeDNSSameZonePassesThrough(t *testing.T) {
	next := &nextCalled{}
	h := newHandler(t, next)

	r, w := request(t, "payments.example.com.", dns.TypeA, "zone-a")
	if _, err := h.ServeDNS(context.Background(), dnstest.NewRecorder(w), r); err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if !next.called {
		t.Fatal("same-zone query must reach the next plugin")
	}
}

func TestServeDNSUnknownNamePassesThrough(t *testing.T) {
	next := &nextCalled{}
	h := newHandler(t, next)

	r, w := request(t, "external.example.net.", dns.TypeA, "zone-b")
	if _, err := h.ServeDNS(context.Background(), dnstest.NewRecorder(w), r); err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if !next.called {
		t.Fatal("name outside the registry must reach the next plugin")
	}
}

// A query with no client cert takes the non-zone-aware path; that is not an
// error.
func TestServeDNSNoIdentityPassesThrough(t *testing.T) {
	next := &nextCalled{}
	h := newHandler(t, next)

	m := new(dns.Msg)
	m.SetQuestion("payments.example.com.", dns.TypeA)
	if _, err := h.ServeDNS(context.Background(), dnstest.NewRecorder(&test.ResponseWriter{}), m); err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if !next.called {
		t.Fatal("query without identity must reach the next plugin")
	}
}

// The registry knows this zone but the config has no gateway for it — this must
// SERVFAIL rather than quietly let the query through.
func TestServeDNSMissingGatewayServfails(t *testing.T) {
	next := &nextCalled{}
	h := newHandler(t, next)

	r, w := request(t, "lonely.example.com.", dns.TypeA, "zone-b")
	code, err := h.ServeDNS(context.Background(), dnstest.NewRecorder(w), r)
	if err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if code != dns.RcodeServerFailure {
		t.Fatalf("rcode = %d, want SERVFAIL", code)
	}
	if next.called {
		t.Fatal("misconfigured zone must not fall through to a normal answer")
	}
}

// An IPv4 gateway meeting an AAAA query returns NODATA (NOERROR with an empty
// answer) so the client falls back to A as usual. NXDOMAIN would tell the client
// the name does not exist.
func TestServeDNSCrossZoneAAAAWithIPv4GatewayReturnsNoData(t *testing.T) {
	next := &nextCalled{}
	h := newHandler(t, next)

	r, w := request(t, "payments.example.com.", dns.TypeAAAA, "zone-b")
	rec := dnstest.NewRecorder(w)

	code, err := h.ServeDNS(context.Background(), rec, r)
	if err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if code != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR", code)
	}
	if len(rec.Msg.Answer) != 0 {
		t.Fatalf("answers = %d, want 0", len(rec.Msg.Answer))
	}
	if next.called {
		t.Fatal("cross-zone AAAA must not fall through")
	}
}

// Query types other than A/AAAA are left alone — SRV, TXT and the rest are
// answered downstream as usual.
func TestServeDNSOtherQtypePassesThrough(t *testing.T) {
	next := &nextCalled{}
	h := newHandler(t, next)

	r, w := request(t, "payments.example.com.", dns.TypeTXT, "zone-b")
	if _, err := h.ServeDNS(context.Background(), dnstest.NewRecorder(w), r); err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if !next.called {
		t.Fatal("TXT query must reach the next plugin")
	}
}
```

At the same time, add `"github.com/coredns/coredns/plugin/test"` and
`"github.com/coredns/coredns/plugin/pkg/dnstest"` to the imports at the top of
`plugin/zonedns/zonedns_test.go`, and copy Task 5's certificate generator across,
renamed to `newTestCertForAgent` because test helpers cannot be shared between
packages:

```go
// Add at the end of plugin/zonedns/zonedns_test.go:
func newTestCertForAgent(t *testing.T, uri string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("parse uri: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}
```

- [ ] **Step 3: Run the test and confirm it fails**

Run: `go test ./plugin/zonedns/ -v`
Expected: FAIL — `undefined: ZoneDNS`

- [ ] **Step 4: Fetch the remaining dependencies and write the metrics**

First install them:

```bash
go get github.com/prometheus/client_golang@latest
go get google.golang.org/grpc@latest
go get github.com/spiffe/go-spiffe/v2@latest
```

Then write the metrics.

Create `plugin/zonedns/metrics.go`:

```go
package zonedns

import (
	"github.com/coredns/coredns/plugin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// sourceZoneTotal is broken down by verdict. reason="unauthorized_agent" is an
	// attack signal and should be alerted on; reason="no_tls" is normal during a
	// migration.
	sourceZoneTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns",
		Name:      "source_zone_total",
		Help:      "Count of source zone resolution attempts by outcome.",
	}, []string{"reason"})

	// decisionTotal is broken down by action. action="servfail" means the config is
	// missing a gateway for some zone and should be alerted on.
	decisionTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns",
		Name:      "decision_total",
		Help:      "Count of routing decisions by action.",
	}, []string{"action"})

	// registryNames is the number of currently resolvable names. Dropping to 0
	// means something is wrong with the registry.
	registryNames = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns",
		Name:      "registry_names",
		Help:      "Number of resolvable names in the current registry snapshot.",
	})

	// registryConflicts is the number of names left unresolvable by a zone
	// conflict. Anything but 0 is a configuration problem.
	registryConflicts = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns",
		Name:      "registry_conflicts",
		Help:      "Number of names removed due to conflicting zone declarations.",
	})

	// While registryReady is 0, every query takes the non-zone-aware path.
	registryReady = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns",
		Name:      "registry_ready",
		Help:      "1 when a registry snapshot is loaded, 0 otherwise.",
	})
)
```

- [ ] **Step 5: Write ServeDNS**

Create `plugin/zonedns/zonedns.go`:

```go
// Package zonedns is the central CoreDNS plugin for zone-based DNS.
//
// It decides the response from the asking workload's zone — declared by the
// node-local agent over mTLS with EDNS0 — and the zone the queried name belongs
// to, which comes from SPIRE registration entries: within a zone it hands the
// query downstream for the ordinary answer, and across zones it answers with that
// zone's gateway VIP.
//
// Only one case changes an answer, cross-zone with a configured gateway;
// everything else passes through untouched, which keeps the blast radius of
// importing this plugin as small as possible.
package zonedns

import (
	"context"
	"net"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
	"github.com/jenting/zonedns/internal/decision"
	"github.com/jenting/zonedns/internal/identity"
	"github.com/jenting/zonedns/internal/registry"
	"github.com/jenting/zonedns/internal/zonetable"
	"github.com/miekg/dns"
)

// ZoneDNS is the plugin's handler.
type ZoneDNS struct {
	Next     plugin.Handler
	Identity identity.Config
	Registry *registry.Store
	Zones    *zonetable.Table
	TTL      uint32
}

// Name implements plugin.Handler.
func (z ZoneDNS) Name() string { return "zonedns" }

// ServeDNS implements plugin.Handler.
func (z ZoneDNS) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	// Address queries only. SRV, TXT and the rest go downstream — this plugin has
	// no way to produce a meaningful cross-zone answer for them.
	if state.QType() != dns.TypeA && state.QType() != dns.TypeAAAA {
		return plugin.NextOrFailure(z.Name(), z.Next, ctx, w, r)
	}

	zone, reason := z.Identity.SourceZone(ctx, w, r)
	sourceZoneTotal.WithLabelValues(reason.String()).Inc()

	destZone, destOK := z.Registry.Lookup(state.Name())

	d := decision.Decide(decision.Input{
		SourceZone: zone,
		SourceOK:   reason == identity.ReasonOK,
		DestZone:   destZone,
		DestOK:     destOK,
	}, z.Zones.Gateway)
	decisionTotal.WithLabelValues(d.Action.String()).Inc()

	switch d.Action {
	case decision.ActionAnswerGateway:
		return z.answerGateway(state, d.Gateway.String())
	case decision.ActionServFail:
		log.Errorf("no gateway configured for zone %q while answering %q; check the zonedns gateway settings",
			destZone, state.Name())
		return dns.RcodeServerFailure, nil
	default:
		return plugin.NextOrFailure(z.Name(), z.Next, ctx, w, r)
	}
}

// answerGateway responds with the gateway VIP.
//
// When the gateway is IPv4 and the query is AAAA, or the other way round, it
// returns NODATA (NOERROR with an empty answer) so the client falls back to the
// other address family as usual. NXDOMAIN would tell the client the name does not
// exist at all, and it would give up on the A query too.
func (z ZoneDNS) answerGateway(state request.Request, gw string) (int, error) {
	ip := net.ParseIP(gw)
	isV4 := ip.To4() != nil

	m := new(dns.Msg)
	m.SetReply(state.Req)
	m.Authoritative = true

	hdr := dns.RR_Header{
		Name:  state.QName(),
		Class: dns.ClassINET,
		Ttl:   z.TTL,
	}

	switch {
	case state.QType() == dns.TypeA && isV4:
		hdr.Rrtype = dns.TypeA
		m.Answer = []dns.RR{&dns.A{Hdr: hdr, A: ip.To4()}}
	case state.QType() == dns.TypeAAAA && !isV4:
		hdr.Rrtype = dns.TypeAAAA
		m.Answer = []dns.RR{&dns.AAAA{Hdr: hdr, AAAA: ip.To16()}}
	}

	state.W.WriteMsg(m)
	return dns.RcodeSuccess, nil
}
```

- [ ] **Step 6: Write setup**

Create `plugin/zonedns/setup.go`:

```go
package zonedns

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/jenting/zonedns/internal/ednszone"
	"github.com/jenting/zonedns/internal/identity"
	"github.com/jenting/zonedns/internal/registry"
	"github.com/jenting/zonedns/internal/zonetable"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/go-spiffe/v2/tlsconfig"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)


var log = clog.NewWithPlugin("zonedns")

const (
	defaultPollInterval = 30 * time.Second
	defaultTTL          = uint32(30)
)

func init() { plugin.Register("zonedns", setup) }

// config is the configuration parsed out of the Corefile.
type config struct {
	spireServer      string
	pollInterval     time.Duration
	authorizedAgents []string
	edns0Code        uint16
	ttl              uint32
	zones            *zonetable.Table
	workloadAPI      string // needed only when spire_server is a network address
	trustDomain      string // likewise, used to verify SPIRE Server's identity
}

// CheckDirectiveOrder confirms that zonedns sorts before cache.
//
// The order is a correctness requirement, not a preference: were cache first, it
// would answer from a (qname, qtype) key that carries no zone, and a cross-zone
// client would receive an answer cached for another zone. That mistake leaves no
// sign at runtime, so it has to be stopped at startup.
//
// The order comes from plugin.cfg at compile time, making this a check on the
// build configuration rather than on the user's.
func CheckDirectiveOrder(directives []string) error {
	zonednsAt, cacheAt := -1, -1
	for i, d := range directives {
		switch d {
		case "zonedns":
			zonednsAt = i
		case "cache":
			cacheAt = i
		}
	}
	if zonednsAt < 0 {
		return fmt.Errorf("zonedns is not registered in dnsserver.Directives; add it to plugin.cfg before cache")
	}
	if cacheAt >= 0 && cacheAt < zonednsAt {
		return fmt.Errorf("zonedns must be ordered before cache in plugin.cfg, but cache is at %d and zonedns at %d; "+
			"with cache first, cross-zone clients would receive answers cached for another zone", cacheAt, zonednsAt)
	}
	return nil
}

func setup(c *caddy.Controller) error {
	if err := CheckDirectiveOrder(dnsserver.Directives); err != nil {
		return plugin.Error("zonedns", err)
	}

	cfg, err := parseConfig(c)
	if err != nil {
		return plugin.Error("zonedns", err)
	}

	store := registry.NewStore()

	conn, cleanup, err := dialSPIRE(cfg)
	if err != nil {
		return plugin.Error("zonedns", err)
	}
	lister := registry.NewSPIRELister(entryv1.NewEntryClient(conn))
	poller := registry.NewPoller(lister, store, cfg.pollInterval)

	ctx, cancel := context.WithCancel(context.Background())
	c.OnStartup(func() error {
		go poller.Run(ctx)
		return nil
	})
	c.OnShutdown(func() error {
		cancel()
		cleanup()
		return conn.Close()
	})

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return ZoneDNS{
			Next:     next,
			Identity: identity.NewConfig(cfg.authorizedAgents, cfg.edns0Code),
			Registry: store,
			Zones:    cfg.zones,
			TTL:      cfg.ttl,
		}
	})
	return nil
}

// dialSPIRE connects to SPIRE Server's Entry API.
//
// Two deployment shapes:
//
//   - unix:// — central shares a machine with SPIRE Server and uses the local
//     admin socket. Access to that socket is governed by file permissions and
//     needs no SVID.
//   - anything else (host:port) — mTLS, with certificates from the local SPIRE
//     agent's Workload API. Central's own registration entry must then set
//     admin: true, or the Entry API refuses.
//
// Certificates come from an X509Source rather than static files, so SVID rotation
// needs no configuration reload.
func dialSPIRE(cfg *config) (*grpc.ClientConn, func(), error) {
	if strings.HasPrefix(cfg.spireServer, "unix://") {
		conn, err := grpc.NewClient(cfg.spireServer, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return nil, nil, fmt.Errorf("dial spire server %q: %w", cfg.spireServer, err)
		}
		return conn, func() {}, nil
	}

	if cfg.workloadAPI == "" {
		return nil, nil, fmt.Errorf("spire_server %q is a network address, so workload_api must also be set "+
			"to obtain the admin SVID used to authenticate to the Entry API", cfg.spireServer)
	}
	td, err := spiffeid.TrustDomainFromString(cfg.trustDomain)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid trust_domain %q: %w", cfg.trustDomain, err)
	}

	source, err := workloadapi.NewX509Source(context.Background(),
		workloadapi.WithClientOptions(workloadapi.WithAddr(cfg.workloadAPI)))
	if err != nil {
		return nil, nil, fmt.Errorf("create X509Source from %q: %w", cfg.workloadAPI, err)
	}

	creds := grpccredentials.MTLSClientCredentials(source, source, tlsconfig.AuthorizeMemberOf(td))
	conn, err := grpc.NewClient(cfg.spireServer, grpc.WithTransportCredentials(creds))
	if err != nil {
		source.Close()
		return nil, nil, fmt.Errorf("dial spire server %q: %w", cfg.spireServer, err)
	}
	return conn, func() { source.Close() }, nil
}

func parseConfig(c *caddy.Controller) (*config, error) {
	cfg := &config{
		pollInterval: defaultPollInterval,
		edns0Code:    ednszone.DefaultCode,
		ttl:          defaultTTL,
	}
	gateways := map[string]netip.Addr{}

	for c.Next() {
		for c.NextBlock() {
			switch c.Val() {
			case "spire_server":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				cfg.spireServer = c.Val()

			case "poll_interval":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				d, err := time.ParseDuration(c.Val())
				if err != nil {
					return nil, c.Errf("invalid poll_interval %q: %v", c.Val(), err)
				}
				cfg.pollInterval = d

			case "authorized_agent":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				cfg.authorizedAgents = append(cfg.authorizedAgents, c.Val())

			case "edns0_code":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				var code uint16
				if _, err := fmt.Sscanf(c.Val(), "%d", &code); err != nil {
					return nil, c.Errf("invalid edns0_code %q: %v", c.Val(), err)
				}
				if code < 65001 {
					return nil, c.Errf("edns0_code %d is outside the local/experimental range 65001-65534", code)
				}
				cfg.edns0Code = code

			case "workload_api":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				cfg.workloadAPI = c.Val()

			case "trust_domain":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				cfg.trustDomain = c.Val()

			case "ttl":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				var ttl uint32
				if _, err := fmt.Sscanf(c.Val(), "%d", &ttl); err != nil {
					return nil, c.Errf("invalid ttl %q: %v", c.Val(), err)
				}
				cfg.ttl = ttl

			case "gateway":
				args := c.RemainingArgs()
				if len(args) != 2 {
					return nil, c.Errf("gateway needs a zone and an address, got %d arguments", len(args))
				}
				addr, err := netip.ParseAddr(args[1])
				if err != nil {
					return nil, c.Errf("invalid gateway address %q for zone %q: %v", args[1], args[0], err)
				}
				gateways[args[0]] = addr

			default:
				return nil, c.Errf("unknown property %q", c.Val())
			}
		}
	}

	if cfg.spireServer == "" {
		return nil, c.Err("spire_server is required")
	}
	// With no authorized agent every declaration is ignored and the plugin can
	// never be zone-aware. That is always a misconfiguration, never a legitimate
	// setup.
	if len(cfg.authorizedAgents) == 0 {
		return nil, c.Err("at least one authorized_agent is required")
	}

	cfg.zones = zonetable.New(gateways)
	return cfg, nil
}
```

- [ ] **Step 7: Run the tests and confirm they pass**

```bash
go test ./plugin/zonedns/ -race -v
```

Expected: PASS, the whole suite green

- [ ] **Step 8: Have the Poller report metrics**

Modify `Run` in `internal/registry/spire.go` so the plugin layer can obtain the
statistics. Add a callback field to `Poller`:

```go
// Add a field to the Poller struct:
//   OnSnapshot func(Stats)

// Add to Run's success branch:
//   if p.OnSnapshot != nil {
//       p.OnSnapshot(stats)
//   }
```

And wire it up after the poller is created in `plugin/zonedns/setup.go`:

```go
poller.OnSnapshot = func(s registry.Stats) {
	registryNames.Set(float64(s.Names))
	registryConflicts.Set(float64(s.Conflicts))
	registryReady.Set(1)
	if s.Conflicts > 0 {
		log.Warningf("%d DNS names have conflicting zone declarations and are unresolvable", s.Conflicts)
	}
}
```

- [ ] **Step 9: Run the full test suite**

Run: `go test ./... -race`
Expected: PASS

- [ ] **Step 10: Commit**

```bash
git add go.mod go.sum plugin/zonedns/ internal/registry/spire.go
git commit -m "feat(zonedns): wire plugin with setup, ServeDNS, ordering check and metrics"
```

---

### Task 10: end-to-end verification and the deployment doc

Verify the whole path with real certificates and a complete plugin chain, and
write down the configuration deployment requires.

**Files:**
- Create: `plugin/zonedns/e2e_test.go`
- Create: `README.md`
- Create: `docs/deployment.md`

**Interfaces:**
- Consumes: all of the packages above
- Produces: no new programmatic interface

- [ ] **Step 1: Write the end-to-end test**

Create `plugin/zonedns/e2e_test.go`:

```go
package zonedns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/netip"
	"testing"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/jenting/zonedns/internal/ednszone"
	"github.com/jenting/zonedns/internal/identity"
	"github.com/jenting/zonedns/internal/registry"
	"github.com/jenting/zonedns/internal/zonetable"
	"github.com/miekg/dns"
)

// The full DoH path: the agent certificate, the http.Request in the context, the
// EDNS0 declaration, the registry lookup, the gateway answer. This is the path a
// real deployment takes, since the transport is DoH.
func TestEndToEndDoHCrossZone(t *testing.T) {
	store := registry.NewStore()
	snap, _ := registry.BuildSnapshot([]registry.Entry{
		{SPIFFEIDPath: "/zone/zone-a/ns/prod/sa/payments", DNSNames: []string{"payments.example.com"}},
	})
	store.Replace(snap)

	next := &nextCalled{}
	h := ZoneDNS{
		Next:     next,
		Identity: identity.NewConfig([]string{testAgentID}, ednszone.DefaultCode),
		Registry: store,
		Zones:    zonetable.New(map[string]netip.Addr{"zone-a": netip.MustParseAddr("203.0.113.10")}),
		TTL:      30,
	}

	// What the agent does: establish an mTLS connection with its own SVID and
	// declare the source zone.
	r := new(dns.Msg)
	r.SetQuestion("payments.example.com.", dns.TypeA)
	ednszone.Set(r, ednszone.DefaultCode, "zone-b")

	certs := []*x509.Certificate{newTestCertForAgent(t, testAgentID)}
	req := &http.Request{TLS: &tls.ConnectionState{PeerCertificates: certs}}
	ctx := context.WithValue(context.Background(), dnsserver.HTTPRequestKey{}, req)

	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	if _, err := h.ServeDNS(ctx, rec, r); err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}

	if next.called {
		t.Fatal("cross-zone query reached the next plugin")
	}
	a, isA := rec.Msg.Answer[0].(*dns.A)
	if !isA || a.A.String() != "203.0.113.10" {
		t.Fatalf("answer = %v, want 203.0.113.10", rec.Msg.Answer[0])
	}
}

// One name and one registry, and differing only in source zone produces different
// answers — the core behaviour of the whole design, worth verifying once on its
// own.
func TestEndToEndSameNameDifferentZones(t *testing.T) {
	store := registry.NewStore()
	snap, _ := registry.BuildSnapshot([]registry.Entry{
		{SPIFFEIDPath: "/zone/zone-a/ns/prod/sa/payments", DNSNames: []string{"payments.example.com"}},
	})
	store.Replace(snap)

	build := func(next *nextCalled) ZoneDNS {
		return ZoneDNS{
			Next:     next,
			Identity: identity.NewConfig([]string{testAgentID}, ednszone.DefaultCode),
			Registry: store,
			Zones:    zonetable.New(map[string]netip.Addr{"zone-a": netip.MustParseAddr("203.0.113.10")}),
			TTL:      30,
		}
	}

	// The zone-a client: same zone, handed downstream.
	nextA := &nextCalled{}
	rA, wA := request(t, "payments.example.com.", dns.TypeA, "zone-a")
	if _, err := build(nextA).ServeDNS(context.Background(), dnstest.NewRecorder(wA), rA); err != nil {
		t.Fatalf("zone-a: %v", err)
	}
	if !nextA.called {
		t.Fatal("zone-a client should have been passed through")
	}

	// The zone-b client: cross-zone, answered with the gateway.
	nextB := &nextCalled{}
	rB, wB := request(t, "payments.example.com.", dns.TypeA, "zone-b")
	recB := dnstest.NewRecorder(wB)
	if _, err := build(nextB).ServeDNS(context.Background(), recB, rB); err != nil {
		t.Fatalf("zone-b: %v", err)
	}
	if nextB.called {
		t.Fatal("zone-b client should not have been passed through")
	}
	if recB.Msg.Answer[0].(*dns.A).A.String() != "203.0.113.10" {
		t.Fatal("zone-b client did not receive the gateway address")
	}
}
```

- [ ] **Step 2: Run the test and confirm it passes**

Run: `go test ./plugin/zonedns/ -race -run TestEndToEnd -v`
Expected: PASS

- [ ] **Step 3: Write the deployment doc**

Create `docs/deployment.md`:

````markdown
# Deploying zonedns central

## Building

zonedns is an external CoreDNS plugin. CoreDNS plugins are linked at compile time
with no runtime loading mechanism, so the CoreDNS binary has to be rebuilt.

1. Fetch the CoreDNS source (the version must match the pin in `go.mod`)
2. Add one line to `plugin.cfg`, **before cache**:

   ```
   zonedns:github.com/jenting/zonedns/plugin/zonedns
   ```

   It must not go after `cache` — the plugin checks at startup and refuses to
   start.

3. Build:

   ```bash
   go generate && go build
   ```

## SPIRE preconditions

### 1. Workload registration entries — the registry's data source

zonedns's registry comes entirely from SPIRE registration entries: `dns_names`
supply the names and the `spiffe_id` path supplies the zone. On the Kubernetes
side they are produced by a `ClusterSPIFFEID`:

```yaml
apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterSPIFFEID
metadata:
  name: zonedns-workloads
spec:
  # A required guard: without this line, a pod not labelled zonedns.io/host
  # renders empty dns_names, SPIRE Server refuses the whole entry with
  # ErrEmptyDomain, and that pod gets no SVID at all — damage reaching far beyond
  # DNS.
  podSelector:
    matchExpressions:
      - {key: zonedns.io/host, operator: Exists}
  spiffeIDTemplate: 'spiffe://example.org/zone/{{ .PodMeta.Labels.zone }}/ns/{{ .PodMeta.Namespace }}/sa/{{ .PodSpec.ServiceAccountName }}'
  dnsNameTemplates:
    - '{{ index .PodMeta.Labels "zonedns.io/host" }}'
```

The corresponding Deployment pod template:

```yaml
metadata:
  labels:
    zone: zone-a
    zonedns.io/host: payments.example.com
```

On the VM side the entry has the same shape and the registry cannot tell the
difference:

```bash
spire-server entry create \
  -spiffeID spiffe://example.org/zone/zone-c/vm/billing-01 \
  -parentID spiffe://example.org/vm/vm-01 \
  -selector unix:uid:1000 \
  -dns billing.example.com
```

**A workload may have exactly one external FQDN.** A second optional label
renders the empty string when unset and the entry is refused; a second
`ClusterSPIFFEID` is masked by `entriesMasked` because its SPIFFE ID and selector
are identical.

### 2. Central's own access to the Entry API

Two shapes, chosen by `spire_server` in the Corefile:

**Same machine (recommended)** — central and SPIRE Server share a VM and use the
local admin socket:

```
spire_server unix:///run/spire/sockets/server.sock
```

Access is governed by file permissions and needs no SVID, no `workload_api` and
no `trust_domain`.

**Across machines** — mTLS, for which central needs an **admin SVID** and must set
both `workload_api` and `trust_domain`:

```bash
spire-server entry create \
  -spiffeID spiffe://example.org/zone/mgmt/service/zonedns-central \
  -parentID spiffe://example.org/vm/central-01 \
  -selector unix:uid:1000 \
  -admin
```

```
spire_server  spire-server.example.org:8081
workload_api  unix:///run/spire/sockets/agent.sock
trust_domain  example.org
```

## Corefile

```
example.com:853 {
    tls /etc/zonedns/svid.pem /etc/zonedns/svid-key.pem /etc/zonedns/bundle.pem {
        client_auth require_and_verify
    }

    zonedns {
        spire_server unix:///run/spire/sockets/server.sock
        poll_interval 30s

        # Only source zones declared by these SPIFFE IDs are believed.
        # Matched exactly; prefixes are not supported.
        authorized_agent spiffe://example.org/zone/infra/node/node-01
        authorized_agent spiffe://example.org/zone/infra/node/node-02

        edns0_code 65001
        ttl 30

        gateway zone-a 203.0.113.10
        gateway zone-b 203.0.113.11
        gateway zone-c 203.0.113.12
    }

    cache 30
    forward . 10.96.0.10
    prometheus :9153
    log
    errors
}
```

`client_auth require_and_verify` is required — without it CoreDNS does not ask for
a client certificate, `identity` gets none, every query takes the non-zone-aware
path, and **zone routing fails completely with no error message**.

## Required alerts

| Metric | Condition | Meaning |
|---|---|---|
| `coredns_zonedns_source_zone_total{reason="unauthorized_agent"}` | Any non-zero growth | An unauthorized source is declaring a zone; this is an attack signal |
| `coredns_zonedns_decision_total{action="servfail"}` | Any non-zero growth | Some zone has no gateway configured |
| `coredns_zonedns_registry_conflicts` | > 0 | An FQDN is declared into several zones, and those names are currently unresolvable |
| `coredns_zonedns_registry_ready` | == 0 for longer than one poll interval | The registry has not loaded and every query falls back to non-zone-aware |
| `coredns_zonedns_source_zone_total{reason="no_tls"}` | Still growing after the migration is complete | Some client is not using the mTLS path |

## An irreversible precondition

**No device may terminate TLS on the path between central and the node agents** —
no L7 ingress, no reverse proxy, no TLS-terminating load balancer. With one in
place, the client certificate central sees is that device's, the
`authorized_agent` comparison either fails or matches the wrong thing, and
**queries still return answers normally** — the failure is entirely silent.

This should be verified continuously by test: issue queries periodically with an
unauthorized certificate and confirm the zone declaration really is ignored.
````

- [ ] **Step 4: Write the README**

Create `README.md`:

```markdown
# zonedns

Zone-based DNS for mixed Kubernetes and VM environments, built on SPIFFE/SPIRE.

When workloads within one zone talk to each other, the answer is the ordinary
service address; across zones it is the destination zone's gateway VIP. The
asking workload's zone is determined by node-local DNS from the source pod IP and
declared to central over mTLS DoH; the queried name's zone comes from its SPIRE
registration entry.

- Design document: `docs/superpowers/specs/2026-08-18-zonedns-design.md`
- Deployment guide: `docs/deployment.md`

## Components

| Path | What it does |
|---|---|
| `plugin/zonedns` | The central CoreDNS plugin: deciding and responding |
| `internal/identity` | The trust boundary: verifies the agent's identity and reads the source zone declaration |
| `internal/registry` | Polls the SPIRE Entry API and maintains FQDN → zone |
| `internal/zonetable` | The zone → gateway VIP configuration |
| `internal/decision` | The core decision table (a pure function) |
| `internal/ednszone` | The EDNS0 wire format between agent and central |
| `internal/spiffezone` | Extracts the zone from a SPIFFE ID path |

## Tests

```bash
go test ./... -race
```

`internal/identity`'s tests cover a range of bypass attempts — whether zone
isolation holds at all depends on nothing but that package, so read its tests
before changing it.
```

- [ ] **Step 5: Run the full test suite and static checks**

```bash
go vet ./...
go test ./... -race -cover
```

Expected: no vet warnings; the whole suite passes; coverage of
`internal/identity` and `internal/decision` above 90%

- [ ] **Step 6: Commit**

```bash
git add plugin/zonedns/e2e_test.go README.md docs/deployment.md
git commit -m "test(zonedns): add end-to-end coverage and deployment docs"
```
