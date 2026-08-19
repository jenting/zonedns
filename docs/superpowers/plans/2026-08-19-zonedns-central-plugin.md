# zonedns Central Plugin Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 實作 zonedns 的中心端 CoreDNS plugin — 終結 mTLS DoH、驗證 agent 身分、依 source zone 與 dest zone 決定回一般答案或 zone gateway VIP。

**Architecture:** 一個 CoreDNS plugin（`zonedns`），組合四個獨立可測的單元：`identity`（信任邊界，從 peer cert + EDNS0 取得 source zone）、`registry`（輪詢 SPIRE Entry API，維護 FQDN → dest zone）、`zonetable`（zone → gateway VIP 設定）、`decision`（純函式）。plugin 必須排在 `cache` 之前，此約束在啟動時強制檢查。

**Tech Stack:** Go、CoreDNS plugin API、miekg/dns、spire-api-sdk（Entry API gRPC）、go-spiffe/v2（SVID 來源與 SPIFFE ID 解析）、Prometheus client。

**Spec:** `docs/superpowers/specs/2026-08-18-zonedns-design.md`

## Global Constraints

- Go module path：`github.com/jenting/zonedns`
- Go 版本：1.25（對齊 `sigs.k8s.io/node-local-dns` 的 `go 1.25.0`，子專案 2 要共用套件）
- CoreDNS 版本：`github.com/coredns/coredns v1.14.6`（對齊 node-local-dns 的 pin）
- EDNS0 option code 預設 `65001`（local/experimental 區間 65001–65534），可經設定覆寫
- 跨 zone 答案 TTL 預設 `30` 秒，可經設定覆寫
- SPIFFE ID path 格式：`/zone/<zone>/...`，zone 為 path 的第二段
- **`zonedns` 在 `dnsserver.Directives` 中必須排在 `cache` 之前**，違反時啟動失敗
- 共用套件放 `internal/`（子專案 2 在同一 module 內，可正常匯入）
- 所有 metric 前綴 `zonedns_`，subsystem 遵循 CoreDNS 慣例

---

### Task 1: 專案骨架 + `spiffezone`（從 SPIFFE ID 取 zone）

**Files:**
- Create: `go.mod`
- Create: `internal/spiffezone/spiffezone.go`
- Test: `internal/spiffezone/spiffezone_test.go`

**Interfaces:**
- Consumes: 無（第一個任務）
- Produces:
  - `spiffezone.FromPath(path string) (string, error)`
  - `spiffezone.FromID(id string) (string, error)`
  - `spiffezone.ErrNoZone error`

- [ ] **Step 1: 建立 module**

```bash
cd /Users/jenting/go/src/github.com/jenting/zonedns
go mod init github.com/jenting/zonedns
go mod edit -go=1.25
```

- [ ] **Step 2: 寫失敗的測試**

建立 `internal/spiffezone/spiffezone_test.go`：

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

- [ ] **Step 3: 執行測試確認失敗**

Run: `go test ./internal/spiffezone/ -v`
Expected: FAIL — `undefined: FromPath`

- [ ] **Step 4: 寫最小實作**

建立 `internal/spiffezone/spiffezone.go`：

```go
// Package spiffezone 從 SPIFFE ID 取出 zone。
//
// 約定：zone 是 SPIFFE ID path 的第一組 key/value，形如 /zone/<zone>/...
// 這個約定同時被 central plugin（取 dest zone）與 agent plugin（取 source zone）
// 使用，因此放在共用套件裡，避免兩邊各寫一份而發生解析差異。
package spiffezone

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ErrNoZone 表示 path 裡沒有合法的 zone 段。
var ErrNoZone = errors.New("spiffezone: no zone segment in path")

// FromPath 從 SPIFFE ID 的 path 取出 zone。
func FromPath(path string) (string, error) {
	segs := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(segs) < 2 || segs[0] != "zone" || segs[1] == "" {
		return "", ErrNoZone
	}
	return segs[1], nil
}

// FromID 從完整的 SPIFFE ID 取出 zone。
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

- [ ] **Step 5: 執行測試確認通過**

Run: `go test ./internal/spiffezone/ -v`
Expected: PASS，全部子測試綠燈

- [ ] **Step 6: Commit**

```bash
git add go.mod internal/spiffezone/
git commit -m "feat(spiffezone): extract zone from SPIFFE ID path"
```

---

### Task 2: `ednszone` — EDNS0 契約編解碼

這是子專案 1 與子專案 2 之間**唯一的相容性介面**（spec §6.6）。兩端都用這個套件，
所以編碼與解碼寫在一起、一起測試，不會有一邊改了另一邊沒改的情況。

**Files:**
- Create: `internal/ednszone/ednszone.go`
- Test: `internal/ednszone/ednszone_test.go`
- Modify: `go.mod`（加入 `github.com/miekg/dns`）

**Interfaces:**
- Consumes: 無
- Produces:
  - `ednszone.DefaultCode uint16 = 65001`
  - `ednszone.Get(m *dns.Msg, code uint16) (string, bool)`
  - `ednszone.Set(m *dns.Msg, code uint16, zone string)`
  - `ednszone.Valid(zone string) bool`
  - `ednszone.MaxLen int = 63`

- [ ] **Step 1: 加入相依套件**

```bash
go get github.com/miekg/dns@latest
```

- [ ] **Step 2: 寫失敗的測試**

建立 `internal/ednszone/ednszone_test.go`：

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
	// 不可累積出兩個同 code 的 option
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
	m.SetEdns0(4096, true) // 既有的 OPT，帶 DO bit
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
	m.SetEdns0(4096, false) // 有 OPT 但沒有我們的 option
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

- [ ] **Step 3: 執行測試確認失敗**

Run: `go test ./internal/ednszone/ -v`
Expected: FAIL — `undefined: Set`

- [ ] **Step 4: 寫最小實作**

建立 `internal/ednszone/ednszone.go`：

```go
// Package ednszone 定義 agent 與 central 之間傳遞 source zone 的線上格式。
//
// 這是兩個子專案唯一的相容性介面（spec §6.6）：agent 用 Set 寫入，central 用 Get
// 讀出。編碼與解碼刻意放在同一個套件並一起測試，避免任一端單方面改動。
//
// 選 EDNS0 而非 EDNS Client Subnet：ECS 的語意是網段而非身分，且會被中間的
// resolver 依 RFC 7871 改寫。選 local/experimental 區間的 option code：該區間
// (65001-65534) 由 IANA 保留給私有用途，不會與標準 option 衝突。
package ednszone

import (
	"github.com/miekg/dns"
)

// DefaultCode 是預設的 EDNS0 option code，取自 IANA 的 local/experimental 區間。
const DefaultCode uint16 = 65001

// MaxLen 是 zone 字串的長度上限，與 k8s label value 的上限一致。
const MaxLen = 63

// Valid 回報 zone 字串是否合法。
//
// 這道檢查在解碼端也會執行 — 即使宣告來自已驗證的 agent，字串內容仍是外部輸入，
// 不可直接用於後續的 map 查詢或日誌輸出。
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

// Set 在訊息上寫入 source zone，必要時建立 OPT record。
//
// 已存在的 OPT record 會被保留（含 UDP size 與 DO bit），同 code 的舊 option 會被
// 取代而非附加 — 否則重試或轉發路徑上可能累積出多個彼此矛盾的宣告。
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

// Get 讀出 source zone。zone 不合法時回 ok=false，與「不存在」同樣處理。
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

- [ ] **Step 5: 執行測試確認通過**

Run: `go test ./internal/ednszone/ -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/ednszone/
git commit -m "feat(ednszone): define EDNS0 wire contract for source zone"
```

---

### Task 3: `zonetable` — zone 到 gateway VIP

**Files:**
- Create: `internal/zonetable/zonetable.go`
- Test: `internal/zonetable/zonetable_test.go`

**Interfaces:**
- Consumes: 無
- Produces:
  - `zonetable.Table` 型別
  - `zonetable.New(entries map[string]netip.Addr) *Table`
  - `(*Table).Gateway(zone string) (netip.Addr, bool)`
  - `(*Table).Len() int`

- [ ] **Step 1: 寫失敗的測試**

建立 `internal/zonetable/zonetable_test.go`：

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

	// 未設定的 zone 必須回 false，讓決策層產生 SERVFAIL 而非靜默放行。
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

- [ ] **Step 2: 執行測試確認失敗**

Run: `go test ./internal/zonetable/ -v`
Expected: FAIL — `undefined: New`

- [ ] **Step 3: 寫最小實作**

建立 `internal/zonetable/zonetable.go`：

```go
// Package zonetable 保存 zone 到 zone gateway VIP 的對照。
//
// 這份資料來自設定檔，項目數量級是 zone 數（數十筆），啟動後不變 — 因此是唯讀的、
// 不需要鎖。重新載入設定時建立新的 Table 取代舊的。
package zonetable

import "net/netip"

// Table 是 zone 到 gateway VIP 的唯讀對照。
type Table struct {
	gw map[string]netip.Addr
}

// New 建立 Table。輸入的 map 會被複製，呼叫端之後的修改不影響已建立的 Table。
func New(entries map[string]netip.Addr) *Table {
	gw := make(map[string]netip.Addr, len(entries))
	for z, a := range entries {
		gw[z] = a
	}
	return &Table{gw: gw}
}

// Gateway 回傳該 zone 的 gateway VIP。
//
// 找不到時回 ok=false。呼叫端必須把這個情況當成設定錯誤處理（SERVFAIL），
// 不可退回一般答案 — 見 spec §6.4 第四列。
func (t *Table) Gateway(zone string) (netip.Addr, bool) {
	a, ok := t.gw[zone]
	return a, ok
}

// Len 回傳已設定的 zone 數量。
func (t *Table) Len() int { return len(t.gw) }
```

- [ ] **Step 4: 執行測試確認通過**

Run: `go test ./internal/zonetable/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/zonetable/
git commit -m "feat(zonetable): map zone to gateway VIP"
```

---

### Task 4: `decision` — 純決策函式

實作 spec §6.4 的五列決策表。這是整個 plugin 的核心邏輯，刻意做成無 I/O 的純函式，
可以窮舉測試。

**Files:**
- Create: `internal/decision/decision.go`
- Test: `internal/decision/decision_test.go`

**Interfaces:**
- Consumes: 無
- Produces:
  - `decision.Action` 型別與常數 `ActionPassThrough`、`ActionAnswerGateway`、`ActionServFail`
  - `decision.Decision` 結構（欄位 `Action Action`、`Gateway netip.Addr`）
  - `decision.Input` 結構（欄位 `SourceZone string`、`SourceOK bool`、`DestZone string`、`DestOK bool`）
  - `decision.Decide(in Input, gateway func(string) (netip.Addr, bool)) Decision`

- [ ] **Step 1: 寫失敗的測試**

建立 `internal/decision/decision_test.go`：

```go
package decision

import (
	"net/netip"
	"testing"
)

var gwA = netip.MustParseAddr("203.0.113.10")

// gateways 模擬 zonetable：只有 zone-a 有 gateway 設定。
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

// 同 zone 不查 gateway 表 — 若查了，未設定 gateway 的 zone 會誤觸 SERVFAIL。
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

- [ ] **Step 2: 執行測試確認失敗**

Run: `go test ./internal/decision/ -v`
Expected: FAIL — `undefined: Decide`

- [ ] **Step 3: 寫最小實作**

建立 `internal/decision/decision.go`：

```go
// Package decision 實作 zonedns 的核心決策邏輯（spec §6.4）。
//
// 刻意做成無 I/O 的純函式：所有外部狀態都由呼叫端先查好再傳進來。這讓決策表可以
// 被窮舉測試，也讓「什麼情況該做什麼」這件事集中在一個地方，不散落在 ServeDNS 裡。
package decision

import "net/netip"

// Action 是決策結果要採取的動作。
type Action int

const (
	// ActionPassThrough 把查詢交給 plugin chain 的下一個 plugin。
	ActionPassThrough Action = iota
	// ActionAnswerGateway 直接以 zone gateway VIP 回答。
	ActionAnswerGateway
	// ActionServFail 回 SERVFAIL。
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

// Input 是做決策所需的全部資訊。
type Input struct {
	SourceZone string
	SourceOK   bool // 是否成功取得可信的 source zone
	DestZone   string
	DestOK     bool // 該 FQDN 是否在 registry 中
}

// Decision 是決策結果。Gateway 只在 Action 為 ActionAnswerGateway 時有意義。
type Decision struct {
	Action  Action
	Gateway netip.Addr
}

// Decide 實作 spec §6.4 的決策表。
//
// gateway 是 zone 到 gateway VIP 的查詢函式（通常是 zonetable.Table.Gateway）。
func Decide(in Input, gateway func(string) (netip.Addr, bool)) Decision {
	// source zone 未知 — 這是非 zone-aware 的正常路徑，不是錯誤。
	if !in.SourceOK {
		return Decision{Action: ActionPassThrough}
	}
	// 這個名字不歸我們管（例如外部網域）。
	if !in.DestOK {
		return Decision{Action: ActionPassThrough}
	}
	// 同 zone — 交給下游回一般答案。刻意不查 gateway 表：同 zone 根本不需要
	// gateway，若查了，未設定 gateway 的 zone 會在自己人互打時誤觸 SERVFAIL。
	if in.DestZone == in.SourceZone {
		return Decision{Action: ActionPassThrough}
	}
	// 跨 zone — 必須有 gateway 設定。
	gw, ok := gateway(in.DestZone)
	if !ok {
		// registry 說這個 zone 存在，但設定檔沒有它的 gateway。這是設定漏掉，
		// 靜默回一般答案等於無聲破壞 zone 隔離，因此刻意不 fail-open。
		return Decision{Action: ActionServFail}
	}
	return Decision{Action: ActionAnswerGateway, Gateway: gw}
}
```

- [ ] **Step 4: 執行測試確認通過**

Run: `go test ./internal/decision/ -v`
Expected: PASS，六個子測試全綠

- [ ] **Step 5: Commit**

```bash
git add internal/decision/
git commit -m "feat(decision): implement zone routing decision table"
```

---

### Task 5: `identity` — peer certificate 取得

處理 DoT 與 DoH 兩種傳輸取得 client certificate 的差異（spec §6.1）。
分成獨立任務是因為這裡有一個容易踩錯的細節：DoH 必須從 context 取 HTTP request，
不能對 `dns.ResponseWriter` 做型別斷言 — 上游 plugin 可能包裝過 writer。

**Files:**
- Create: `internal/identity/peercert.go`
- Test: `internal/identity/peercert_test.go`
- Test: `internal/identity/testdata_test.go`（測試用憑證產生器）
- Modify: `go.mod`（加入 `github.com/coredns/coredns`）

**Interfaces:**
- Consumes: 無
- Produces:
  - `identity.PeerCertificates(ctx context.Context, w dns.ResponseWriter) ([]*x509.Certificate, bool)`
  - `identity.SPIFFEIDFromCert(cert *x509.Certificate) (string, bool)`
  - 測試輔助：`newTestCert(t *testing.T, uri string) *x509.Certificate`

- [ ] **Step 1: 加入 CoreDNS 相依**

```bash
go get github.com/coredns/coredns@v1.14.6
```

- [ ] **Step 2: 寫測試用憑證產生器**

建立 `internal/identity/testdata_test.go`：

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

// newTestCert 產生一張帶指定 URI SAN 的憑證。uri 為空字串時不帶 URI SAN。
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

- [ ] **Step 3: 寫失敗的測試**

建立 `internal/identity/peercert_test.go`：

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

// plainWriter 模擬一般（非 TLS）的 ResponseWriter。
type plainWriter struct{ dns.ResponseWriter }

// dotWriter 模擬 DoT 的 ResponseWriter，實作 dns.ConnectionStater。
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
	// CoreDNS 的 DoH server 會把 *http.Request 放進 context（server_https.go）。
	// 從 context 取而非對 writer 做型別斷言，才不會被上游 plugin 的包裝影響。
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
	w := &dotWriter{state: &tls.ConnectionState{}} // 有 TLS 但沒有 client cert
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
	req := &http.Request{} // HTTP 沒有 TLS
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

- [ ] **Step 4: 執行測試確認失敗**

Run: `go test ./internal/identity/ -v`
Expected: FAIL — `undefined: PeerCertificates`

- [ ] **Step 5: 寫最小實作**

建立 `internal/identity/peercert.go`：

```go
// Package identity 是 zonedns 的信任邊界（spec §6.1）。
//
// 整套 zone 隔離是否可被繞過，只取決於這個套件是否正確。任何修改都必須連帶檢視
// 這裡的測試是否仍然涵蓋對應的攻擊情境。
package identity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/miekg/dns"
)

// PeerCertificates 取出這次查詢的 client certificate 鏈。
//
// 兩種傳輸的取法不同：
//
//   - DoH：CoreDNS 的 HTTPS server 會把 *http.Request 放進 context。從 context 取
//     而不是對 writer 做型別斷言 — 上游 plugin（例如 metrics）可能包裝過
//     ResponseWriter，型別斷言會失敗，而失敗的方式是「安靜地回 false」，
//     結果是 zone 驗證整個失效卻沒有任何錯誤。
//   - DoT：writer 實作 dns.ConnectionStater。
//
// 沒有 TLS、或有 TLS 但對方沒有出示憑證時回 ok=false。呼叫端必須把這個情況當成
// 「非 zone-aware 的正常路徑」，而不是錯誤。
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

// SPIFFEIDFromCert 取出憑證的 SPIFFE ID（URI SAN）。
//
// 只接受 spiffe scheme：憑證可以帶任意 URI SAN，若不檢查 scheme，一張帶著
// https:// URI 的憑證就能冒充成身分來源。
func SPIFFEIDFromCert(cert *x509.Certificate) (string, bool) {
	for _, u := range cert.URIs {
		if u != nil && u.Scheme == "spiffe" {
			return u.String(), true
		}
	}
	return "", false
}
```

- [ ] **Step 6: 執行測試確認通過**

Run: `go test ./internal/identity/ -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add go.mod go.sum internal/identity/
git commit -m "feat(identity): extract peer certificate for DoT and DoH"
```

---

### Task 6: `identity.SourceZone` — 完整信任邊界

把 Task 5 的憑證取得、授權 agent 清單比對、EDNS0 讀取串成 spec §6.1 的五個步驟。
**這是整個專案測試密度最高的地方** — 每一種繞過方式都要有對應的測試。

**Files:**
- Create: `internal/identity/identity.go`
- Test: `internal/identity/identity_test.go`

**Interfaces:**
- Consumes:
  - `identity.PeerCertificates`、`identity.SPIFFEIDFromCert`（Task 5）
  - `ednszone.Get`、`ednszone.DefaultCode`（Task 2）
- Produces:
  - `identity.Reason` 型別與常數 `ReasonOK`、`ReasonNoTLS`、`ReasonUnauthorizedAgent`、`ReasonNoDeclaration`
  - `identity.Config` 結構（欄位 `AuthorizedAgents []string`、`EDNS0Code uint16`）
  - `identity.NewConfig(agents []string, code uint16) Config`
  - `(Config).SourceZone(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (string, Reason)`

- [ ] **Step 1: 寫失敗的測試**

建立 `internal/identity/identity_test.go`：

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
```

- [ ] **Step 2: 執行測試確認失敗**

Run: `go test ./internal/identity/ -run TestSourceZone -v`
Expected: FAIL — `undefined: NewConfig`

- [ ] **Step 3: 寫最小實作**

建立 `internal/identity/identity.go`：

```go
package identity

import (
	"context"

	"github.com/jenting/zonedns/internal/ednszone"
	"github.com/miekg/dns"
)

// Reason 說明 SourceZone 為何得到（或得不到）結果。呼叫端用它輸出 metric。
type Reason int

const (
	// ReasonOK 成功取得可信的 source zone。
	ReasonOK Reason = iota
	// ReasonNoTLS 連線沒有 client certificate — 非 zone-aware 的正常路徑。
	ReasonNoTLS
	// ReasonUnauthorizedAgent 憑證有效但不在授權清單中。這是攻擊訊號，需告警。
	ReasonUnauthorizedAgent
	// ReasonNoDeclaration agent 已授權，但沒有帶宣告、或宣告的 zone 不合法。
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

// Config 是信任邊界的設定。
type Config struct {
	authorized map[string]struct{}
	code       uint16
}

// NewConfig 建立 Config。
//
// agents 為空表示「沒有任何 agent 被授權」，不是「全部放行」— 設定漏掉時必須是
// 拒絕而非開放。
func NewConfig(agents []string, code uint16) Config {
	set := make(map[string]struct{}, len(agents))
	for _, a := range agents {
		set[a] = struct{}{}
	}
	return Config{authorized: set, code: code}
}

// SourceZone 取得這次查詢可信的 source zone，實作 spec §6.1 的五個步驟。
//
// 步驟順序不可調換 —— 特別是「先確認 agent 已授權，才讀 EDNS0 宣告」。若把讀取
// 提前，未授權者的宣告就會流進後續邏輯。
func (c Config) SourceZone(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (string, Reason) {
	// 步驟 1、2：取得 client certificate。憑證鏈本身已由 TLS 層以 SPIRE trust
	// bundle 驗證過，這裡不重複驗證。
	certs, ok := PeerCertificates(ctx, w)
	if !ok {
		return "", ReasonNoTLS
	}

	// 步驟 3：只看葉憑證。中繼憑證帶什麼身分都與呼叫者無關。
	id, ok := SPIFFEIDFromCert(certs[0])
	if !ok {
		return "", ReasonUnauthorizedAgent
	}
	if _, authorized := c.authorized[id]; !authorized {
		return "", ReasonUnauthorizedAgent
	}

	// 步驟 4、5：通過授權才讀宣告。ednszone.Get 內含格式驗證，不合法時回 false。
	zone, ok := ednszone.Get(r, c.code)
	if !ok {
		return "", ReasonNoDeclaration
	}
	return zone, ReasonOK
}
```

- [ ] **Step 4: 執行測試確認通過**

Run: `go test ./internal/identity/ -v`
Expected: PASS，全部測試綠燈

- [ ] **Step 5: 加上競態檢查**

Run: `go test ./internal/identity/ -race -v`
Expected: PASS，無競態報告

- [ ] **Step 6: Commit**

```bash
git add internal/identity/
git commit -m "feat(identity): enforce trust boundary for source zone declaration"
```

---

### Task 7: `registry` — 記憶體快照與衝突處理

先做不依賴 SPIRE 的部分：從一組 entry 建立快照、正規化 DNS 名稱、偵測衝突、
提供執行緒安全的原子替換。Task 8 才接上真正的 SPIRE 輪詢。

**Files:**
- Create: `internal/registry/registry.go`
- Test: `internal/registry/registry_test.go`

**Interfaces:**
- Consumes: `spiffezone.FromPath`（Task 1）
- Produces:
  - `registry.Entry` 結構（欄位 `SPIFFEIDPath string`、`DNSNames []string`）
  - `registry.Snapshot` 型別
  - `registry.BuildSnapshot(entries []Entry) (*Snapshot, Stats)`
  - `registry.Stats` 結構（欄位 `Names int`、`Conflicts int`、`Skipped int`）
  - `(*Snapshot).Lookup(fqdn string) (string, bool)`
  - `registry.Store` 型別
  - `registry.NewStore() *Store`
  - `(*Store).Replace(s *Snapshot)`
  - `(*Store).Lookup(fqdn string) (string, bool)`
  - `(*Store).Ready() bool`

- [ ] **Step 1: 寫失敗的測試**

建立 `internal/registry/registry_test.go`：

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

	// DNS 查詢帶結尾點且大小寫不定，registry 的 key 來自 SPIRE entry 則不帶點。
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

// 兩筆 entry 對同一個名字宣告不同 zone：不可任選一個，該名字整個視為不可解析。
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

// 同一個 zone 的多個副本共用一個名字是正常的，不算衝突。
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

// 未就緒的 Store 一律回 false — 啟動期間必須走非 zone-aware 路徑，不可猜測。
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

- [ ] **Step 2: 執行測試確認失敗**

Run: `go test ./internal/registry/ -v`
Expected: FAIL — `undefined: BuildSnapshot`

- [ ] **Step 3: 寫最小實作**

建立 `internal/registry/registry.go`：

```go
// Package registry 維護 FQDN 到 dest zone 的對照（spec §6.2）。
//
// 資料來源是 SPIRE Server 的 registration entry：entry 的 dns_names 提供名稱，
// entry 的 spiffe_id path 提供 zone。本套件只處理「一組 entry → 可查詢的快照」，
// 取得 entry 的方式在 spire.go。
package registry

import (
	"strings"
	"sync/atomic"

	"github.com/jenting/zonedns/internal/spiffezone"
)

// Entry 是建立快照所需的 SPIRE registration entry 欄位。
type Entry struct {
	SPIFFEIDPath string
	DNSNames     []string
}

// Stats 描述一次快照建立的結果，供 metric 使用。
type Stats struct {
	Names     int // 可解析的名稱數
	Conflicts int // 因 zone 衝突而被移除的名稱數
	Skipped   int // 因 SPIFFE ID 沒有 zone 段而略過的 entry 數
}

// Snapshot 是某個時間點的唯讀對照表。
type Snapshot struct {
	zoneOf map[string]string
}

// normalize 把 DNS 名稱轉成統一的查詢 key：小寫、無結尾點。
//
// 需要這一步是因為兩端格式不同 — DNS 查詢的 qname 帶結尾點且大小寫不定，
// SPIRE entry 的 dns_names 則是不帶點的一般字串。
func normalize(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// BuildSnapshot 從一組 entry 建立快照。
//
// 同一個名稱被宣告成不同 zone 時，該名稱會被整個移除而非任選一個 —— 這種情況下
// 任何選擇都可能是錯的，而錯誤的 zone 會把流量導向錯誤的 gateway。回傳的 Stats
// 讓呼叫端把衝突數輸出成 metric 以便告警。
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

// Lookup 查出該 FQDN 所屬的 zone。
func (s *Snapshot) Lookup(fqdn string) (string, bool) {
	zone, ok := s.zoneOf[normalize(fqdn)]
	return zone, ok
}

// Store 持有目前生效的快照，支援讀取與原子替換併發進行。
//
// 讀取路徑在每次 DNS 查詢上，因此用 atomic.Pointer 而非 mutex：替換是低頻的
// （每個輪詢週期一次），讀取是高頻的。
type Store struct {
	cur atomic.Pointer[Snapshot]
}

// NewStore 建立尚未就緒的 Store。
func NewStore() *Store { return &Store{} }

// Replace 換上新的快照，並使 Store 進入就緒狀態。
func (st *Store) Replace(s *Snapshot) { st.cur.Store(s) }

// Ready 回報是否已有快照。
func (st *Store) Ready() bool { return st.cur.Load() != nil }

// Lookup 查詢目前的快照。
//
// 尚未就緒時一律回 false —— 啟動期間或首次輪詢失敗時，查詢會走非 zone-aware
// 路徑（回一般答案），而不是猜一個可能錯誤的 zone。
func (st *Store) Lookup(fqdn string) (string, bool) {
	s := st.cur.Load()
	if s == nil {
		return "", false
	}
	return s.Lookup(fqdn)
}
```

- [ ] **Step 4: 執行測試確認通過**

Run: `go test ./internal/registry/ -race -v`
Expected: PASS，含併發測試，無競態報告

- [ ] **Step 5: Commit**

```bash
git add internal/registry/
git commit -m "feat(registry): build FQDN to zone snapshots with conflict detection"
```

---

### Task 8: `registry/spire` — SPIRE Entry API 輪詢器

**Files:**
- Create: `internal/registry/spire.go`
- Test: `internal/registry/spire_test.go`
- Modify: `go.mod`（加入 `github.com/spiffe/spire-api-sdk`）

**Interfaces:**
- Consumes: `registry.Entry`、`registry.BuildSnapshot`、`registry.Store`（Task 7）
- Produces:
  - `registry.EntryLister` 介面：`ListEntries(ctx context.Context, pageToken string) ([]Entry, string, error)`
  - `registry.Poller` 型別
  - `registry.NewPoller(lister EntryLister, store *Store, interval time.Duration) *Poller`
  - `(*Poller).PollOnce(ctx context.Context) (Stats, error)`
  - `(*Poller).Run(ctx context.Context)`
  - `registry.NewSPIRELister(client entryv1.EntryClient) EntryLister`

- [ ] **Step 1: 加入 SPIRE SDK 相依**

```bash
go get github.com/spiffe/spire-api-sdk@latest
```

- [ ] **Step 2: 寫失敗的測試**

建立 `internal/registry/spire_test.go`：

```go
package registry

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakeLister 依序回傳預先安排好的分頁，可注入錯誤。
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
		// token 格式為 "page-<n>"
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

// 輪詢失敗時必須保留上一份快照 —— SPIRE 短暫不可用不應讓全域 DNS 失去 zone 路由。
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

// 首次輪詢就失敗時 Store 必須維持未就緒，不可變成空快照。
// 空快照會讓所有查詢「查得到但都不在 registry」，與「還不知道」意義不同。
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

- [ ] **Step 3: 執行測試確認失敗**

Run: `go test ./internal/registry/ -run 'TestPoll|TestRun' -v`
Expected: FAIL — `undefined: NewPoller`

- [ ] **Step 4: 寫最小實作**

建立 `internal/registry/spire.go`：

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

// pollErrors 記錄連續失敗次數，由 plugin 層讀出成 metric。
var pollErrors atomic.Int64

// ConsecutivePollErrors 回傳連續輪詢失敗次數。0 表示最近一次輪詢成功。
func ConsecutivePollErrors() int64 { return pollErrors.Load() }

// EntryLister 取得一頁 registration entry。
//
// 抽成介面是為了讓輪詢邏輯（分頁、錯誤處理、快照替換）可以脫離 gRPC 測試。
type EntryLister interface {
	ListEntries(ctx context.Context, pageToken string) ([]Entry, string, error)
}

// pageSize 是每次向 SPIRE 索取的 entry 數。
const pageSize = 500

type spireLister struct {
	client entryv1.EntryClient
}

// NewSPIRELister 以 SPIRE Entry API 實作 EntryLister。
//
// 注意 Entry API 沒有 watch/stream RPC：ListEntries 是分頁的一元呼叫，唯一的串流
// RPC (SyncAuthorizedEntries) 是給 agent 同步自己被授權的 entry 用的，不能列出全部。
// 因此這裡是輪詢而非監看。
//
// 呼叫此 API 需要 admin SVID —— central 所在主機的 SPIRE registration entry 必須
// 設定 admin: true。
func NewSPIRELister(client entryv1.EntryClient) EntryLister {
	return &spireLister{client: client}
}

func (l *spireLister) ListEntries(ctx context.Context, pageToken string) ([]Entry, string, error) {
	resp, err := l.client.ListEntries(ctx, &entryv1.ListEntriesRequest{
		PageSize:  pageSize,
		PageToken: pageToken,
		// 只取需要的兩個欄位，避免把 selector 等大量無關資料拉過來。
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

// Poller 週期性地把 SPIRE 的 entry 拉成新快照放進 Store。
type Poller struct {
	lister   EntryLister
	store    *Store
	interval time.Duration
}

// NewPoller 建立 Poller。
func NewPoller(lister EntryLister, store *Store, interval time.Duration) *Poller {
	return &Poller{lister: lister, store: store, interval: interval}
}

// PollOnce 拉取全部 entry 並替換快照。
//
// 失敗時**不會**動到既有快照：SPIRE 短暫不可用不應讓所有 zone 路由消失。首次輪詢
// 就失敗時 Store 維持未就緒（而非變成空快照），因為「還不知道」與「查得到但都不在
// registry」是不同的意思，後者會讓所有跨 zone 查詢靜默地退回一般答案。
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

// Run 依設定的間隔持續輪詢，直到 ctx 結束。啟動時立即輪詢一次。
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

- [ ] **Step 5: 執行測試確認通過**

Run: `go test ./internal/registry/ -race -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/registry/
git commit -m "feat(registry): poll SPIRE Entry API with pagination and failure tolerance"
```

---

### Task 9: plugin 組裝 — setup、ServeDNS、順序檢查、metrics

把前八個任務接成一個真正的 CoreDNS plugin。

**Files:**
- Create: `plugin/zonedns/zonedns.go`
- Create: `plugin/zonedns/setup.go`
- Create: `plugin/zonedns/metrics.go`
- Test: `plugin/zonedns/zonedns_test.go`
- Test: `plugin/zonedns/setup_test.go`

**Interfaces:**
- Consumes: `identity.Config`、`registry.Store`、`zonetable.Table`、`decision.Decide`、`ednszone.DefaultCode`
- Produces:
  - `zonedns.ZoneDNS` 結構（欄位 `Next plugin.Handler`、`Identity identity.Config`、`Registry *registry.Store`、`Zones *zonetable.Table`、`TTL uint32`）
  - `(ZoneDNS).Name() string`
  - `(ZoneDNS).ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error)`
  - `zonedns.CheckDirectiveOrder(directives []string) error`

- [ ] **Step 1: 寫順序檢查的失敗測試**

建立 `plugin/zonedns/setup_test.go`：

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

// 順序錯誤必須是啟動失敗，不能只是警告 —— cache 排在前面時，跨 zone 的 client
// 會拿到別人快取的同 zone 答案，而這在執行期沒有任何徵兆。
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

// 沒有 cache 時順序無所謂。
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

// 沒有授權 agent 等於這個 plugin 永遠不會 zone-aware，是設定錯誤而非合法組態。
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

- [ ] **Step 2: 寫 ServeDNS 的失敗測試**

建立 `plugin/zonedns/zonedns_test.go`：

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

// nextCalled 是一個記錄自己是否被呼叫的下游 plugin。
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

// request 建立一個來自已授權 agent、帶指定 source zone 的查詢。
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

// 沒有 client cert 的查詢走非 zone-aware 路徑，不是錯誤。
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

// registry 有這個 zone，但設定檔沒有它的 gateway —— 必須 SERVFAIL，不可靜默放行。
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

// IPv4 gateway 遇到 AAAA 查詢時回 NODATA（NOERROR + 空 answer），
// 讓 client 正常退回 A。回 NXDOMAIN 會讓 client 認為這個名字不存在。
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

// 非 A/AAAA 的查詢型別不介入 —— 例如 SRV、TXT 應照常由下游回答。
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

同時在 `plugin/zonedns/zonedns_test.go` 檔案開頭的 import 加入
`"github.com/coredns/coredns/plugin/test"` 與 `"github.com/coredns/coredns/plugin/pkg/dnstest"`，
並複製 Task 5 的憑證產生器（改名為 `newTestCertForAgent`，因為跨套件無法共用測試輔助）：

```go
// 於 plugin/zonedns/zonedns_test.go 末端加入：
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

- [ ] **Step 3: 執行測試確認失敗**

Run: `go test ./plugin/zonedns/ -v`
Expected: FAIL — `undefined: ZoneDNS`

- [ ] **Step 4: 取得剩餘相依並寫 metrics**

先安裝：

```bash
go get github.com/prometheus/client_golang@latest
go get google.golang.org/grpc@latest
go get github.com/spiffe/go-spiffe/v2@latest
```

然後寫 metrics。

建立 `plugin/zonedns/metrics.go`：

```go
package zonedns

import (
	"github.com/coredns/coredns/plugin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// sourceZoneTotal 依判定結果分類。reason="unauthorized_agent" 是攻擊訊號，
	// 應設定告警；reason="no_tls" 在遷移期間是正常的。
	sourceZoneTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns",
		Name:      "source_zone_total",
		Help:      "Count of source zone resolution attempts by outcome.",
	}, []string{"reason"})

	// decisionTotal 依動作分類。action="servfail" 表示設定漏了某個 zone 的
	// gateway，應設定告警。
	decisionTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns",
		Name:      "decision_total",
		Help:      "Count of routing decisions by action.",
	}, []string{"action"})

	// registryNames 是目前可解析的名稱數。掉到 0 表示 registry 出問題。
	registryNames = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns",
		Name:      "registry_names",
		Help:      "Number of resolvable names in the current registry snapshot.",
	})

	// registryConflicts 是因 zone 衝突而不可解析的名稱數。非 0 即為設定問題。
	registryConflicts = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns",
		Name:      "registry_conflicts",
		Help:      "Number of names removed due to conflicting zone declarations.",
	})

	// registryReady 為 0 時所有查詢都走非 zone-aware 路徑。
	registryReady = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns",
		Name:      "registry_ready",
		Help:      "1 when a registry snapshot is loaded, 0 otherwise.",
	})
)
```

- [ ] **Step 5: 寫 ServeDNS**

建立 `plugin/zonedns/zonedns.go`：

```go
// Package zonedns 是 zone-based DNS 的中心端 CoreDNS plugin。
//
// 它依查詢者的 zone（由 node-local agent 經 mTLS + EDNS0 宣告）與被查詢名稱所屬的
// zone（來自 SPIRE registration entry）決定回應：同 zone 交給下游回一般答案，
// 跨 zone 則回該 zone 的 gateway VIP。
//
// 只有「跨 zone 且 gateway 已設定」這一種情況會改變答案，其餘一律不介入 ——
// 這讓匯入本 plugin 的影響面盡可能小。
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

// ZoneDNS 是 plugin 的處理器。
type ZoneDNS struct {
	Next     plugin.Handler
	Identity identity.Config
	Registry *registry.Store
	Zones    *zonetable.Table
	TTL      uint32
}

// Name 實作 plugin.Handler。
func (z ZoneDNS) Name() string { return "zonedns" }

// ServeDNS 實作 plugin.Handler。
func (z ZoneDNS) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	// 只處理位址查詢。SRV、TXT 等一律交給下游 —— 本 plugin 沒有能力為它們產生
	// 有意義的跨 zone 答案。
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

// answerGateway 以 gateway VIP 回應。
//
// gateway 是 IPv4 而查詢是 AAAA（或反之）時回 NODATA（NOERROR + 空 answer），
// 讓 client 正常退回另一種位址族。回 NXDOMAIN 會讓 client 認為整個名字不存在，
// 連 A 查詢也一併放棄。
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

- [ ] **Step 6: 寫 setup**

建立 `plugin/zonedns/setup.go`：

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

// config 是從 Corefile 解析出來的設定。
type config struct {
	spireServer      string
	pollInterval     time.Duration
	authorizedAgents []string
	edns0Code        uint16
	ttl              uint32
	zones            *zonetable.Table
	workloadAPI      string // 僅在 spire_server 為網路位址時需要
	trustDomain      string // 同上，用於驗證 SPIRE Server 的身分
}

// CheckDirectiveOrder 確認 zonedns 排在 cache 之前。
//
// 這個順序不是偏好而是正確性要求：cache 若排在前面，它會用 (qname, qtype) 這個
// 不含 zone 的 key 回答，於是跨 zone 的 client 會拿到別的 zone 快取的答案。這種
// 錯誤在執行期沒有任何徵兆，因此必須在啟動時就擋下來。
//
// 順序由編譯期的 plugin.cfg 決定，所以這是建置設定的檢查，不是使用者設定的檢查。
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

// dialSPIRE 連上 SPIRE Server 的 Entry API。
//
// 兩種部署形態：
//
//   - unix:// — central 與 SPIRE Server 同機，走本機管理 socket。該 socket 的存取
//     權由檔案權限控制，不需要 SVID。
//   - 其他（host:port）— 走 mTLS，憑證取自本機 SPIRE agent 的 Workload API。此時
//     central 自己的 registration entry 必須設 admin: true，否則 Entry API 會拒絕。
//
// 憑證用 X509Source 而非靜態檔案，SVID 輪替才不需要重新載入設定。
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
	// 沒有授權 agent 表示所有宣告都會被忽略，plugin 永遠不會 zone-aware。
	// 這一定是設定錯誤，不是合法組態。
	if len(cfg.authorizedAgents) == 0 {
		return nil, c.Err("at least one authorized_agent is required")
	}

	cfg.zones = zonetable.New(gateways)
	return cfg, nil
}
```

- [ ] **Step 7: 執行測試確認通過**

```bash
go test ./plugin/zonedns/ -race -v
```

Expected: PASS，全部測試綠燈

- [ ] **Step 8: 讓 Poller 回報 metric**

修改 `internal/registry/spire.go` 的 `Run`，讓 plugin 層能取得統計。在 `Poller`
加一個回呼欄位：

```go
// 於 Poller 結構加入欄位：
//   OnSnapshot func(Stats)

// 於 Run 的成功分支加入：
//   if p.OnSnapshot != nil {
//       p.OnSnapshot(stats)
//   }
```

並在 `plugin/zonedns/setup.go` 建立 poller 後接上：

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

- [ ] **Step 9: 執行完整測試**

Run: `go test ./... -race`
Expected: PASS

- [ ] **Step 10: Commit**

```bash
git add go.mod go.sum plugin/zonedns/ internal/registry/spire.go
git commit -m "feat(zonedns): wire plugin with setup, ServeDNS, ordering check and metrics"
```

---

### Task 10: 端到端驗證與部署文件

用真實的憑證與完整的 plugin chain 驗證整條路徑，並寫下部署所需的設定。

**Files:**
- Create: `plugin/zonedns/e2e_test.go`
- Create: `README.md`
- Create: `docs/deployment.md`

**Interfaces:**
- Consumes: 全部前述套件
- Produces: 無新的程式介面

- [ ] **Step 1: 寫端到端測試**

建立 `plugin/zonedns/e2e_test.go`：

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

// 走 DoH 路徑的完整流程：agent 憑證 → context 中的 http.Request → EDNS0 宣告
// → registry 查詢 → gateway 答案。這是實際部署會走的路徑（傳輸為 DoH）。
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

	// agent 端會做的事：帶自己的 SVID 建立 mTLS 連線，並宣告 source zone。
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

// 同一個名字、同一份 registry，只有 source zone 不同就得到不同答案 ——
// 這是整套設計的核心行為，值得單獨驗證一次。
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

	// zone-a 的 client：同 zone，交給下游。
	nextA := &nextCalled{}
	rA, wA := request(t, "payments.example.com.", dns.TypeA, "zone-a")
	if _, err := build(nextA).ServeDNS(context.Background(), dnstest.NewRecorder(wA), rA); err != nil {
		t.Fatalf("zone-a: %v", err)
	}
	if !nextA.called {
		t.Fatal("zone-a client should have been passed through")
	}

	// zone-b 的 client：跨 zone，回 gateway。
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

- [ ] **Step 2: 執行測試確認通過**

Run: `go test ./plugin/zonedns/ -race -run TestEndToEnd -v`
Expected: PASS

- [ ] **Step 3: 寫部署文件**

建立 `docs/deployment.md`：

````markdown
# zonedns central 部署

## 建置

zonedns 是 external CoreDNS plugin。CoreDNS 的 plugin 是編譯期連結的，沒有執行期
載入機制，因此必須重新建置 CoreDNS binary。

1. 取得 CoreDNS 原始碼（版本需與 `go.mod` 的 pin 一致）
2. 在 `plugin.cfg` 中 **cache 之前** 加入一行：

   ```
   zonedns:github.com/jenting/zonedns/plugin/zonedns
   ```

   順序不可放在 `cache` 之後 —— plugin 啟動時會檢查並拒絕啟動。

3. 建置：

   ```bash
   go generate && go build
   ```

## SPIRE 前置條件

### 一、workload 的 registration entry（registry 的資料來源）

zonedns 的 registry 完全來自 SPIRE registration entry：`dns_names` 提供名稱，
`spiffe_id` 的 path 提供 zone。k8s 這一側用 `ClusterSPIFFEID` 產生：

```yaml
apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterSPIFFEID
metadata:
  name: zonedns-workloads
spec:
  # 必要守衛：沒有這一行，未標 zonedns.io/host 的 pod 會渲染出空的 dns_names，
  # SPIRE Server 以 ErrEmptyDomain 拒絕整筆 entry，該 pod 會拿不到 SVID ——
  # 失效範圍遠大於 DNS。
  podSelector:
    matchExpressions:
      - {key: zonedns.io/host, operator: Exists}
  spiffeIDTemplate: 'spiffe://example.org/zone/{{ .PodMeta.Labels.zone }}/ns/{{ .PodMeta.Namespace }}/sa/{{ .PodSpec.ServiceAccountName }}'
  dnsNameTemplates:
    - '{{ index .PodMeta.Labels "zonedns.io/host" }}'
```

對應的 Deployment pod template：

```yaml
metadata:
  labels:
    zone: zone-a
    zonedns.io/host: payments.example.com
```

VM 這一側的 entry 形式相同，registry 看不出差別：

```bash
spire-server entry create \
  -spiffeID spiffe://example.org/zone/zone-c/vm/billing-01 \
  -parentID spiffe://example.org/vm/vm-01 \
  -selector unix:uid:1000 \
  -dns billing.example.com
```

**一個 workload 只能有一個對外 FQDN。** 加第二個選配 label 會在未填時渲染出空字串
導致 entry 被拒；開第二個 `ClusterSPIFFEID` 會因 SPIFFE ID 與 selector 相同而被
`entriesMasked` 遮蔽。

### 二、central 自己存取 Entry API 的權限

兩種形態，Corefile 的 `spire_server` 決定走哪一種：

**同機（建議）** —— central 與 SPIRE Server 在同一台 VM，走本機管理 socket：

```
spire_server unix:///run/spire/sockets/server.sock
```

存取權由檔案權限控制，不需要 SVID，也不需要 `workload_api` / `trust_domain`。

**跨機** —— 走 mTLS，此時 central 需要 **admin SVID**，且必須設定 `workload_api`
與 `trust_domain`：

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

        # 只有這些 SPIFFE ID 宣告的 source zone 會被採信。
        # 精確比對，不支援前綴。
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

`client_auth require_and_verify` 是必要的 —— 沒有它，CoreDNS 不會要求 client 憑證，
`identity` 取不到憑證就會讓所有查詢走非 zone-aware 路徑，**zone 路由會完全失效
而且沒有錯誤訊息**。

## 必要的告警

| Metric | 條件 | 意義 |
|---|---|---|
| `coredns_zonedns_source_zone_total{reason="unauthorized_agent"}` | 任何非零增長 | 有未授權的來源在宣告 zone，這是攻擊訊號 |
| `coredns_zonedns_decision_total{action="servfail"}` | 任何非零增長 | 某個 zone 缺 gateway 設定 |
| `coredns_zonedns_registry_conflicts` | > 0 | 有 FQDN 被宣告成多個 zone，這些名字目前不可解析 |
| `coredns_zonedns_registry_ready` | == 0 持續超過一個輪詢週期 | registry 未載入，全部查詢退回非 zone-aware |
| `coredns_zonedns_source_zone_total{reason="no_tls"}` | 遷移完成後仍持續增長 | 有 client 沒走 mTLS 路徑 |

## 不可回頭的前提

central 與各節點 agent 之間的路徑上**不得有任何終結 TLS 的設備**（L7 ingress、
反向代理、TLS 終結負載平衡器）。若有，central 看到的 client 憑證會是該設備的，
`authorized_agent` 比對會失敗或誤中，而**查詢仍會正常得到答案** —— 失效完全無聲。

這一點應以測試持續驗證：定期以非授權憑證發出查詢，確認 zone 宣告確實被忽略。
````

- [ ] **Step 4: 寫 README**

建立 `README.md`：

```markdown
# zonedns

Zone-based DNS for mixed Kubernetes and VM environments, built on SPIFFE/SPIRE.

同一個 zone 內的 workload 互打時回一般的服務位址；跨 zone 時回目標 zone 的
gateway VIP。查詢者的 zone 由 node-local DNS 依 source pod IP 查出，經 mTLS DoH
向中心宣告；被查詢名稱的 zone 來自 SPIRE registration entry。

- 設計文件：`docs/superpowers/specs/2026-08-18-zonedns-design.md`
- 部署說明：`docs/deployment.md`

## 元件

| 路徑 | 說明 |
|---|---|
| `plugin/zonedns` | 中心端 CoreDNS plugin：決策與回應 |
| `internal/identity` | 信任邊界：驗證 agent 身分並讀取 source zone 宣告 |
| `internal/registry` | 輪詢 SPIRE Entry API，維護 FQDN → zone |
| `internal/zonetable` | zone → gateway VIP 設定 |
| `internal/decision` | 核心決策表（純函式） |
| `internal/ednszone` | agent 與 central 之間的 EDNS0 線上格式 |
| `internal/spiffezone` | 從 SPIFFE ID path 取出 zone |

## 測試

```bash
go test ./... -race
```

`internal/identity` 的測試涵蓋各種繞過嘗試 —— 整套 zone 隔離是否成立只取決於
該套件，修改前請先讀它的測試。
```

- [ ] **Step 5: 執行完整測試與靜態檢查**

```bash
go vet ./...
go test ./... -race -cover
```

Expected: 無 vet 警告；全部測試通過；`internal/identity` 與 `internal/decision`
的涵蓋率應在 90% 以上

- [ ] **Step 6: Commit**

```bash
git add plugin/zonedns/e2e_test.go README.md docs/deployment.md
git commit -m "test(zonedns): add end-to-end coverage and deployment docs"
```
