// Package registry 維護 FQDN 到 dest zone 的對照（spec §6.2）。
//
// 資料來源是 SPIRE Server 的 registration entry：entry 的 dns_names 提供名稱，
// entry 的 spiffe_id path 提供 zone。本套件只處理「一組 entry → 可查詢的快照」，
// 取得 entry 的方式在 spire.go。
package registry

import (
	"strings"
	"sync/atomic"

	"github.com/jenting/zonedns/internal/ednszone"
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
	Skipped   int // 因 SPIFFE ID 沒有 zone 段、或 zone 字串不合 ednszone.Valid 而略過的 entry 數
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
		// ednszone.Valid 是 identity.SourceZone 用來驗證 agent 宣告的 source
		// zone 字元集的同一套規則（見 ednszone.Get）。若在這裡放行一個不合此
		// 規則的 zone（例如 k8s label value 允許但 ednszone.Valid 拒絕的
		// "zone.a"），它會在 gateway 表與這份 registry 裡都能正常查得到、正常
		// 當 dest zone 使用，但該 zone 裡的每一個 workload 當 source 發問時，
		// 它們 agent 宣告的 source zone 都會被 ednszone.Get 判成不合法而丟棄
		// （ReasonNoDeclaration）—— 於是這些 workload 永遠拿到 zone-盲的答案，
		// 且沒有告警。因此兩側必須用同一套驗證，不合規的 zone 一律視同「沒有
		// zone 段」處理，計進 Skipped 而非放進可查詢的快照。
		if !ednszone.Valid(zone) {
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
