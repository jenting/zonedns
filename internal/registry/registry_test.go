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

// k8s label value 允許點字元，但 ednszone.Valid（identity 端驗證 agent 宣告的
// source zone 所用的同一套規則）拒絕。這個 entry 若被放進可查詢的快照，這個
// zone 就能正常當 dest zone 用，但該 zone 裡每一個 workload 當 source 發問時，
// 它們的 source zone 宣告都會在 identity.SourceZone 被判定不合法而丟棄 ——
// 必須跟「沒有 zone 段」一樣，整個 entry 計進 Skipped。
func TestBuildSnapshotSkipsEntriesWithNonConformingZone(t *testing.T) {
	snap, stats := BuildSnapshot([]Entry{
		{SPIFFEIDPath: "/zone/zone.a/ns/prod/sa/legacy", DNSNames: []string{"legacy.example.com"}},
		{SPIFFEIDPath: "/zone/zone-a/ns/prod/sa/payments", DNSNames: []string{"payments.example.com"}},
	})

	if _, ok := snap.Lookup("legacy.example.com."); ok {
		t.Fatal("entry with a non-conforming zone must not enter the registry")
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
