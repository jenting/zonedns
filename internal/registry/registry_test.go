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

// A Kubernetes label value permits a dot, but ednszone.Valid — the same rule
// identity uses to validate the source zone an agent declares — rejects it. Were
// such an entry placed in the queryable snapshot, the zone would work perfectly
// as a dest zone, while every workload inside it asking as a source would have
// its declaration judged invalid by identity.SourceZone and discarded. The whole
// entry must therefore be counted in Skipped, exactly like a missing zone
// segment.
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
