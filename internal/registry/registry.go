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

	"github.com/jenting/zonedns/internal/ednszone"
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
	Skipped   int // entries skipped: no zone segment in the SPIFFE ID, or a zone string ednszone.Valid rejects
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
		// ednszone.Valid is the same character-set rule identity.SourceZone uses to
		// validate the source zone an agent declares (see ednszone.Get). Letting a
		// zone through here that breaks that rule — "zone.a", say, which a
		// Kubernetes label value permits but ednszone.Valid rejects — would leave
		// it perfectly resolvable in both the gateway table and this registry, and
		// perfectly usable as a dest zone. But every workload inside that zone, when
		// it asks as a source, would have its agent's source zone declaration judged
		// invalid by ednszone.Get and discarded (ReasonNoDeclaration) — so those
		// workloads would forever receive zone-blind answers, with no alert. Both
		// sides must therefore validate identically, and a non-conforming zone is
		// treated exactly like a missing zone segment: counted in Skipped rather
		// than placed in the queryable snapshot.
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
