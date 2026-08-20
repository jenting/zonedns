// This file of package registry fetches registration entries from SPIRE Server.
//
// SPIRE's Entry API has no watch or stream RPC: ListEntries is a paginated unary
// call, and the one streaming RPC (SyncAuthorizedEntries) exists for an agent to
// sync the entries it is authorized for — it cannot list them all. So what this
// file implements is a poller, not a watcher.
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

// EntryLister fetches one page of registration entries.
//
// It is an interface so the polling logic — pagination, error handling, snapshot
// replacement — can be tested without gRPC.
type EntryLister interface {
	ListEntries(ctx context.Context, pageToken string) ([]Entry, string, error)
}

// pageSize is how many entries are requested from SPIRE at a time.
const pageSize = 500

// maxPollPages bounds how many pages a single PollOnce will follow.
//
// A defensive limit: no known SPIRE deployment approaches pageSize(500) *
// maxPollPages = 5,000,000 entries — SPIRE's own documentation describes test
// scales in the tens of thousands — so no legitimate registry can reach it. It
// exists to stop a misbehaving SPIRE server (one that always returns a non-empty
// NextPageToken, say) from spinning PollOnce forever: `all` would grow without
// bound, no new snapshot would ever be produced, and Run would log no error —
// looking from outside like "frozen on the last successful snapshot" while
// really being wedged and leaking memory. Exceeding the limit is an error and
// takes the existing failure path, which keeps the old snapshot.
const maxPollPages = 10000

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

	// pollErrors counts this Poller's consecutive polling failures.
	//
	// It is a field on Poller rather than a package-level variable. The current
	// deployment builds only one Poller, so the two are equivalent today, but a
	// single package-level counter would be shared by every Poller in the process:
	// a second one — polling two SPIRE Servers at once, say — would share the
	// first's counter instead of counting separately, and the meaning of
	// ConsecutivePollErrors as "consecutive failures" would stop being reliable.
	// As a field, every Poller is independent by construction, rather than the
	// problem waiting to be discovered when a second one appears.
	pollErrors atomic.Int64

	// OnSnapshot is called after each successful poll with that snapshot's Stats.
	//
	// It is Run's only channel for handing the statistics outward — to the plugin
	// layer publishing them as Prometheus gauges, for instance. PollOnce's return
	// value is visible only when a caller invokes it directly; the polling loop
	// inside Run returns nothing at all. May be nil.
	OnSnapshot func(Stats)

	// OnPollErrors is called after every poll, successful or not, with the
	// consecutive failure count as of that moment (in step with
	// ConsecutivePollErrors()).
	//
	// It is the only data source for the registry_poll_errors gauge. Unlike
	// OnSnapshot it fires on success as well as failure — failures are what raise
	// the count, successes are what reset the gauge to zero, and dropping either
	// leaves the metric stuck at an old value or pinned at 0 forever. May be
	// nil.
	OnPollErrors func(count int64)
}

// NewPoller builds a Poller.
func NewPoller(lister EntryLister, store *Store, interval time.Duration) *Poller {
	return &Poller{lister: lister, store: store, interval: interval}
}

// ConsecutivePollErrors returns this Poller's consecutive polling failures. Zero
// means the most recent poll succeeded, or that none has run yet.
//
// Spec §6.2 requires that a failed poll "keep the previous snapshot and increment
// a metric" — this method, through OnPollErrors or by the caller polling it, is
// that metric's only data source. When SPIRE becomes unreachable (an expired
// admin SVID, admin rights revoked, a network partition), the Store keeps the
// last snapshot indefinitely: registry_ready stays at 1 and registry_names stays
// at its final value, and this counter is the only signal.
func (p *Poller) ConsecutivePollErrors() int64 { return p.pollErrors.Load() }

// PollOnce fetches every entry and replaces the snapshot.
//
// On failure it does NOT touch the existing snapshot: a brief SPIRE outage must
// not make all zone routing disappear. When the very first poll fails the Store
// stays not-ready rather than becoming an empty snapshot, because "not known
// yet" and "resolvable but absent from the registry" mean different things, and
// the latter would silently drop every cross-zone query back to the ordinary
// answer.
//
// The pagination loop has two defences against a misbehaving server that never
// lets it stop: the maxPollPages page limit, and detecting the same page token
// coming back a second time. With the limit alone, a server that is stuck but
// returns the same token every time would still burn the entire budget before
// failing; the repeat check catches that immediately. Both count as errors and
// take the existing failure path, which keeps the old snapshot.
func (p *Poller) PollOnce(ctx context.Context) (Stats, error) {
	var all []Entry
	seenTokens := make(map[string]struct{})
	token := ""
	for pages := 0; ; pages++ {
		if pages >= maxPollPages {
			return Stats{}, fmt.Errorf("registry: aborting poll after %d pages, SPIRE server may be misbehaving", maxPollPages)
		}
		if token != "" {
			if _, dup := seenTokens[token]; dup {
				return Stats{}, fmt.Errorf("registry: SPIRE server returned page token %q twice, aborting poll", token)
			}
			seenTokens[token] = struct{}{}
		}

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
		stats, err := p.PollOnce(ctx)
		if err != nil {
			p.pollErrors.Add(1)
			log.Warningf("registry poll failed, keeping previous snapshot: %v", err)
		} else {
			p.pollErrors.Store(0)
			if p.OnSnapshot != nil {
				p.OnSnapshot(stats)
			}
		}
		if p.OnPollErrors != nil {
			p.OnPollErrors(p.pollErrors.Load())
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
