package registry

import (
	"context"
	"errors"
	"fmt"
	"sync"
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

// everGrowingTokenLister returns a distinct, never-repeating, never-empty
// NextPageToken forever — a misbehaving SPIRE server that just keeps paging.
// Nothing in this response shape repeats, so only the maxPollPages bound
// (not the duplicate-token check) can stop it.
type everGrowingTokenLister struct {
	mu    sync.Mutex
	calls int
}

func (l *everGrowingTokenLister) ListEntries(_ context.Context, _ string) ([]Entry, string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	return nil, fmt.Sprintf("page-%d", l.calls), nil
}

func (l *everGrowingTokenLister) callCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

// TestPollOnceBoundsRunawayPagination checks that a SPIRE server always
// returning a non-empty and always different NextPageToken cannot spin PollOnce
// forever: it must return an error within maxPollPages calls, and must not touch
// the existing snapshot.
func TestPollOnceBoundsRunawayPagination(t *testing.T) {
	good := &fakeLister{pages: [][]Entry{
		{{SPIFFEIDPath: "/zone/zone-a/ns/prod/sa/payments", DNSNames: []string{"payments.example.com"}}},
	}}
	store := NewStore()
	p := NewPoller(good, store, time.Minute)
	if _, err := p.PollOnce(context.Background()); err != nil {
		t.Fatalf("seeding poll: %v", err)
	}

	runaway := &everGrowingTokenLister{}
	p.lister = runaway

	if _, err := p.PollOnce(context.Background()); err == nil {
		t.Fatal("expected error from a poll that never terminates pagination")
	}
	if got := runaway.callCount(); got != maxPollPages {
		t.Fatalf("calls = %d, want exactly maxPollPages (%d) — the page-count bound did not fire as expected", got, maxPollPages)
	}

	zone, ok := store.Lookup("payments.example.com.")
	if !ok || zone != "zone-a" {
		t.Fatalf("previous snapshot was lost: (%q,%v)", zone, ok)
	}
}

// repeatedTokenLister always hands back the exact same non-empty
// NextPageToken — a SPIRE server that is stuck rather than merely slow.
type repeatedTokenLister struct {
	mu    sync.Mutex
	calls int
}

func (l *repeatedTokenLister) ListEntries(_ context.Context, _ string) ([]Entry, string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	return nil, "stuck-token", nil
}

func (l *repeatedTokenLister) callCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

// TestPollOnceDetectsRepeatedPageToken checks that a SPIRE server returning the
// same page token twice is treated as an error at once, rather than failing only
// after the maxPollPages budget is exhausted.
func TestPollOnceDetectsRepeatedPageToken(t *testing.T) {
	good := &fakeLister{pages: [][]Entry{
		{{SPIFFEIDPath: "/zone/zone-a/ns/prod/sa/payments", DNSNames: []string{"payments.example.com"}}},
	}}
	store := NewStore()
	p := NewPoller(good, store, time.Minute)
	if _, err := p.PollOnce(context.Background()); err != nil {
		t.Fatalf("seeding poll: %v", err)
	}

	stuck := &repeatedTokenLister{}
	p.lister = stuck

	if _, err := p.PollOnce(context.Background()); err == nil {
		t.Fatal("expected error from a poll whose page token repeats")
	}
	// The token is seen as "already used" on the call after it was first
	// returned, so this must fail in a small, fixed number of calls — far
	// short of maxPollPages — proving detection fired, not the page bound.
	if got := stuck.callCount(); got == 0 || got >= maxPollPages {
		t.Fatalf("calls = %d, want a small fixed count well under maxPollPages (%d)", got, maxPollPages)
	}

	zone, ok := store.Lookup("payments.example.com.")
	if !ok || zone != "zone-a" {
		t.Fatalf("previous snapshot was lost: (%q,%v)", zone, ok)
	}
}

// flakyLister fails the first failUntil calls, then succeeds forever after.
type flakyLister struct {
	mu        sync.Mutex
	calls     int
	failUntil int
}

func (l *flakyLister) ListEntries(_ context.Context, _ string) ([]Entry, string, error) {
	l.mu.Lock()
	l.calls++
	call := l.calls
	l.mu.Unlock()

	if call <= l.failUntil {
		return nil, "", errors.New("spire unavailable")
	}
	return []Entry{{SPIFFEIDPath: "/zone/zone-a/ns/prod/sa/svc", DNSNames: []string{"svc.example.com"}}}, "", nil
}

// TestRunTracksConsecutivePollErrors checks that Run raises pollErrors on a
// failed poll and resets it on the next success. ConsecutivePollErrors is the
// plugin layer's only source for that metric, and this path previously had no
// test coverage at all.
func TestRunTracksConsecutivePollErrors(t *testing.T) {
	lister := &flakyLister{failUntil: 3}
	p := NewPoller(lister, NewStore(), 2*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()

	var sawFailure, sawReset bool
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if n := p.ConsecutivePollErrors(); n > 0 {
			sawFailure = true
		} else if sawFailure {
			sawReset = true
			break
		}
		time.Sleep(time.Millisecond)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return after context cancellation")
	}

	if !sawFailure {
		t.Fatal("expected ConsecutivePollErrors() to become > 0 after a failing poll")
	}
	if !sawReset {
		t.Fatal("expected ConsecutivePollErrors() to reset to 0 after a subsequent successful poll")
	}
}

// pollErrors is a field on each Poller, not one package-level counter — two
// Pollers failing separately must not affect each other's consecutive failure
// counts. This is the only test that proves they really are independent after
// pollErrors moved from a package variable to a field; moving it back would make
// this test fail.
func TestPollErrorsAreIndependentPerPoller(t *testing.T) {
	// pollErrors is only ever mutated inside Run's loop (PollOnce itself is
	// I/O-free and side-effect-free with respect to the counter), so this
	// drives each Poller through Run rather than calling PollOnce directly.
	failing := &fakeLister{err: errors.New("spire unavailable")}
	ok := &fakeLister{pages: [][]Entry{
		{{SPIFFEIDPath: "/zone/zone-a/ns/prod/sa/payments", DNSNames: []string{"payments.example.com"}}},
	}}

	pFail := NewPoller(failing, NewStore(), time.Hour) // long interval: Run's immediate first poll is all that runs
	pOK := NewPoller(ok, NewStore(), time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	doneFail := make(chan struct{})
	doneOK := make(chan struct{})
	go func() { pFail.Run(ctx); close(doneFail) }()
	go func() { pOK.Run(ctx); close(doneOK) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && pFail.ConsecutivePollErrors() == 0 {
		time.Sleep(time.Millisecond)
	}

	if n := pFail.ConsecutivePollErrors(); n != 1 {
		t.Fatalf("pFail.ConsecutivePollErrors() = %d, want 1", n)
	}
	if n := pOK.ConsecutivePollErrors(); n != 0 {
		t.Fatalf("pOK.ConsecutivePollErrors() = %d, want 0 — a failure on another Poller must not leak into this one", n)
	}

	cancel()
	for _, done := range []chan struct{}{doneFail, doneOK} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("Run did not return after context cancellation")
		}
	}
}

// OnPollErrors is the only data source for the registry_poll_errors gauge: it
// must fire on success as well as failure — resetting to zero on success, raising
// the count on failure — and firing in only one of those cases would leave the
// gauge stuck at an old value.
func TestRunCallsOnPollErrorsOnBothOutcomes(t *testing.T) {
	lister := &flakyLister{failUntil: 2}
	p := NewPoller(lister, NewStore(), 2*time.Millisecond)

	var mu sync.Mutex
	var saw []int64
	p.OnPollErrors = func(count int64) {
		mu.Lock()
		saw = append(saw, count)
		mu.Unlock()
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(saw)
		mu.Unlock()
		if n >= 4 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return after context cancellation")
	}

	mu.Lock()
	defer mu.Unlock()
	var sawPositive, sawZero bool
	for _, n := range saw {
		if n > 0 {
			sawPositive = true
		} else {
			sawZero = true
		}
	}
	if !sawPositive {
		t.Fatalf("OnPollErrors never reported a positive count: %v", saw)
	}
	if !sawZero {
		t.Fatalf("OnPollErrors never reported 0 after recovery: %v", saw)
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
