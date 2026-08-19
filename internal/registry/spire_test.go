package registry

import (
	"context"
	"errors"
	"fmt"
	"sync"
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

// TestPollOnceBoundsRunawayPagination 驗證一個永遠回傳非空、且每次都不同的
// NextPageToken 的 SPIRE server 不會讓 PollOnce 無限迴圈：它必須在 maxPollPages
// 次呼叫內回傳錯誤，並且不能動到既有快照。
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

// TestPollOnceDetectsRepeatedPageToken 驗證一個回傳同一個 page token 兩次的
// SPIRE server 會被立刻視為錯誤，而不是把 maxPollPages 的預算耗完才失敗。
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

// TestRunTracksConsecutivePollErrors 驗證 Run 會在輪詢失敗時把 pollErrors 往上加，
// 並在下一次成功時歸零 —— ConsecutivePollErrors 是 plugin 層要發布成 metric 的
// 唯一來源，這條路徑之前完全沒有測試覆蓋。
func TestRunTracksConsecutivePollErrors(t *testing.T) {
	lister := &flakyLister{failUntil: 3}
	p := NewPoller(lister, NewStore(), 2*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()

	var sawFailure, sawReset bool
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if n := ConsecutivePollErrors(); n > 0 {
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
