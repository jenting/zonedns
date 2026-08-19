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
