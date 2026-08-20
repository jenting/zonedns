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
