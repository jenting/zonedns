package drift

import (
	"reflect"
	"testing"
)

func TestCompareReportsHostsNoPodClaims(t *testing.T) {
	// The dangerous direction: a VirtualService sends clients to
	// payments.example.com, but no pod claims that name via zonedns.io/host, so
	// the central registry has no entry for it and the service never gets zone
	// routing — while queries keep succeeding and nobody notices.
	got := Compare(
		[]string{"payments.example.com", "orders.example.com"},
		[]string{"orders.example.com"},
	)
	if want := []string{"payments.example.com"}; !reflect.DeepEqual(got.UnclaimedHosts, want) {
		t.Errorf("UnclaimedHosts = %v, want %v", got.UnclaimedHosts, want)
	}
	if len(got.UnroutedLabels) != 0 {
		t.Errorf("UnroutedLabels = %v, want empty", got.UnroutedLabels)
	}
	if got.OK() {
		t.Error("OK() = true, want false when a VirtualService host is unclaimed")
	}
}

func TestCompareReportsLabelsNoVirtualServiceDeclares(t *testing.T) {
	got := Compare(
		[]string{"orders.example.com"},
		[]string{"orders.example.com", "paymnets.example.com"}, // typo
	)
	if want := []string{"paymnets.example.com"}; !reflect.DeepEqual(got.UnroutedLabels, want) {
		t.Errorf("UnroutedLabels = %v, want %v", got.UnroutedLabels, want)
	}
	if len(got.UnclaimedHosts) != 0 {
		t.Errorf("UnclaimedHosts = %v, want empty", got.UnclaimedHosts)
	}
	if got.OK() {
		t.Error("OK() = true, want false when a label is unrouted")
	}
}

func TestCompareBothDirectionsAtOnce(t *testing.T) {
	// The most typical drift: somebody renamed the VirtualService and forgot the
	// pod label. One rename trips both directions at once — nobody claims the new
	// name, and nobody queries the old one.
	got := Compare(
		[]string{"payments-v2.example.com"},
		[]string{"payments.example.com"},
	)
	if want := []string{"payments-v2.example.com"}; !reflect.DeepEqual(got.UnclaimedHosts, want) {
		t.Errorf("UnclaimedHosts = %v, want %v", got.UnclaimedHosts, want)
	}
	if want := []string{"payments.example.com"}; !reflect.DeepEqual(got.UnroutedLabels, want) {
		t.Errorf("UnroutedLabels = %v, want %v", got.UnroutedLabels, want)
	}
}

func TestCompareMatchedIsClean(t *testing.T) {
	got := Compare(
		[]string{"payments.example.com", "orders.example.com"},
		[]string{"orders.example.com", "payments.example.com"},
	)
	if !got.OK() {
		t.Errorf("OK() = false, want true; report = %+v", got)
	}
}

func TestCompareDeduplicates(t *testing.T) {
	// Several VirtualServices may declare the same host, and several pods
	// (replicas of one Deployment) necessarily carry the same label. Duplication
	// is not drift and must not appear twice in the report.
	got := Compare(
		[]string{"payments.example.com", "payments.example.com"},
		[]string{"orders.example.com", "orders.example.com"},
	)
	if want := []string{"payments.example.com"}; !reflect.DeepEqual(got.UnclaimedHosts, want) {
		t.Errorf("UnclaimedHosts = %v, want %v", got.UnclaimedHosts, want)
	}
	if want := []string{"orders.example.com"}; !reflect.DeepEqual(got.UnroutedLabels, want) {
		t.Errorf("UnroutedLabels = %v, want %v", got.UnroutedLabels, want)
	}
}

func TestCompareIgnoresEmptyStrings(t *testing.T) {
	// A label value may be the empty string (zonedns.io/host: ""). That is not a
	// name and must not be reported as drift.
	got := Compare([]string{""}, []string{""})
	if !got.OK() {
		t.Errorf("OK() = false, want true; report = %+v", got)
	}
}

func TestCompareEmptyInputsAreClean(t *testing.T) {
	if got := Compare(nil, nil); !got.OK() {
		t.Errorf("OK() = false, want true; report = %+v", got)
	}
}

func TestReportIsSorted(t *testing.T) {
	// This tool runs in CI, so its output must diff cleanly — map iteration order
	// must not leak into it.
	got := Compare([]string{"c.example.com", "a.example.com", "b.example.com"}, nil)
	want := []string{"a.example.com", "b.example.com", "c.example.com"}
	if !reflect.DeepEqual(got.UnclaimedHosts, want) {
		t.Errorf("UnclaimedHosts = %v, want %v", got.UnclaimedHosts, want)
	}
}
