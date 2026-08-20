package decision

import (
	"net/netip"
	"testing"
)

var gwA = netip.MustParseAddr("203.0.113.10")

// gateways stands in for zonetable: only zone-a has a gateway configured.
func gateways(zone string) (netip.Addr, bool) {
	if zone == "zone-a" {
		return gwA, true
	}
	return netip.Addr{}, false
}

func TestDecideTable(t *testing.T) {
	tests := []struct {
		name string
		in   Input
		want Decision
	}{
		{
			"same zone passes through",
			Input{SourceZone: "zone-a", SourceOK: true, DestZone: "zone-a", DestOK: true},
			Decision{Action: ActionPassThrough},
		},
		{
			"cross zone answers gateway",
			Input{SourceZone: "zone-b", SourceOK: true, DestZone: "zone-a", DestOK: true},
			Decision{Action: ActionAnswerGateway, Gateway: gwA},
		},
		{
			"dest not in registry passes through",
			Input{SourceZone: "zone-b", SourceOK: true, DestOK: false},
			Decision{Action: ActionPassThrough},
		},
		{
			"cross zone without gateway config servfails",
			Input{SourceZone: "zone-a", SourceOK: true, DestZone: "zone-z", DestOK: true},
			Decision{Action: ActionServFail},
		},
		{
			"unknown source passes through even when dest is known",
			Input{SourceOK: false, DestZone: "zone-a", DestOK: true},
			Decision{Action: ActionPassThrough},
		},
		{
			"unknown source passes through when dest unknown too",
			Input{SourceOK: false, DestOK: false},
			Decision{Action: ActionPassThrough},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Decide(tt.in, gateways)
			if got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

// Action.String() produces the action label value of the decision_total
// Prometheus metric. Reordering the iota would rename the metric without anyone
// noticing, and would quietly disable the action="servfail" alert required by
// docs/deployment.md — the only alert that catches "a zone has no gateway
// configured". Every constant's string is pinned individually, plus an
// out-of-range value to pin the default branch. internal/identity already has
// this test for Reason.String(); this is the missing half.
func TestActionString(t *testing.T) {
	cases := []struct {
		action Action
		want   string
	}{
		{ActionPassThrough, "passthrough"},
		{ActionAnswerGateway, "gateway"},
		{ActionServFail, "servfail"},
		{Action(999), "unknown"},
	}
	for _, c := range cases {
		if got := c.action.String(); got != c.want {
			t.Fatalf("Action(%d).String() = %q, want %q", c.action, got, c.want)
		}
	}
}

// The same-zone path must not consult the gateway table — if it did, a zone
// with no configured gateway would wrongly SERVFAIL.
func TestSameZoneDoesNotConsultGatewayTable(t *testing.T) {
	called := false
	gw := func(string) (netip.Addr, bool) {
		called = true
		return netip.Addr{}, false
	}
	in := Input{SourceZone: "zone-z", SourceOK: true, DestZone: "zone-z", DestOK: true}
	if got := Decide(in, gw); got.Action != ActionPassThrough {
		t.Fatalf("got %v, want ActionPassThrough", got.Action)
	}
	if called {
		t.Fatal("gateway table consulted on the same-zone path")
	}
}
