// Package decision implements zonedns's core decision logic (spec §6.4).
//
// Deliberately a pure function with no I/O: the caller looks up all external
// state and passes it in. That lets the decision table be tested exhaustively,
// and keeps "what to do in which situation" in one place rather than scattered
// through ServeDNS.
package decision

import "net/netip"

// Action is the action a decision calls for.
type Action int

const (
	// ActionPassThrough hands the query to the next plugin in the chain.
	ActionPassThrough Action = iota
	// ActionAnswerGateway answers directly with the zone gateway VIP.
	ActionAnswerGateway
	// ActionServFail returns SERVFAIL.
	ActionServFail
)

func (a Action) String() string {
	switch a {
	case ActionPassThrough:
		return "passthrough"
	case ActionAnswerGateway:
		return "gateway"
	case ActionServFail:
		return "servfail"
	default:
		return "unknown"
	}
}

// Input is everything needed to make a decision.
type Input struct {
	SourceZone string
	SourceOK   bool // whether a trustworthy source zone was obtained
	DestZone   string
	DestOK     bool // whether the FQDN is present in the registry
}

// Decision is the result. Gateway is meaningful only when Action is
// ActionAnswerGateway.
type Decision struct {
	Action  Action
	Gateway netip.Addr
}

// Decide implements the decision table in spec §6.4.
//
// gateway looks up the gateway VIP for a zone (normally
// zonetable.Table.Gateway).
func Decide(in Input, gateway func(string) (netip.Addr, bool)) Decision {
	// Source zone unknown — this is the ordinary non-zone-aware path, not an error.
	if !in.SourceOK {
		return Decision{Action: ActionPassThrough}
	}
	// This name is not ours to handle (an external domain, say).
	if !in.DestOK {
		return Decision{Action: ActionPassThrough}
	}
	// Same zone — let downstream return the ordinary answer. The gateway table
	// is deliberately not consulted: a same-zone lookup needs no gateway at all,
	// and consulting it would make a zone with no configured gateway SERVFAIL
	// when its own workloads talk to each other.
	if in.DestZone == in.SourceZone {
		return Decision{Action: ActionPassThrough}
	}
	// Cross-zone — a gateway must be configured.
	gw, ok := gateway(in.DestZone)
	if !ok {
		// The registry says this zone exists but the config file has no gateway
		// for it. That is a missing configuration, and silently returning the
		// ordinary answer would break zone isolation without a sound — so this
		// path deliberately does not fail open.
		return Decision{Action: ActionServFail}
	}
	return Decision{Action: ActionAnswerGateway, Gateway: gw}
}
