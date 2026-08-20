// Package ednszone defines the wire format that carries the source zone between
// the agent and central.
//
// This is the only compatibility interface between the two subprojects (spec
// §6.6): the agent writes with Set, central reads with Get. Encoding and
// decoding deliberately live in one package and are tested together, so that
// neither end can change the format on its own.
//
// EDNS0 rather than EDNS Client Subnet: ECS means a network prefix, not an
// identity, and intermediate resolvers rewrite it per RFC 7871. An option code
// from the local/experimental range: IANA reserves that range (65001-65534) for
// private use, so it cannot collide with a standard option.
package ednszone

import (
	"github.com/miekg/dns"
)

// DefaultCode is the default EDNS0 option code, taken from IANA's
// local/experimental range.
const DefaultCode uint16 = 65001

// MaxLen bounds the length of a zone string, matching the limit on a Kubernetes
// label value.
const MaxLen = 63

// Valid reports whether a zone string is well formed.
//
// The decoding side runs this check too: even when the declaration comes from a
// verified agent, the string itself is external input and must not go straight
// into a map lookup or a log line.
func Valid(zone string) bool {
	if zone == "" || len(zone) > MaxLen {
		return false
	}
	for i := 0; i < len(zone); i++ {
		c := zone[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '_':
		default:
			return false
		}
	}
	return true
}

// Set writes the source zone onto a message, creating an OPT record if needed.
//
// An existing OPT record is preserved along with its UDP size and DO bit, and an
// older option with the same code is replaced rather than appended — otherwise a
// retry or forwarding path could accumulate several declarations that contradict
// each other.
func Set(m *dns.Msg, code uint16, zone string) {
	opt := m.IsEdns0()
	if opt == nil {
		m.SetEdns0(dns.DefaultMsgSize, false)
		opt = m.IsEdns0()
	}

	kept := opt.Option[:0]
	for _, o := range opt.Option {
		if l, isLocal := o.(*dns.EDNS0_LOCAL); isLocal && l.Code == code {
			continue
		}
		kept = append(kept, o)
	}
	opt.Option = append(kept, &dns.EDNS0_LOCAL{Code: code, Data: []byte(zone)})
}

// Get reads the source zone. An invalid zone returns ok=false, handled the same
// way as one that is absent.
//
// Two or more options carrying the same code also return ok=false, even when one
// of them is well formed. Set prevents a single caller from stacking them up,
// but central parses bytes off the wire, and a packet from a malicious or buggy
// agent is not protected by Set. Picking one of them (taking the first, say)
// would accept a declaration an attacker may have inserted in place of another —
// the same reasoning that makes SPIFFEIDFromCert refuse certificates with
// several URI SANs: ambiguity must fail closed, with no attempt to pick the
// "most plausible" one.
func Get(m *dns.Msg, code uint16) (string, bool) {
	opt := m.IsEdns0()
	if opt == nil {
		return "", false
	}
	var zone string
	matches := 0
	for _, o := range opt.Option {
		l, isLocal := o.(*dns.EDNS0_LOCAL)
		if !isLocal || l.Code != code {
			continue
		}
		matches++
		if matches > 1 {
			return "", false
		}
		zone = string(l.Data)
	}
	if matches != 1 || !Valid(zone) {
		return "", false
	}
	return zone, true
}
