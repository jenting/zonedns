package identity

import (
	"context"

	"github.com/jenting/zonedns/internal/ednszone"
	"github.com/miekg/dns"
)

// Reason explains why SourceZone did (or did not) produce a result. Callers use
// it as a metric label.
type Reason int

const (
	// ReasonOK: a trustworthy source zone was obtained.
	ReasonOK Reason = iota
	// ReasonNoTLS: the connection carries no client certificate — the ordinary
	// non-zone-aware path.
	ReasonNoTLS
	// ReasonUnauthorizedAgent: the certificate is valid but absent from the
	// authorized list. This is an attack signal and must be alerted on.
	ReasonUnauthorizedAgent
	// ReasonNoDeclaration: the agent is authorized but carried no declaration, or
	// declared an invalid zone.
	ReasonNoDeclaration
)

func (r Reason) String() string {
	switch r {
	case ReasonOK:
		return "ok"
	case ReasonNoTLS:
		return "no_tls"
	case ReasonUnauthorizedAgent:
		return "unauthorized_agent"
	case ReasonNoDeclaration:
		return "no_declaration"
	default:
		return "unknown"
	}
}

// Config configures the trust boundary.
type Config struct {
	authorized map[string]struct{}
	code       uint16
}

// NewConfig builds a Config.
//
// An empty agents list means "no agent is authorized", not "let everyone
// through" — a missing configuration must deny rather than open up.
func NewConfig(agents []string, code uint16) Config {
	set := make(map[string]struct{}, len(agents))
	for _, a := range agents {
		set[a] = struct{}{}
	}
	return Config{authorized: set, code: code}
}

// SourceZone obtains a trustworthy source zone for this query, implementing the
// five steps of spec §6.1.
//
// The order of the steps must not be rearranged — in particular, the agent is
// confirmed authorized before the EDNS0 declaration is read. Reading it earlier
// would let an unauthorized party's declaration flow into the logic that
// follows.
func (c Config) SourceZone(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (string, Reason) {
	// Steps 1 and 2: obtain the client certificate. The chain itself has already
	// been verified by the TLS layer against the SPIRE trust bundle, so it is not
	// verified again here.
	certs, ok := PeerCertificates(ctx, w)
	if !ok {
		return "", ReasonNoTLS
	}

	// Step 3: look only at the leaf. Whatever identity an intermediate carries has
	// nothing to do with the caller.
	id, ok := SPIFFEIDFromCert(certs[0])
	if !ok {
		return "", ReasonUnauthorizedAgent
	}
	if _, authorized := c.authorized[id]; !authorized {
		return "", ReasonUnauthorizedAgent
	}

	// Steps 4 and 5: read the declaration only once authorization passes.
	// ednszone.Get validates the format and returns false when it is invalid.
	zone, ok := ednszone.Get(r, c.code)
	if !ok {
		return "", ReasonNoDeclaration
	}
	return zone, ReasonOK
}
