// Package identity is zonedns's trust boundary (spec §6.1).
//
// Whether the whole of zone isolation can be bypassed depends on nothing but
// this package being correct. Any change must come with a review of whether the
// tests here still cover the corresponding attack.
package identity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/miekg/dns"
)

// PeerCertificates returns the client certificate chain for this query.
//
// The two transports differ in how it is obtained:
//
//   - DoH: CoreDNS's HTTPS server puts the *http.Request into the context. It is
//     taken from the context rather than by type-asserting the writer — an
//     upstream plugin (metrics, for one) may have wrapped the ResponseWriter, in
//     which case the assertion fails, and it fails by quietly returning false.
//     Zone verification would be entirely disabled without a single error.
//
//   - DoT: the writer implements dns.ConnectionStater.
//
//     This path is not robust against ResponseWriter wrapping. CoreDNS's metrics
//     plugin wraps the writer in a Recorder that stores dns.ResponseWriter as an
//     interface field, at which point the `w.(dns.ConnectionStater)` assertion
//     fails — and the result is not an error but a quiet fall through to "no
//     certificate", switching off zone verification for DoT queries with no
//     alert whatsoever. The DoH branch deliberately reads the *http.Request from
//     the context precisely so that wrapping cannot affect it. Forcing this
//     plugin to sort ahead of metrics would fix DoT, but CoreDNS's own request
//     metrics would then never see cross-zone responses again — a poor trade for
//     a transport we do not deploy. The conclusion: a zone-aware listener must be
//     DoH and must not rely on this DoT path.
//
// Returns ok=false when there is no TLS, or TLS but no certificate presented.
// The caller must treat that as the ordinary non-zone-aware path, not an
// error.
func PeerCertificates(ctx context.Context, w dns.ResponseWriter) ([]*x509.Certificate, bool) {
	if req, isDoH := ctx.Value(dnsserver.HTTPRequestKey{}).(*http.Request); isDoH && req != nil {
		return certsFromState(req.TLS)
	}
	if cs, isDoT := w.(dns.ConnectionStater); isDoT {
		return certsFromState(cs.ConnectionState())
	}
	return nil, false
}

func certsFromState(st *tls.ConnectionState) ([]*x509.Certificate, bool) {
	if st == nil || len(st.PeerCertificates) == 0 {
		return nil, false
	}
	return st.PeerCertificates, true
}

// SPIFFEIDFromCert returns the certificate's SPIFFE ID (its URI SAN).
//
// There must be exactly one URI SAN and its scheme must be spiffe; anything else
// returns ok=false.
//
// crypto/tls's chain verification checks neither the number of URI SANs nor
// their scheme, and SourceZone deliberately does not re-verify the chain (see
// the package doc), so this is the only place enforcing the SPIFFE
// specification's invariant that a SPIFFE certificate carries exactly one URI
// SAN. SAN order is chosen by whoever holds the certificate, possibly an
// attacker: if several URI SANs were allowed and the first with a spiffe scheme
// were taken as the identity, an attacker holding a certificate that carries
// both an authorized SPIFFE ID and their own could impersonate the authorized
// agent simply by ordering the authorized one first. So more than one URI SAN is
// refused outright, with no attempt to pick the "most plausible" one — ambiguity
// must fail closed.
func SPIFFEIDFromCert(cert *x509.Certificate) (string, bool) {
	if len(cert.URIs) != 1 {
		return "", false
	}
	u := cert.URIs[0]
	if u == nil || u.Scheme != "spiffe" {
		return "", false
	}
	return u.String(), true
}
