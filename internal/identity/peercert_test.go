package identity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"testing"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/jenting/zonedns/internal/testcerts"
	"github.com/miekg/dns"
)

// plainWriter simulates an ordinary (non-TLS) ResponseWriter.
type plainWriter struct{ dns.ResponseWriter }

// dotWriter simulates a DoT ResponseWriter, implementing dns.ConnectionStater.
type dotWriter struct {
	dns.ResponseWriter
	state *tls.ConnectionState
}

func (w *dotWriter) ConnectionState() *tls.ConnectionState { return w.state }

func TestPeerCertificatesFromDoT(t *testing.T) {
	cert := testcerts.New(t, "spiffe://example.org/node/n1")
	w := &dotWriter{state: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}}

	got, ok := PeerCertificates(context.Background(), w)
	if !ok {
		t.Fatal("ok = false, want true")
	}
	if len(got) != 1 || !got[0].Equal(cert) {
		t.Fatal("returned certificate does not match")
	}
}

func TestPeerCertificatesFromDoH(t *testing.T) {
	cert := testcerts.New(t, "spiffe://example.org/node/n1")
	req := &http.Request{TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}}
	// CoreDNS's DoH server puts the *http.Request into the context (server_https.go).
	// We read it from the context rather than type-asserting the writer, so that
	// upstream plugins wrapping the ResponseWriter don't break this lookup.
	ctx := context.WithValue(context.Background(), dnsserver.HTTPRequestKey{}, req)

	got, ok := PeerCertificates(ctx, &plainWriter{})
	if !ok {
		t.Fatal("ok = false, want true")
	}
	if len(got) != 1 || !got[0].Equal(cert) {
		t.Fatal("returned certificate does not match")
	}
}

func TestPeerCertificatesNoTLS(t *testing.T) {
	if _, ok := PeerCertificates(context.Background(), &plainWriter{}); ok {
		t.Fatal("plain UDP/TCP connection must not yield certificates")
	}
}

func TestPeerCertificatesTLSWithoutClientCert(t *testing.T) {
	w := &dotWriter{state: &tls.ConnectionState{}} // TLS present but no client cert
	if _, ok := PeerCertificates(context.Background(), w); ok {
		t.Fatal("TLS without a client certificate must yield ok=false")
	}

	req := &http.Request{TLS: &tls.ConnectionState{}}
	ctx := context.WithValue(context.Background(), dnsserver.HTTPRequestKey{}, req)
	if _, ok := PeerCertificates(ctx, &plainWriter{}); ok {
		t.Fatal("DoH without a client certificate must yield ok=false")
	}
}

func TestPeerCertificatesPlainHTTPRequest(t *testing.T) {
	req := &http.Request{} // plain HTTP has no TLS
	ctx := context.WithValue(context.Background(), dnsserver.HTTPRequestKey{}, req)
	if _, ok := PeerCertificates(ctx, &plainWriter{}); ok {
		t.Fatal("non-TLS HTTP request must yield ok=false")
	}
}

func TestSPIFFEIDFromCert(t *testing.T) {
	cert := testcerts.New(t, "spiffe://example.org/node/n1")
	got, ok := SPIFFEIDFromCert(cert)
	if !ok {
		t.Fatal("ok = false, want true")
	}
	if got != "spiffe://example.org/node/n1" {
		t.Fatalf("got %q", got)
	}
}

func TestSPIFFEIDFromCertRejectsNonSPIFFE(t *testing.T) {
	if _, ok := SPIFFEIDFromCert(testcerts.New(t, "https://example.org/node/n1")); ok {
		t.Fatal("non-spiffe URI SAN must be rejected")
	}
	if _, ok := SPIFFEIDFromCert(testcerts.New(t, "")); ok {
		t.Fatal("certificate without URI SAN must be rejected")
	}
}
