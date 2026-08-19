// Package testcerts generates throwaway certificates for tests.
//
// It is imported only from _test.go files across the module (identity,
// and later tasks that need the same generator), so it never reaches the
// plugin binary despite importing "testing" from a non-test file.
package testcerts

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"
)

// New generates a certificate with the given URI SANs.
//
// Variadic so every existing single-argument call site (including
// New(t, "") for "no URI SAN") keeps compiling unchanged, while callers
// that need to test multi-SAN certificates can pass more than one URI:
// New(t, uri1, uri2). Empty-string arguments are skipped rather than
// turned into a SAN, preserving the historical "" == no SAN meaning.
func New(t *testing.T, uris ...string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	for _, uri := range uris {
		if uri == "" {
			continue
		}
		u, err := url.Parse(uri)
		if err != nil {
			t.Fatalf("parse uri %q: %v", uri, err)
		}
		tmpl.URIs = append(tmpl.URIs, u)
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}
