package testcerts

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"
)

// CA 是拋棄式的憑證頒發機構，用來簽發能完成真實 TLS 握手的憑證。
//
// 為什麼不能用 New：它回傳的是自簽的 *x509.Certificate，沒有私鑰。那對「手工
// 組一個 tls.ConnectionState 再餵給程式」的單元測試夠用，但真實握手需要成對的
// 憑證與金鑰，而且雙方必須鏈到同一個信任根 —— 否則驗證的是憑證鏈以外的東西。
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

// NewCA 建立一個新的拋棄式 CA。
func NewCA(t *testing.T) *CA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("testcerts: generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "testcerts-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("testcerts: create CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("testcerts: parse CA certificate: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &CA{cert: cert, key: key, pool: pool}
}

// Pool 回傳只信任這個 CA 的憑證池，供 tls.Config 的 RootCAs／ClientCAs 使用。
func (ca *CA) Pool() *x509.CertPool { return ca.pool }

// Issue 簽發一張帶指定 SPIFFE ID 作為 URI SAN 的葉憑證。
//
// 同時設定 serverAuth 與 clientAuth，因為 SPIFFE 的 SVID 本來就兩用 —— 同一張
// 憑證在一個連線上當 client、在另一個連線上當 server。
func (ca *CA) Issue(t *testing.T, spiffeID string) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("testcerts: generate leaf key: %v", err)
	}
	u, err := url.Parse(spiffeID)
	if err != nil {
		t.Fatalf("testcerts: parse spiffe id %q: %v", spiffeID, err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: spiffeID},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{u},
		// 讓 httptest 起的伺服器能以 127.0.0.1/localhost 被驗證。
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("testcerts: sign leaf certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("testcerts: parse leaf certificate: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}
}
