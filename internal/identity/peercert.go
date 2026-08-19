// Package identity 是 zonedns 的信任邊界（spec §6.1）。
//
// 整套 zone 隔離是否可被繞過，只取決於這個套件是否正確。任何修改都必須連帶檢視
// 這裡的測試是否仍然涵蓋對應的攻擊情境。
package identity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/miekg/dns"
)

// PeerCertificates 取出這次查詢的 client certificate 鏈。
//
// 兩種傳輸的取法不同：
//
//   - DoH：CoreDNS 的 HTTPS server 會把 *http.Request 放進 context。從 context 取
//     而不是對 writer 做型別斷言 — 上游 plugin（例如 metrics）可能包裝過
//     ResponseWriter，型別斷言會失敗，而失敗的方式是「安靜地回 false」，
//     結果是 zone 驗證整個失效卻沒有任何錯誤。
//   - DoT：writer 實作 dns.ConnectionStater。
//
// 沒有 TLS、或有 TLS 但對方沒有出示憑證時回 ok=false。呼叫端必須把這個情況當成
// 「非 zone-aware 的正常路徑」，而不是錯誤。
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

// SPIFFEIDFromCert 取出憑證的 SPIFFE ID（URI SAN）。
//
// 只接受 spiffe scheme：憑證可以帶任意 URI SAN，若不檢查 scheme，一張帶著
// https:// URI 的憑證就能冒充成身分來源。
func SPIFFEIDFromCert(cert *x509.Certificate) (string, bool) {
	for _, u := range cert.URIs {
		if u != nil && u.Scheme == "spiffe" {
			return u.String(), true
		}
	}
	return "", false
}
