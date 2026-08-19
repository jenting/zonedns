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
//     這條路徑對 ResponseWriter 包裝不健壯：CoreDNS 的 metrics plugin 會用一個
//     把 dns.ResponseWriter 存成 interface 欄位的 Recorder 包住 writer，此時
//     `w.(dns.ConnectionStater)` 斷言失敗 —— 結果不是報錯，而是安靜地落到
//     「沒有憑證」，DoT 查詢的 zone 驗證就這樣被關掉而不會有任何告警。DoH 分支
//     刻意改成從 context 讀 *http.Request，正是為了不受這種包裝影響。我們刻意
//     不強迫本 plugin 排到 metrics 之前去修這件事 —— 那樣做雖然能修好 DoT，卻
//     會讓 CoreDNS 自己的 request metrics 再也看不到跨 zone 的回應，對一個我們
//     根本沒有部署的傳輸方式來說不划算。結論：zone-aware listener 必須用 DoH，
//     不能依賴 DoT 這條路徑。
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
// 必須「恰好一個」URI SAN，且其 scheme 為 spiffe，否則回 ok=false。
//
// crypto/tls 的鏈驗證不檢查 URI SAN 的數量或 scheme，而 SourceZone 刻意不重
// 驗證鏈（見套件說明），所以「SPIFFE 憑證只能有一個 URI SAN」這個 SPIFFE 規範
// 要求的不變量，這裡就是唯一把關的地方。SAN 順序由持有憑證的一方（可能是攻擊
// 者）決定：若允許多個 URI SAN 時挑出第一個 spiffe scheme 的當身分，攻擊者只
// 要拿到一張同時帶著「被授權的 SPIFFE ID」與「自己的 SPIFFE ID」的憑證，把被
// 授權的那個排在前面，就能冒充成被授權的 agent。因此看到超過一個 URI SAN 一律
// 拒絕，不嘗試挑出「最合理」的那個 —— 模糊就是要 fail closed。
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
