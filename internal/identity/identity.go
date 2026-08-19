package identity

import (
	"context"

	"github.com/jenting/zonedns/internal/ednszone"
	"github.com/miekg/dns"
)

// Reason 說明 SourceZone 為何得到（或得不到）結果。呼叫端用它輸出 metric。
type Reason int

const (
	// ReasonOK 成功取得可信的 source zone。
	ReasonOK Reason = iota
	// ReasonNoTLS 連線沒有 client certificate — 非 zone-aware 的正常路徑。
	ReasonNoTLS
	// ReasonUnauthorizedAgent 憑證有效但不在授權清單中。這是攻擊訊號，需告警。
	ReasonUnauthorizedAgent
	// ReasonNoDeclaration agent 已授權，但沒有帶宣告、或宣告的 zone 不合法。
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

// Config 是信任邊界的設定。
type Config struct {
	authorized map[string]struct{}
	code       uint16
}

// NewConfig 建立 Config。
//
// agents 為空表示「沒有任何 agent 被授權」，不是「全部放行」— 設定漏掉時必須是
// 拒絕而非開放。
func NewConfig(agents []string, code uint16) Config {
	set := make(map[string]struct{}, len(agents))
	for _, a := range agents {
		set[a] = struct{}{}
	}
	return Config{authorized: set, code: code}
}

// SourceZone 取得這次查詢可信的 source zone，實作 spec §6.1 的五個步驟。
//
// 步驟順序不可調換 —— 特別是「先確認 agent 已授權，才讀 EDNS0 宣告」。若把讀取
// 提前，未授權者的宣告就會流進後續邏輯。
func (c Config) SourceZone(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (string, Reason) {
	// 步驟 1、2：取得 client certificate。憑證鏈本身已由 TLS 層以 SPIRE trust
	// bundle 驗證過，這裡不重複驗證。
	certs, ok := PeerCertificates(ctx, w)
	if !ok {
		return "", ReasonNoTLS
	}

	// 步驟 3：只看葉憑證。中繼憑證帶什麼身分都與呼叫者無關。
	id, ok := SPIFFEIDFromCert(certs[0])
	if !ok {
		return "", ReasonUnauthorizedAgent
	}
	if _, authorized := c.authorized[id]; !authorized {
		return "", ReasonUnauthorizedAgent
	}

	// 步驟 4、5：通過授權才讀宣告。ednszone.Get 內含格式驗證，不合法時回 false。
	zone, ok := ednszone.Get(r, c.code)
	if !ok {
		return "", ReasonNoDeclaration
	}
	return zone, ReasonOK
}
