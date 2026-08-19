// Package ednszone 定義 agent 與 central 之間傳遞 source zone 的線上格式。
//
// 這是兩個子專案唯一的相容性介面（spec §6.6）：agent 用 Set 寫入，central 用 Get
// 讀出。編碼與解碼刻意放在同一個套件並一起測試，避免任一端單方面改動。
//
// 選 EDNS0 而非 EDNS Client Subnet：ECS 的語意是網段而非身分，且會被中間的
// resolver 依 RFC 7871 改寫。選 local/experimental 區間的 option code：該區間
// (65001-65534) 由 IANA 保留給私有用途，不會與標準 option 衝突。
package ednszone

import (
	"github.com/miekg/dns"
)

// DefaultCode 是預設的 EDNS0 option code，取自 IANA 的 local/experimental 區間。
const DefaultCode uint16 = 65001

// MaxLen 是 zone 字串的長度上限，與 k8s label value 的上限一致。
const MaxLen = 63

// Valid 回報 zone 字串是否合法。
//
// 這道檢查在解碼端也會執行 — 即使宣告來自已驗證的 agent，字串內容仍是外部輸入，
// 不可直接用於後續的 map 查詢或日誌輸出。
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

// Set 在訊息上寫入 source zone，必要時建立 OPT record。
//
// 已存在的 OPT record 會被保留（含 UDP size 與 DO bit），同 code 的舊 option 會被
// 取代而非附加 — 否則重試或轉發路徑上可能累積出多個彼此矛盾的宣告。
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

// Get 讀出 source zone。zone 不合法時回 ok=false，與「不存在」同樣處理。
//
// 出現兩個以上帶同一個 code 的 option 時也回 ok=false，即使其中之一內容合法 ——
// Set 會防止單一呼叫端疊加出這種訊息，但 central 端解析的是線上位元組，
// 惡意或有 bug 的 agent 送出的封包不受 Set 保護。任選其中一個（例如「取第一個」）
// 等於接受一個可能已被攻擊者插入的宣告冒充另一個，與本專案在
// SPIFFEIDFromCert 拒絕多個 URI SAN 憑證的理由相同：模糊就是要 fail closed，
// 不嘗試挑出「最合理」的那個。
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
