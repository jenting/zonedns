// Package zonetable 保存 zone 到 zone gateway VIP 的對照。
//
// 這份資料來自設定檔，項目數量級是 zone 數（數十筆），啟動後不變 — 因此是唯讀的、
// 不需要鎖。重新載入設定時建立新的 Table 取代舊的。
package zonetable

import "net/netip"

// Table 是 zone 到 gateway VIP 的唯讀對照。
type Table struct {
	gw map[string]netip.Addr
}

// New 建立 Table。輸入的 map 會被複製，呼叫端之後的修改不影響已建立的 Table。
func New(entries map[string]netip.Addr) *Table {
	gw := make(map[string]netip.Addr, len(entries))
	for z, a := range entries {
		gw[z] = a
	}
	return &Table{gw: gw}
}

// Gateway 回傳該 zone 的 gateway VIP。
//
// 找不到時回 ok=false。呼叫端必須把這個情況當成設定錯誤處理（SERVFAIL），
// 不可退回一般答案 — 見 spec §6.4 第四列。
func (t *Table) Gateway(zone string) (netip.Addr, bool) {
	a, ok := t.gw[zone]
	return a, ok
}

// Len 回傳已設定的 zone 數量。
func (t *Table) Len() int { return len(t.gw) }
