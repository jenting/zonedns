# zonedns

Zone-based DNS for mixed Kubernetes and VM environments, built on SPIFFE/SPIRE.

同一個 zone 內的 workload 互打時回一般的服務位址；跨 zone 時回目標 zone 的
gateway VIP。查詢者的 zone 由 node-local DNS 依 source pod IP 查出，經 mTLS DoH
向中心宣告；被查詢名稱的 zone 來自 SPIRE registration entry。

- 設計文件：`docs/superpowers/specs/2026-08-18-zonedns-design.md`
- 部署說明：`docs/deployment.md`

## 元件

| 路徑 | 說明 |
|---|---|
| `plugin/zonedns` | 中心端 CoreDNS plugin：解析 Corefile、連上 SPIRE Server、決策與回應 |
| `internal/identity` | 信任邊界：驗證 agent 身分並讀取 source zone 宣告 |
| `internal/registry` | 輪詢 SPIRE Entry API，維護 FQDN → zone 的唯讀快照 |
| `internal/zonetable` | zone → gateway VIP 設定 |
| `internal/decision` | 核心決策表（純函式，無 I/O） |
| `internal/ednszone` | agent 與 central 之間的 EDNS0 線上格式 |
| `internal/spiffezone` | 從 SPIFFE ID path 取出 zone |
| `internal/testcerts` | 測試專用：產生帶指定 URI SAN 的拋棄式憑證，只被 `_test.go` 匯入 |
| `plugin/zonedns_agent` | 節點端 CoreDNS plugin：判定來源 zone、以 zone 為 key 快取、向 central 宣告 |
| `internal/podzone` | 本機 pod IP → zone（node-scoped informer） |
| `internal/zonecache` | 以 `(qname, qtype, zone)` 為 key 的答案快取 |
| `internal/dohupstream` | 釘住 central SPIFFE ID 的 mTLS DoH client |

節點端與中心端不共用程式碼，只共用 `internal/ednszone` 定義的線上格式（EDNS0
option 裡怎麼編碼一個 zone 宣告）—— 這是兩者之間唯一的相容性介面。任何一邊
單獨修改這個格式，另一邊都不會編譯失敗或執行期報錯，只會讓宣告的 zone 讀不
出來，查詢安靜地走回非 zone-aware 路徑。

## 測試

```bash
go test ./... -race
```

`internal/identity` 的測試涵蓋各種繞過嘗試 —— 整套 zone 隔離是否成立只取決於
該套件，修改前請先讀它的測試。`plugin/zonedns/e2e_test.go` 與
`plugin/zonedns/zonedns_test.go` 一起以真實憑證與完整的 plugin chain 驗證兩條
端到端路徑：DoH 全路徑，以及同一個名字在不同 source zone 下得到不同答案。
`plugin/zonedns_agent/e2e_test.go` 在節點端驗證同一件事的鏡像場景：同一個
名字、兩個不同 zone 的呼叫者，經真正的 DoH wire 編碼／解碼得到兩個不同答案，
且各自觸發一次獨立的上游查詢。
