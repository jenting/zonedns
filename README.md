# zonedns

Zone-based DNS for mixed Kubernetes and VM environments, built on SPIFFE/SPIRE.

同一個 zone 內的 workload 互打時回一般的服務位址；跨 zone 時回目標 zone 的
gateway VIP。查詢者的 zone 由 node-local DNS 依 source pod IP 查出，經 mTLS DoH
向中心宣告；被查詢名稱的 zone 來自 SPIRE registration entry。

zone 之間在網路層是隔離的，跨 zone 流量只能走 zone gateway —— 這個前提讓「答案
判斷錯誤」的後果是連不上，而不是繞過政策。

## 文件

| 文件 | 內容 |
|---|---|
| `docs/superpowers/specs/2026-08-18-zonedns-design.md` | 設計與核心不變式、威脅模型、**已知限制** |
| `docs/deployment.md` | 兩端的建置與部署、必要告警、兩端必須成對維護的設定 |
| `deploy/k8s/` | 節點端可直接套用的 Kubernetes manifest |

初次接觸建議先讀 spec 的 §3（核心不變式）與 §9（已知限制）—— 這個系統大部分的
失效方式都是「回一個看起來合理的答案」而不是報錯，§9 列的就是那些。

## 架構

```
pod ──一般 UDP DNS──▶ node-local DNS + zonedns_agent
                          │  source IP → 本機 pod → zone label
                          │  以 (qname, qtype, zone) 為 key 快取
                          ▼  mTLS DoH + EDNS0 帶 zone
                      CoreDNS + zonedns（跑在 VM 上）
                          │  驗證 agent 身分才採信宣告
                          │  registry: FQDN → zone（輪詢 SPIRE Entry API）
                          ▼  同 zone → 交給下游；跨 zone → 回 gateway VIP
```

## 元件

**中心端**

| 路徑 | 說明 |
|---|---|
| `plugin/zonedns` | CoreDNS plugin：解析 Corefile、連上 SPIRE Server、決策與回應 |
| `internal/identity` | 信任邊界：驗證 agent 身分並讀取 source zone 宣告 |
| `internal/registry` | 輪詢 SPIRE Entry API，維護 FQDN → zone 的唯讀快照 |
| `internal/zonetable` | zone → gateway VIP 設定 |
| `internal/decision` | 核心決策表（純函式，無 I/O） |

**節點端**

| 路徑 | 說明 |
|---|---|
| `plugin/zonedns_agent` | CoreDNS plugin：判定來源 zone、以 zone 為 key 快取、向 central 宣告 |
| `internal/podzone` | 本機 pod IP → zone（node-scoped informer） |
| `internal/zonecache` | 以 `(qname, qtype, zone)` 為 key 的答案快取 |
| `internal/dohupstream` | 釘住 central SPIFFE ID 的 mTLS DoH client |

**共用**

| 路徑 | 說明 |
|---|---|
| `internal/ednszone` | 兩端之間的 EDNS0 線上格式 |
| `internal/spiffezone` | 從 SPIFFE ID path 取出 zone |
| `internal/testcerts` | 測試專用：產生帶指定 URI SAN 的拋棄式憑證，只被 `_test.go` 匯入 |

節點端與中心端不共用程式碼，只共用 `internal/ednszone` 定義的線上格式（EDNS0
option 裡怎麼編碼一個 zone 宣告）—— 這是兩者之間唯一的相容性介面。任何一邊
單獨修改這個格式，另一邊都不會編譯失敗或執行期報錯，只會讓宣告的 zone 讀不
出來，查詢安靜地走回非 zone-aware 路徑。

## 建置

兩個 plugin 都是 external CoreDNS plugin —— CoreDNS 的 plugin 是**編譯期連結**
的，沒有執行期載入機制，所以兩者都必須重新建置宿主 binary。

- **中心端**編進普通 CoreDNS：在 `plugin.cfg` 加一行（**必須在 `cache` 之前**）
  再 `go generate && go build`
- **節點端**編進 `sigs.k8s.io/node-local-dns`：加 blank import、把
  `"zonedns_agent"` 插進 `dnsserver.Directives`（**同樣在 `cache` 之前**），
  並注意該專案 vendor 相依、且必須以 `GOOS=linux` 建置

兩端的順序要求不是偏好：內建的 `cache` plugin 以 `(qname, qtype)` 為 key，不含
發問者的 zone。若它排在前面，一個 zone 的 pod 會拿到另一個 zone 快取的答案，而
執行期沒有任何徵兆。兩端都會在啟動時檢查並拒絕錯誤的順序。

完整步驟見 `docs/deployment.md`。

## 測試

```bash
go test ./... -race
```

`internal/identity` 的測試涵蓋各種繞過嘗試 —— 整套 zone 隔離是否成立只取決於
該套件，修改前請先讀它的測試。兩端各有一組端到端測試，驗證同一個名字在不同
source zone 下得到不同答案：中心端在 `plugin/zonedns/e2e_test.go`，節點端在
`plugin/zonedns_agent/e2e_test.go`（經真正的 DoH wire 編碼／解碼）。

### 測試沒有涵蓋的

這兩件事已知未被自動化測試涵蓋，且都曾實際造成問題：

- **兩端從未在測試中真正對接。** 它們只在 `internal/ednszone` 的套件測試裡各自
  碰到線上格式。一個只有在兩端接起來才會顯現的錯誤，兩邊的測試都會是綠的 ——
  `upstream` URL 重複附加 `/dns-query` 那個 bug 就是這樣躲過 16 個任務與兩輪
  最終審查的。
- **k8s 模式的 pod informer 從未在真實 cluster 執行過。** 單元測試用的
  `fake.NewSimpleClientset` 不套用 field selector，所以「只看本機節點的 pod」
  這件事在測試裡從來沒有真正發生。
