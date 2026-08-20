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
| `build/` | 兩份 Dockerfile 與注入 plugin 的 registration 檔 |
| `Makefile` | 建置、測試、image、漂移檢查的入口（`make help`） |

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

## 部署前提

**agent 與 central 之間的路徑上不得有任何終結 TLS 的設備**（L7 ingress、反向
代理、TLS 終結負載平衡器）。整套 zone 隔離建立在 central 看到的 client 憑證就是
agent 本人的 SVID —— 中間一旦有設備終結 TLS，central 看到的會是它的憑證。

（2026-08-20 已向環境負責人確認：本環境不會有 TLS termination 出現在打到 DNS
server 的路徑上。）

這個前提不必靠定期測試維護，執行期本身就在驗證它，而且在每一次查詢上生效：

- **agent → central 由建構方式擋住** —— agent 以 `AuthorizeID(central)` 釘死對方
  的 SPIFFE ID，中間設備出示自己的憑證時握手直接失敗。這一側不可能靜默。
- **central → agent 會降級但有訊號** —— `coredns_zonedns_source_zone_total{reason="unauthorized_agent"}`
  會上升。

**`unauthorized_agent` 告警的正確處置是移除那個未授權身分，絕不是把它的
SPIFFE ID 加進 `authorized_agent` 讓告警消失。** 那一步之後該身分能宣告任意
zone，整套隔離失效且從此完全無聲。這是程式碼防不住的一步 —— 設定說誰可信，
central 就信誰。

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

**工具**

| 路徑 | 說明 |
|---|---|
| `cmd/zonedns-drift` | 比對 VirtualService 的 `hosts:` 與 pod 的 `zonedns.io/host` label，抓出兩份宣告的漂移 |
| `internal/drift` | 上面那支工具的比對與收集邏輯 |

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

```bash
make images          # 兩個 image
make image-central   # 只建中心端
make image-agent     # 只建節點端
make help            # 全部目標
```

兩份 Dockerfile 各自內建自檢：中心端確認 `-plugins` 列得出 `zonedns`，節點端
餵一份含 `zonedns_agent` 的 Corefile 確認 directive 被認得。建置失敗會停在建置，
而不是變成一個看起來正常、卻沒有 plugin 的 image。

完整步驟與版本 pinning 的理由見 `docs/deployment.md`。

## 測試

```bash
go test ./... -race
```

`internal/identity` 的測試涵蓋各種繞過嘗試 —— 整套 zone 隔離是否成立只取決於
該套件，修改前請先讀它的測試。兩端各有一組端到端測試，驗證同一個名字在不同
source zone 下得到不同答案：中心端在 `plugin/zonedns/e2e_test.go`，節點端在
`plugin/zonedns_agent/e2e_test.go`（經真正的 DoH wire 編碼／解碼）。

### 兩端對接測試

`internal/integration` 讓真正的 `Agent.ServeDNS` 經過**真實的 mTLS 握手**打到
真正的 `ZoneDNS.ServeDNS`，中間不替換任何一端的邏輯。它涵蓋單邊測試構造不出來
的情境：兩端設定不同的 `edns0_code`、未授權憑證在真實握手下被拒、以及 client
偽造的宣告在線上被剝除。

那裡的假 central **刻意跟真的一樣嚴格** —— 它套用與 CoreDNS DoH server 完全
相同的路徑檢查。`upstream` URL 重複附加 `/dns-query` 那個 bug 之所以躲過 16 個
任務與兩輪最終審查，正是因為當時的測試替身接受任何路徑。寬鬆的替身會複製它
本來要防的盲點。

### 需要真實 cluster 的測試

`internal/podzone/cluster_test.go` 以 `cluster` build tag 隔開，一般的
`go test ./...` 不會跑到。CI 用兩節點 kind cluster 執行；本機重現：

```bash
kind create cluster --config deploy/kind/two-node.yaml
kubectl apply -f deploy/k8s/01-rbac.yaml
go test -tags=cluster ./internal/podzone/ -run TestCluster -v
```

它驗的是 `fake.NewSimpleClientset` 結構上做不到的事：它的 object tracker
**忽略 field selector**，所以「informer 只看本機節點的 pod」這個行為在其他
測試裡從來沒有真正發生過。測試以該 ServiceAccount 的 token 連線、用的是
`deploy/k8s/01-rbac.yaml` 那份真正的 RBAC，所以權限不足時 informer 會同步不了
而失敗。

必須是兩個節點：單節點的 cluster 無法證明範圍真的被限縮。

`internal/drift/cluster_test.go` 同樣以 `cluster` tag 隔開，需要一個裝了 Istio
CRD 的 cluster：

```bash
kind create cluster
make istio-crds
make test-drift
```

它驗的是 fake dynamic client 結構上做不到的事：那個假物件**對 GVR 不做任何驗證**
—— 群組名、資源複數形、版本全部打錯，它一樣照列不誤。也就是說「這支工具真的
讀得到 VirtualService」這件事，在單元測試裡從來沒有被證明過，而它是整個檢查的
前提：讀不到就等於沒有漂移，一份漂亮的乾淨報告。

## 漂移檢查

一個 workload 的對外名稱在這套設計裡被寫了兩份 —— pod 的 `zonedns.io/host`
label 決定 SPIRE entry 的 dns_name（也就是 central registry 的 key），Istio
VirtualService 的 `hosts:` 決定 client 實際查什麼名字。**兩份宣告漂移時沒有任何
東西會報錯**：central 查不到那個名字，就把它當成不歸自己管而交給下游，於是那個
服務靜靜地失去 zone 路由，而 DNS 查詢照常有答案。

```bash
make drift              # 用目前的 kubeconfig
go run ./cmd/zonedns-drift --show-skipped
```

| 離開碼 | 意義 |
|---|---|
| 0 | 沒有漂移 |
| 1 | 發現漂移 |
| 2 | 檢查本身失敗（連不上、權限不足、沒裝 Istio CRD） |

離開碼 2 是刻意與 0 分開的：叢集裡沒有 Istio CRD 和叢集裡沒有漂移，如果都印成
「乾淨」，這支工具就會在最該說話的時候保持沉默。

比對前會排除三類名稱（`--show-skipped` 會列出來並附上理由）：萬用 host、cluster
內部名稱（短名與 `*.svc.cluster.local`）、以及綁在 gateway 而非 mesh 的
VirtualService。這些不可能有對應的 workload label，比對它們只會製造假警報。

**這個檢查只比對名稱。** 兩邊都對得上的名稱仍然可能指向錯誤的 workload —— 要驗
那件事得追蹤 VirtualService → destination Service → pod 的路由，也就是設計時評估
後否決的 Istio traversal 方案。工具的輸出會把這個界線印出來。

在叢集內執行（CronJob）時需要的權限：對 `pods` 與 `networking.istio.io` 的
`virtualservices` 有 cluster 範圍的 `list`。

`--namespace` 可以把檢查限縮到單一 namespace，但**那會縮小正確性**：Istio 允許
A namespace 的 VirtualService 指向 B namespace 的服務，限縮後那種情形會被誤報成
「沒有 pod 認領」。它的用途是測試與範圍受限的檢查，正式用途請維持預設的全 cluster。

## CI

`.github/workflows/ci.yaml` 有五個 job。每一個都對應一種「單元測試結構上證明不了」
的東西：

| Job | 它證明什麼 |
|---|---|
| `test` | 格式、`go vet`、`go build`、`go mod tidy` 是 no-op、`go test -race` |
| `plugin-link` | 兩個 plugin 真的連結得進宿主 binary 並完成註冊；另外建一個**順序錯誤**的 binary，確認它啟動時真的被拒絕 |
| `manifests` | `deploy/k8s/*.yaml` 對真實 API server 通過 server-side dry-run，且裝了真的 `ClusterSPIFFEID` CRD —— 少了 CRD，打錯的欄位名會被當成合法 YAML 放行 |
| `informer` | 兩節點 kind cluster 上，`spec.nodeName` field selector 真的把範圍限縮到本機，且 `deploy/k8s/01-rbac.yaml` 的權限真的夠 |
| `drift` | 漂移檢查對真實 Istio CRD 跑得動，三個離開碼都正確，而且報告會**指名道姓** |

`tidy-check` 不是潔癖：CoreDNS 版本必須與上游 node-local-dns 一致、k8s 函式庫
必須落在同一條線上，否則 agent plugin 連結不進去。那些 pin 全靠這個 job 守住。

`plugin-link` 與 `drift` 都刻意包含**反向驗證** —— 建一個應該失敗的東西，確認它
真的失敗。只驗成功路徑的話，一個永遠通過的檢查看起來跟一個正確的檢查一模一樣。

## 目前狀態

**可用的**：兩端 plugin 與其對接、節點端的 Kubernetes manifest、兩份 Dockerfile
與 Makefile、漂移檢查工具、上述五個 CI job。

**還沒做的**：

| 項目 | 影響 |
|---|---|
| central 的 VM 端部署 artifact | central 跑在 VM 上，但 repo 裡只有 `docs/deployment.md` 的文字敘述，沒有 systemd unit 或任何可直接套用的檔案 |
| `PrometheusRule` | 必要告警列在 `docs/deployment.md`，但沒有可直接套用的 rule 檔 —— 目前得手動照著建 |
| spec §11 項 2 的尾巴 | 是否有 `Sidecar` 資源逐 namespace 覆寫成 `REGISTRY_ONLY`。若有，該範圍的跨 zone 流量會中斷而他處正常 |
| spec §11 項 4 | CoreDNS 對多個 `bind` server block 的支援 —— 僅在日後改回 per-zone 位址時才需要 |

另外有數項已記錄但未處理的次要問題，例如 `podzone.Run` 不可重入（重複呼叫會建出
第二個 informer），以及 `zonecache` 會快取「非成功但帶有答案」的回應。兩者在目前
的使用方式下不會觸發。
