# Zone-Based DNS (zonedns) — 設計文件

日期：2026-08-18
狀態：設計已定案。§11 原四項待驗證事實已清除三項，餘一項已由設計繞開。

## 1. 問題

環境是 k8s + VM 混合。每個 workload 有 SPIFFE ID，ID 的 path 中帶 zone 資訊。
不同 zone 之間**在網路層是隔離的**，跨 zone 流量只能走 zone gateway。

需求：DNS 解析要依「發問者的 zone」給出不同答案。

- 同 zone 互打 → 回 dest 服務的 zone-內 VIP（一般的 k8s ClusterIP / LB VIP）
- 跨 zone 互打 → 回 **dest zone 的 gateway VIP**

## 2. 名詞

| 名詞 | 意義 |
|---|---|
| zone | workload 的網路/信任分區，編碼在 SPIFFE ID 的 path 中 |
| zone gateway | 某個 zone 對外的入口，跨 zone 流量的唯一路徑 |
| source zone | 發出 DNS 查詢的 workload 所屬的 zone |
| dest zone | 被查詢的 FQDN 所對應的 workload 所屬的 zone |
| agent plugin | 裝在每台機器上的 CoreDNS plugin（node-local DNS 內） |
| central plugin | 中心 CoreDNS 上的 zonedns plugin |

## 3. 核心不變式

以下三條是整個設計的基礎，任何修改都必須重新檢視：

1. **zone 是 workload 的單一屬性。** 同一個 workload 當 client 與當 server 時的
   zone 相同。zone 只在一個地方宣告：pod 的 `zone` label（VM 則是 provisioning 設定）。
2. **一個 FQDN 只屬於一個 zone。** 不需要選擇策略、不需要 failover 語意。
3. **zone 之間網路隔離。** 錯誤的 DNS 答案導致的是「連不上」，不是「繞過政策」。
   這條讓多數失效模式從安全問題降級為連通性問題（可偵測、可告警）。

## 4. 架構總覽

```
  pod (labels: zone=zone-a, zonedns.io/host=payments.example.com)
    │  一般 UDP DNS，不做任何修改
    ▼
  node-local DNS (CoreDNS) + agent plugin          ← 每台機器
    │  ① source IP → 本機 pod watch → labels["zone"]
    │  ② 查快取 (qname, qtype, zone)
    ▼  ③ DoH over mTLS（節點 SVID 當 client cert）+ EDNS0 帶 zone
  central CoreDNS + zonedns plugin（跑在 VM 上）
    │  ④ 驗證 client cert ∈ 授權 agent 清單，才採信 EDNS0 的 zone
    │  ⑤ registry: FQDN → dest zone（來自 SPIRE Server entries）
    │  ⑥ 同 zone → 交給下一個 plugin；跨 zone → 回 dest zone GW VIP
    ▼
  upstream DNS (kubernetes plugin / forward)
```

### 為什麼身分在節點端建立

DNS 查詢封包裡沒有身分資訊，也沒有任何機制會自動附加：

- resolver（glibc/musl）只按 RFC 1035 組訊息，不知道 SPIFFE
- SPIRE agent 不在資料路徑上，是被動的（workload 主動經 Workload API 索取）
- OS 層的「不可偽造的呼叫端身分」只存在於 unix domain socket
  （`SO_PEERCRED`），IP 之上不存在
- 就算把 SVID 塞進查詢也沒有意義：憑證是公開的，不經握手無法證明持有私鑰

因此身分只能由「知道 pod 身分且在資料路徑上」的元件建立。可選位置是 pod 內
（per-pod sidecar）或節點上（node-local DNS）。選節點上的理由：workload 零改動、
k8s 與 VM 一致、source IP 在 CNI 反欺騙下無法偽造。

### 被評估後排除的替代方案

| 方案 | 排除原因 |
|---|---|
| per-zone listener 位址（webhook 注入 dnsConfig） | 需要每台機器綁 N 個 link-local IP、加 zone 要動所有節點；且執行期可由 pod 自行繞過 |
| qname 帶 zone（`payments.zone-a.example.com`） | 服務搬 zone 時名稱改變，命名與拓樸綁死 |
| 每 zone 一組 CoreDNS，不帶 identity | 同一節點混多 zone，打到哪台無法決定 source zone |
| 節點端持有完整 registry，本機決策 | 每節點都要 watch SPIRE Server，等於把控制面複製到每台機器 |
| eBPF 在出向封包插入 EDNS0 option | 要在 eBPF 內解析改寫 DNS、重算 checksum、處理既有 OPT；接收端仍須信任該程式，信任模型與信任 agent 相同，付出換不到東西 |
| per-pod DNS sidecar | 每 pod 多一個 container；VM 上「每 process 一個 sidecar」不可行 |

## 5. 部署期契約

zone 與對外名稱都在 deploy 期宣告，且**只宣告一次**。

### k8s

Deployment 的 pod template：

```yaml
metadata:
  labels:
    zone: zone-a
    zonedns.io/host: payments.example.com
```

`ClusterSPIFFEID`：

```yaml
apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterSPIFFEID
spec:
  podSelector:
    matchExpressions:
      - {key: zonedns.io/host, operator: Exists}
  spiffeIDTemplate: 'spiffe://example.org/zone/{{ .PodMeta.Labels.zone }}/ns/{{ .PodMeta.Namespace }}/sa/{{ .PodSpec.ServiceAccountName }}'
  dnsNameTemplates:
    - '{{ index .PodMeta.Labels "zonedns.io/host" }}'
```

**`podSelector` 的 Exists 守衛是必要條件，不是最佳化。** spire-controller-manager
渲染模板時未設 `missingkey=error`，label 不存在會渲染成空字串；而 SPIRE Server 的
`x509util.ValidateLabel` 會以 `ErrEmptyDomain` 拒絕空的 DNS name，導致**整筆
registration entry 建立失敗，pod 拿不到 SVID** — 失效範圍遠大於 DNS。

產出的 SPIRE entry：

```
spiffe_id: spiffe://example.org/zone/zone-a/ns/prod/sa/payments
selectors: [k8s:pod-uid:...]
dns_names: [payments.example.com]
```

### VM

一台 VM 只屬於一個 zone。SPIRE entry 形式相同，registry 看不出差別：

```
spiffe_id: spiffe://example.org/zone/zone-c/vm/billing-01
dns_names: [billing.example.com]
```

agent 的 zone 於 provisioning 時寫入設定檔（或自本機 SVID 解析），不做 per-query 判斷。

### Istio ServiceEntry（zone GW VIP）— 建議，非必要

**現況：`meshConfig.outboundTrafficPolicy.mode` 為 `ALLOW_ANY`（Istio 預設）**，
跨 zone 答案（zone GW VIP）雖不在 Istio service registry 中，仍會經 PassthroughCluster
直送，**不需 `ServiceEntry` 即可運作**。

將 zone GW VIP 註冊為 `ServiceEntry` 是建議的加固，理由有二：

- **可觀測性。** Istio 文件載明 passthrough 的 observability 會降低。跨 zone 流量正是
  本設計最需要監測的部分，註冊後才能取得正常的 mesh 遙測。
- **不依賴 mesh 層預設值。** 若日後有人為設定衛生將模式收緊為 `REGISTRY_ONLY`，
  未註冊的跨 zone 流量會全數落入 BlackHoleCluster 而中斷。

**需要確認的例外**：`Sidecar` 資源可逐 namespace／workload 覆寫此模式。mesh 層為
`ALLOW_ANY` 不保證各處皆然；若某 namespace 覆寫為 `REGISTRY_ONLY`，該範圍的跨 zone
流量會中斷而其他範圍正常，此種局部失效不易診斷。

```
kubectl get sidecar -A -o yaml | grep -B10 -A2 outboundTrafficPolicy
```

## 6. 子專案 1：central plugin

### 6.1 `identity` 單元 — 信任邊界

```go
func SourceZone(ctx context.Context, w dns.ResponseWriter) (zone string, ok bool)
```

**順序不可調換：**

1. 連線非來自 mTLS listener → 回 `ok=false`（**這是正常路徑，不是錯誤**）
2. 取 peer certificate（憑證鏈驗證由 TLS 層以 SPIRE trust bundle 完成）
3. 自 SAN URI 取 agent 的 SPIFFE ID → **必須命中設定的授權 agent 清單**
4. **只有通過 3 才讀 EDNS0 宣告的 zone**；未通過則忽略宣告並遞增 metric
   （這是攻擊訊號，需可告警）
5. 驗證 zone 字串格式（字元集、長度）

傳輸無關：DoT 與 DoH 取憑證的 API 不同，以介面隔離。

```go
// DoT
w.(dns.ConnectionStater).ConnectionState().PeerCertificates
// DoH — DoHWriter 未實作 ConnectionStater
w.(*dnsserver.DoHWriter).Request().TLS.PeerCertificates
```

伺服器端 mTLS 由 CoreDNS `tls` plugin 的 `client_auth` 選項啟用
（設為 `RequireAndVerifyClientCert`，並令 `ClientCAs = RootCAs`）。

### 6.2 `registry` 單元

```go
func Lookup(fqdn string) (zone string, ok bool)
```

**輪詢** SPIRE Server Entry API 的 `ListEntries`，將每筆 entry 攤平成
`dns_names[i] → zone`，zone 取自 `spiffe_id` 的 path 中的 `/zone/<X>/` 段。

**Entry API 沒有 watch/stream RPC。** `ListEntries` 是分頁的一元呼叫；唯一的串流
RPC `SyncAuthorizedEntries` 是給 agent 同步「自己被授權的 entry」用的，不能用來列出
全部 entry。因此本單元是輪詢器而非 watcher，須以 `page_size` / `next_page_token`
分頁，並以 `output_mask` 只取 `spiffe_id` 與 `dns_names` 以縮小回應。

存取 Entry API 需要 **admin SVID** — central 服務所在 VM 需有 SPIRE agent，且其
registration entry 必須設 `admin: true`。

封裝於內部的失效處理：初次載入尚未完成（未就緒時一律回 `ok=false`，走非 zone-aware
路徑）、輪詢失敗時沿用上一份快照並遞增 metric、多筆 entry 宣告同一 `dns_name` 但
zone 不同（衝突 → 該 FQDN 視為不可解析並遞增 metric，不可任選一個）。

### 6.3 `zonetable` 單元

```go
func Gateway(zone string) (netip.Addr, bool)
```

純設定，來源為 Corefile 或掛載的設定檔。項目數量級為 zone 數（數十筆）。

### 6.4 決策邏輯

純函式，無 I/O：

| source zone | dest zone | 動作 |
|---|---|---|
| 已知 | 已知，相同 | 交給下一個 plugin |
| 已知 | 已知，不同 | **回該 zone 的 GW VIP** |
| 已知 | 不在 registry | 交給下一個 plugin（外部網域） |
| 已知 | 已知，但無 GW 設定 | **SERVFAIL** + 高優先度 metric |
| 未知 | 任意 | 交給下一個 plugin |

只有第二列改變答案。第四列刻意不 fail-open：registry 說 zone 存在但 zone 表沒有
它的 GW，這是設定漏掉；靜默回直連 VIP 等於無聲破壞 zone 隔離。

### 6.5 快取與 plugin 順序

中心端**不需要** zone-aware 快取：

- 同 zone 分支的答案來自 upstream，與 source zone 無關，且只有該服務所屬 zone 的
  client 會走到這個分支，故可用原 qname 快取
- 跨 zone 分支的答案來自設定表，純記憶體，無需快取

代價是一個順序約束：**`zonedns` 必須排在 `cache` 之前**。反之 cache 會在 zonedns
之前把同 zone 答案回給跨 zone 的 client。此約束須在 plugin 註冊時檢查並拒絕錯誤
順序，不可僅寫在文件。

### 6.6 協定契約（agent ↔ central）

此契約由子專案 1 定義、子專案 2 消費，兩者的相容性完全繫於此節。

**傳輸**：**DoH over mTLS（已定案）**。client cert 為 agent 所在機器的 SVID，
經 SPIRE trust bundle 驗證。

agent 端**不使用** CoreDNS 內建的 `forward` plugin，儘管它確實支援 DoH 與 mTLS
（`forward . https://... { tls CERT KEY CA }`；`Proxy.SetTLSConfig` 會將設定帶入 DoH 的
`http.Transport.TLSClientConfig`）。原因是 `tls` 選項接受的是**檔案路徑，且僅在設定
解析時讀取一次**，而 SPIRE SVID 頻繁輪替（預設 TTL 1 小時，過半即換發）。靠 `reload`
plugin 重新載入設定來換憑證會**連帶清空節點快取** — 在每台機器上每半小時發生一次，
與部署 node-local cache 的目的直接衝突。

因此 agent plugin 自行持有上游連線，憑證取自 go-spiffe 的 `workloadapi.X509Source`，
以 `tls.Config.GetClientCertificate` 在每次握手取得當下有效的 SVID。輪替完全在記憶體
內完成，不需重新載入設定，節點快取不受影響。

**source zone 的攜帶方式**：EDNS0 option，option code 取自 local/experimental
區間（65001–65534），設定值兩端必須一致，預設值寫死於契約並可經設定覆寫。
payload 為 UTF-8 的 zone 字串，不含 SPIFFE ID 其餘部分。

選 EDNS0 而非 EDNS Client Subnet 或自訂 record 的理由：ECS 語意是網段而非身分，
會被中間的 resolver 依 RFC 7871 改寫；自訂 record 則會影響快取與序列化行為。

**驗證規則**：central 端在採信該 option 前，必須先完成 §6.1 的步驟 1–3。
未通過者，該 option 一律**視為不存在**（而非視為錯誤）— 查詢繼續走非 zone-aware
路徑，並遞增 metric。

**TTL**：跨 zone 答案的 TTL 由 central 端設定，預設 30 秒。此值決定「服務搬移 zone」
或「zone GW VIP 變更」的傳播延遲上限，且 agent 的 zone-aware 快取必須遵守它。
不採用 0 是因為節點端會因此完全失去快取效益；不採用長 TTL 是因為 zone 拓樸變更
期間的錯誤答案會持續整個 TTL，而在網路隔離下那代表持續的連線失敗。

## 7. 子專案 2：agent plugin

編譯進自建的 node-local DNS image（NodeLocal DNSCache 本身即 CoreDNS）。
node-local DNS 的**定址與部署形態完全不變**：單一 link-local 位址、既有 iptables
規則、pod 的 resolv.conf 不改、不需要 mutating webhook、現有 pod 不需重啟。
新增 zone 時節點不需任何變更。

### 7.1 k8s 模式

```
source IP → 本機 pod 表 → labels["zone"]
```

pod 表以 `fieldSelector: spec.nodeName=<自己>` watch，僅本機數十筆。
所讀的 `zone` label 正是 `spiffeIDTemplate` 產生 SPIFFE ID 所用的同一個值，
由建構方式保證不漂移。

前提：NodeLocal DNSCache 走 link-local 位址且不經 DNAT/conntrack，故 source IP
為真實 pod IP。有無 Istio sidecar 對此透明 — sidecar 與 app 同 netns，即使查詢
先經 sidecar DNS proxy 再轉發，source IP 仍是 pod IP。

### 7.2 VM 模式

zone 於啟動時自設定檔決定，所有查詢共用，無 per-query 判斷。

### 7.3 快取

**必須** zone-aware：最終答案隨 zone 而異。key 為 `(qname, qtype, zone)`。
因 zone 由 agent 自行算出，此處實作單純。排在既有 `cache` plugin 之前。

### 7.4 Corefile 範圍隔離

**既有的 node-local cache 是 zone-盲的** — 以 `(qname, qtype)` 為 key。若讓它快取參與
zone 路由的名稱，zone-a 的 pod 問過之後，zone-b 的 pod 會取得同一份答案。

作法是讓 agent plugin 只負責參與 zone 路由的網域，置於獨立的 server block，其餘設定
完全不動：

```
cluster.local:53 { ... 既有設定不動 ... }

example.com:53 {
    zonedns_agent {
        spire_socket /run/spire/sockets/agent.sock
        upstream     https://central-dns/dns-query
    }
}

.:53 { ... 既有 cache + forward 不動 ... }
```

zone-aware 快取（§7.3）由 agent plugin 自行持有，不使用 stock `cache` plugin。此安排
使匯入本設計對既有 node-local DNS 行為的影響面收斂到單一網域。

### 7.5 上游身分驗證

**agent 必須以 SPIFFE ID 釘住 central，不可只驗證憑證鏈。**

若只用 SPIRE trust bundle 做一般 TLS 驗證，信任域內**任何一張 SVID** 都能冒充
central。這與子專案 1 實作時發現並修掉的 `AuthorizeMemberOf` 問題完全對稱，但這一
側後果更重：偽造的 central 可以回傳任意答案 —— 例如告訴 zone-a 的 client 某個同
zone 服務其實是跨 zone 的，並給出攻擊者控制的位址。agent 對答案沒有任何獨立查核
手段，會完整採信。

作法與子專案 1 相同：`tlsconfig.AuthorizeID` 搭配設定中的 central SPIFFE ID，
設定項為必填（無預設值，缺少即啟動失敗）。

**部署耦合**：agent 自身 SVID 的 SPIFFE ID 必須出現在 central 的 `authorized_agent`
清單中，否則 central 會忽略它宣告的 zone 並靜默退回非 zone-aware 路徑。兩端的
設定必須成對維護。

### 7.6 失效模式與偵測

這類問題最大的風險不是會壞，而是壞得安靜。每一項都必須有偵測手段：

| 失效模式 | 偵測 |
|---|---|
| pod IP 回收後對應到舊 pod | watch 的 delete 事件立即失效映射；查不到 IP 一律走退路，**絕不沿用舊值** |
| 節點上有 SNAT/masquerade 改寫 source IP | 輸出「source IP == 節點 IP」查詢比例的 metric，數值跳升即告警 |
| hostNetwork pod（source IP 為節點 IP） | 退到非 zone-aware 路徑；identity resolver 設計為可插拔介面 |
| k8s watch 中斷 | 明確的就緒狀態；未就緒時走退路而非猜測 |

## 8. 威脅模型

| 攻擊 | 結果 |
|---|---|
| pod 偽造 source IP | CNI 反欺騙阻擋；即使成功，回應也送不回攻擊者 |
| 非授權來源直連 central CoreDNS 並宣告任意 zone | client cert 不在授權清單 → 宣告被忽略 → 走非 zone-aware 路徑 |
| 取得他人 SVID 憑證（公開部分）冒用 | 無私鑰則 mTLS 握手失敗 |
| 竄改 EDNS0 zone 值 | 位於 mTLS 通道內，無法在傳輸中竄改 |

因 zone 之間網路隔離，即使 zone 判斷錯誤，得到的位址也路由不到，後果為連線失敗
而非政策繞過。

## 9. 已知限制

1. **一個 workload 只能有一個對外 FQDN。** 加第二個選配 label 會在未填時渲染出空
   字串導致 entry 被拒；開第二個 `ClusterSPIFFEID` 會因 SPIFFE ID 與 selector 相同
   而被 `entriesMasked` 遮蔽。多別名需求須改用 Istio traversal 方案。
2. **`zonedns.io/host` 與 VirtualService 的 `hosts:` 是同一名稱的兩份宣告。**
   漂移的後果是 registry 查不到 → 不做 zone 路由（降級但安全），而且**沒有任何
   東西會報錯** —— DNS 查詢照常有答案，只是答案不再受 zone 約束。

   防線是 `cmd/zonedns-drift`：把所有 VirtualService 的 `hosts:` 與所有帶
   `zonedns.io/host` 的 pod label 做集合比對，兩個方向都報 —— 沒人認領的 host
   （危險：client 會查它）與沒人查的 label（多半是打錯字）。離開碼 0 乾淨、
   1 有漂移、2 檢查本身失敗（連不上、權限不足、沒裝 Istio CRD）。適合放進 CI
   或以 CronJob 定期跑。

   比對前會排除三類名稱並列在 `--show-skipped` 裡：萬用 host、cluster 內部名稱
   （短名與 `*.svc.cluster.local`）、以及綁在 gateway 而非 mesh 的 VirtualService。
   這些不可能有對應的 workload label，比對它們只會產生假警報。

   **這個檢查只比對名稱。** 兩邊都對得上的名稱仍然可能指向錯誤的 workload ——
   要驗證那件事得走 VirtualService → destination Service → pod 的路由追蹤，也就是
   限制 1 提到的那個 Istio traversal 方案 —— 本設計刻意不採用它。工具的輸出會把
   這個界線寫出來，避免一份乾淨報告被讀成「設定正確」。
3. **稽核僅到 zone 粒度。** 中心端不知道是哪個 workload 在查詢。日後若需
   per-workload DNS 政策，須重新設計而非擴充。
4. **hostNetwork pod 不支援 zone 路由。**

5. **zone-aware listener 必須是 DoH，不可用 DoT。** 實作審查時發現：CoreDNS 的
   `metrics` plugin 以 `NewRecorder(w)` 包裝 ResponseWriter，而該 Recorder 是把
   `dns.ResponseWriter` 當**介面欄位**內嵌，因此 DoT 取憑證所依賴的
   `w.(dns.ConnectionStater)` 型別斷言必然失敗。後果是 DoT 查詢一律被判定為
   「沒有憑證」→ 走非 zone-aware 路徑 → **zone 隔離靜默關閉，且 `unauthorized_agent`
   告警永遠不會觸發**。

   DoH 路徑不受影響，因為它是從 context 取 `*http.Request`（見 §6.1），與 writer
   是否被包裝無關 —— 這正是當初選擇 context 而非型別斷言的原因。

   未以調整 plugin 順序修正：把 `zonedns` 排到 `metrics` 之前雖可修好 DoT，但會使
   CoreDNS 的標準請求 metrics 從此看不到任何跨 zone 答案，對一個已決定不部署的傳輸
   而言代價過高。

6. **多個 URI SAN 的憑證一律拒絕。** SPIFFE 規定憑證只能有一個 URI SAN，但
   `crypto/tls` 的憑證鏈驗證不檢查 SAN 數量。若接受多個並取第一個 spiffe URI，
   攻擊者只要取得一張同時帶有授權 agent ID 與自己 ID 的憑證，把授權那個排在前面
   即可冒充。因此 `SPIFFEIDFromCert` 要求恰好一個 URI SAN，模糊即拒絕。

## 10. 測試策略

- `identity` 單元的測試密度須高於其他單元 — **整套 zone 隔離是否可被繞過只取決於它**。
  adversarial 案例：無 cert、非授權 cert、授權 cert 但無 EDNS0、多個 EDNS0 option、
  zone 字串含分隔字元、zone 缺失。DoT 與 DoH 兩條取憑證路徑各測一次。
- 決策邏輯為純函式，以表格驅動窮舉 §6.4 全部五列。
- `registry` 的失效處理：初次載入未完成、watch 斷線、`dns_names` 衝突。
- plugin 順序約束：註冊時放在 `cache` 之後必須報錯。
- 端到端：central plugin 可在無 agent 的情況下以構造的 mTLS 連線 + EDNS0 驗證。

## 11. 待驗證項

1. ~~**Istio DNS capture 狀態。**~~ **已確認：未啟用。** 查詢不會被 sidecar 攔截，
   一律到達 node-local DNS。有無 sidecar 對本設計透明（sidecar 與 app 同 netns，
   source IP 仍為 pod IP）。

2. ~~**`outboundTrafficPolicy` 對 zone GW VIP 的影響。**~~ **已確認：`ALLOW_ANY`**，
   跨 zone 經 PassthroughCluster 直送，不需額外設定即可運作。`ServiceEntry` 降為建議
   事項（見 §5）。**唯一待確認**：是否有 `Sidecar` 資源逐 namespace 覆寫為
   `REGISTRY_ONLY` — 該範圍的跨 zone 流量會中斷而他處正常。

3. ~~**central 服務的擺放位置。**~~ **已確認：置於 VM，路徑上無終結 TLS 的設備。**
   §6.1 的信任邊界完整成立 — central 看到的 client cert 即為 agent 本人的 SVID。

   2026-08-20 再次確認：環境內不會有 TLS termination 出現在打到 DNS server 的
   路徑上。

   **此前提為本設計的安全基礎。** 日後若在路徑上引入 L7 ingress、反向代理或
   TLS 終結負載平衡器，會發生什麼事：

   - **agent → central 方向由建構方式擋住。** `internal/dohupstream` 以
     `tlsconfig.AuthorizeID(central)` 釘死對方的 SPIFFE ID，中間設備出示自己的
     憑證時握手直接失敗 —— SERVFAIL 加 `upstream_errors_total`，這一側不可能靜默。
   - **central → agent 方向會降級但有訊號。** central 看到的是中間設備的
     client cert，不是 agent 本人的 SVID。該身分不在 `authorized_agent` 清單裡，
     zone 宣告被忽略、查詢回退到非 zone-aware 路徑，而
     `coredns_zonedns_source_zone_total{reason="unauthorized_agent"}` 會上升
     —— 這正是 §9 限制 5 與部署文件把它列為必要告警的原因。

   換言之，執行期的 mTLS 釘住本身就是這個前提的持續驗證，而且比任何測試都強：
   它在正式環境的每一次查詢上生效。**真正無法由程式碼防住的是人的反應** ——
   把中間設備的 SPIFFE ID 加進 `authorized_agent` 來「修好」那個告警。那一步
   之後，該設備就能宣告任意 zone，整套隔離失效且完全無聲。`unauthorized_agent`
   告警的處理流程必須寫明：這個告警的正確處置是移除中間設備，不是授權它。

4. **CoreDNS 對多個 `bind` server block 的支援**（僅在日後改回 per-zone 位址時才需要）。

## 12. 實作順序

先做子專案 1（central plugin）。契約必須先存在，且它可在沒有 agent 的情況下以
真實 SPIRE entries 端到端驗證。子專案 2 消費該契約，與子專案 1 同技術棧
（皆為 CoreDNS plugin），可共用 identity、zone 解析、SPIFFE 相關套件。
