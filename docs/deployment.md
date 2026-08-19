# zonedns central 部署

## 建置

zonedns 是 external CoreDNS plugin。CoreDNS 的 plugin 是編譯期連結的，沒有執行期
載入機制，因此必須重新建置 CoreDNS binary。

1. 取得 CoreDNS 原始碼（版本需與 `go.mod` 的 pin 一致）
2. 在 `plugin.cfg` 中 **cache 之前** 加入一行：

   ```
   zonedns:github.com/jenting/zonedns/plugin/zonedns
   ```

   順序不可放在 `cache` 之後 —— `setup()` 一啟動就會呼叫
   `CheckDirectiveOrder(dnsserver.Directives)`，順序錯誤會直接拒絕啟動而不是
   靜默接受（見 `plugin/zonedns/setup.go`）：把 `cache` 排在前面，cache 會用
   `(qname, qtype)` 這個不含 zone 的 key 回答，跨 zone 的 client 會拿到別的
   zone 快取的答案，而且執行期沒有任何徵兆。

3. 建置：

   ```bash
   go generate && go build
   ```

## SPIRE 前置條件

### 一、workload 的 registration entry（registry 的資料來源）

zonedns 的 registry 完全來自 SPIRE registration entry：`dns_names` 提供名稱，
`spiffe_id` 的 path 提供 zone。k8s 這一側用 `ClusterSPIFFEID` 產生：

```yaml
apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterSPIFFEID
metadata:
  name: zonedns-workloads
spec:
  # 必要守衛：沒有這一行，未標 zonedns.io/host 的 pod 會渲染出空的 dns_names，
  # SPIRE Server 以 ErrEmptyDomain 拒絕整筆 entry，該 pod 會拿不到 SVID ——
  # 失效範圍遠大於 DNS，見設計文件 §5。
  podSelector:
    matchExpressions:
      - {key: zonedns.io/host, operator: Exists}
  spiffeIDTemplate: 'spiffe://example.org/zone/{{ .PodMeta.Labels.zone }}/ns/{{ .PodMeta.Namespace }}/sa/{{ .PodSpec.ServiceAccountName }}'
  dnsNameTemplates:
    - '{{ index .PodMeta.Labels "zonedns.io/host" }}'
```

對應的 Deployment pod template：

```yaml
metadata:
  labels:
    zone: zone-a
    zonedns.io/host: payments.example.com
```

VM 這一側的 entry 形式相同，registry 看不出差別：

```bash
spire-server entry create \
  -spiffeID spiffe://example.org/zone/zone-c/vm/billing-01 \
  -parentID spiffe://example.org/vm/vm-01 \
  -selector unix:uid:1000 \
  -dns billing.example.com
```

**一個 workload 只能有一個對外 FQDN**（設計文件 §9 已知限制 1）。加第二個選配
label 會在未填時渲染出空字串導致 entry 被拒；開第二個 `ClusterSPIFFEID` 會因
SPIFFE ID 與 selector 相同而被 `entriesMasked` 遮蔽。

### 二、central 自己存取 Entry API 的權限

兩種形態，Corefile 的 `spire_server` 決定走哪一種：

**同機（建議）** —— central 與 SPIRE Server 在同一台 VM，走本機管理 socket：

```
spire_server unix:///run/spire/sockets/server.sock
```

存取權由檔案權限控制，不需要 SVID，也不需要 `spire_server_id` 或
`workload_api`（`spire_server_id` 若設了也沒有作用，因為這條路徑不做 mTLS
握手——直接留空即可，設了只會徒增混淆）。

**跨機** —— 走 mTLS，此時 central 需要**同機的 SPIRE agent**（取得 admin SVID
用），且其 registration entry 必須設 `admin: true`：

```bash
spire-server entry create \
  -spiffeID spiffe://example.org/zone/mgmt/service/zonedns-central \
  -parentID spiffe://example.org/vm/central-01 \
  -selector unix:uid:1000 \
  -admin
```

Corefile 除了 `workload_api`（central 自己的 Workload API socket，取得上面那張
admin SVID）之外，**必須**設定 `spire_server_id`：

```
spire_server     spire-server.example.org:8081
spire_server_id  spiffe://example.org/spire/server
workload_api     unix:///run/spire/sockets/agent.sock
```

`spire_server_id` 釘住 SPIRE Server **確切的** SPIFFE ID（`AuthorizeID`），而不只
是驗證「trust domain 內的某個成員」（`AuthorizeMemberOf`）。少了它，任何持有同
trust domain 內任一張 SVID、且能攔截這條連線的人，都能冒充 SPIRE Server 餵一份
偽造的 registry、把任意名字導向任意 zone，進而左右 zonedns 的每一個路由決策 ——
`spire_server` 為網路位址時，`parseConfig` 會直接拒絕沒有 `spire_server_id` 的
設定檔，fail closed。

沒有獨立的 `trust_domain` 選項：`spire_server_id` 本身就是一個完整的 SPIFFE ID
（含 trust domain），不需要另外重複宣告。

## Corefile

**傳輸方式是 DNS-over-HTTPS，不是 DNS-over-TLS。** 兩者看起來都是「TLS 上跑
DNS」，但 zonedns 的身分擷取只有在 DoH 上才可靠：

- DoH 的 client 憑證是從 context 裡的 `*http.Request` 取得（`identity` 套件），
  與 CoreDNS 如何包裝 `dns.ResponseWriter` 無關。
- DoT 的 client 憑證則要對 `ResponseWriter` 做 `dns.ConnectionStater` 型別斷言。
  CoreDNS 內建的 `metrics` plugin 會用一個把 `dns.ResponseWriter` 存成
  **介面欄位**（而非具名的具體型別內嵌）的 Recorder 包住 writer，這個斷言在
  它包過的 writer 上必然失敗。

後果是：把 zonedns 接在 `853` 這種 DoT listener 上，每個查詢都會被判定成
「沒有憑證」，安靜地退回非 zone-aware 路徑 —— zone 隔離整個關閉，而
`unauthorized_agent` 這個原本該告警的 metric 永遠不會遞增，因為根本沒有走到
會檢查 client cert 的那段程式碼。`setup()` 會在偵測到 DoT listener 時印出
啟動警告（見 `plugin/zonedns/setup.go` 的 `warnIfDoT`），但**不會拒絕啟動**——
這是刻意的：把 `zonedns` 排到 `metrics` 之前雖可修好 DoT，卻會讓 CoreDNS 的
標準 request metrics 從此看不到任何跨 zone 答案，對一個已經決定不部署的傳輸
而言代價過高（設計文件 §9 限制 5）。實務上請直接使用下面的 `https://` 監聽，
`853` 只是操作者出於習慣可能會伸手去用的錯誤設定，這裡先說清楚原因。

```
https://example.com:443 {
    tls /etc/zonedns/svid.pem /etc/zonedns/svid-key.pem /etc/zonedns/bundle.pem {
        client_auth require_and_verify
    }

    zonedns {
        spire_server unix:///run/spire/sockets/server.sock
        poll_interval 30s

        # 只有這些 SPIFFE ID 宣告的 source zone 會被採信。
        # 精確比對，不支援前綴。
        authorized_agent spiffe://example.org/zone/infra/node/node-01
        authorized_agent spiffe://example.org/zone/infra/node/node-02

        edns0_code 65001
        ttl 30

        gateway zone-a 203.0.113.10
        gateway zone-b 203.0.113.11
        gateway zone-c 203.0.113.12
    }

    cache 30
    forward . 10.96.0.10
    prometheus :9153
    log
    errors
}
```

`client_auth require_and_verify` 是必要的 —— 沒有它，CoreDNS 不會要求 client 憑證，
`identity` 取不到憑證就會讓所有查詢走非 zone-aware 路徑，**zone 路由會完全失效
而且沒有錯誤訊息**。

### `zonedns` 區塊的設定項

以下是 `plugin/zonedns/setup.go` 實際支援、且僅支援的選項。沒有列出的名字
（包含 `trust_domain` —— 舊版曾有，已移除）在解析時會被 `parseConfig` 直接
拒絕。

| 選項 | 必要性 | 說明 |
|---|---|---|
| `spire_server` | **必要** | `unix://` socket 或 `host:port`。決定走哪一種存取模式，見上一節。 |
| `authorized_agent` | **必要，至少一筆**，可重複 | 允許宣告 source zone 的 agent SPIFFE ID，精確比對。一筆都沒有等於這個 plugin 永遠不會 zone-aware，`parseConfig` 視為設定錯誤而拒絕。 |
| `spire_server_id` | `spire_server` 為 `host:port` 時**必要**；`unix://` 時不需要（設了也無作用） | 釘住 SPIRE Server 的確切 SPIFFE ID，見上一節。 |
| `workload_api` | `spire_server` 為 `host:port` 時必要 | central 自己的 Workload API socket，取得存取 Entry API 用的 admin SVID。 |
| `poll_interval` | 選填，預設 `30s` | 輪詢 SPIRE Entry API 的週期。必須是正值，否則啟動時直接拒絕。 |
| `edns0_code` | 選填，預設 `65001` | agent/central 之間攜帶 source zone 的 EDNS0 option code，須落在 IANA local/experimental 區間 `65001`–`65534`，且與 agent 端設定一致。 |
| `ttl` | 選填，預設 `30` | 跨 zone 答案（gateway 位址）的 TTL 秒數。 |
| `gateway` | 選填，可重複；語法 `gateway <zone> <address>` | zone 到 gateway VIP 的對照。同一個 zone 重複宣告會被拒絕（不是「後面覆蓋前面」）。 |

## 必要的告警

以下 metric 定義於 `plugin/zonedns/metrics.go`，皆以 `coredns_zonedns_` 為字首
（CoreDNS 的 metrics namespace 是 `coredns`，subsystem 是 `zonedns`）。

| Metric | 條件 | 意義 |
|---|---|---|
| `coredns_zonedns_source_zone_total{reason="unauthorized_agent"}` | 任何非零增長 | 有未授權的來源在宣告 zone，這是攻擊訊號 |
| `coredns_zonedns_decision_total{action="servfail"}` | 任何非零增長 | 某個 zone 缺 gateway 設定 |
| `coredns_zonedns_registry_conflicts` | > 0 | 有 FQDN 被宣告成多個 zone，這些名字目前不可解析 |
| `coredns_zonedns_registry_ready` | == 0 持續超過一個 `poll_interval` | registry 未載入，全部查詢退回非 zone-aware |
| `coredns_zonedns_registry_poll_errors` | > 0 | 連續輪詢 SPIRE Entry API 失敗（admin SVID 過期、`admin: true` 被收回、網路分斷…）。Store 會沿用上一份快照，`registry_ready` 與 `registry_names` 都不會變 —— 這是這種失效唯一會動的 metric，新註冊或改 zone 的名稱會持續查不到而靜默走非 zone-aware 路徑，直到輪詢恢復 |
| `coredns_zonedns_source_zone_total{reason="no_tls"}` | 遷移完成後仍持續增長 | 有 client 沒走 mTLS 路徑 |

`coredns_zonedns_registry_names`（目前可解析的名稱數）雖非告警項，掉到 0 或
異常驟降也值得留意，通常代表 SPIRE Server 端的 entry 大量消失。

## 不可回頭的前提

central 與各節點 agent 之間的路徑上**不得有任何終結 TLS 的設備**（L7 ingress、
反向代理、TLS 終結負載平衡器）。若有，central 看到的 client 憑證會是該設備的，
`authorized_agent` 比對會失敗或誤中，而**查詢仍會正常得到答案** —— 失效完全無聲
（設計文件 §11 第 3 項）。

這一點應以測試持續驗證：定期以非授權憑證發出查詢，確認 zone 宣告確實被忽略
（即回應為非 zone-aware 的一般答案，而不是 SERVFAIL 或連線層級的拒絕 ——
`identity` 把「未授權」與「沒有憑證」都當成同一種退路處理，這是設計上刻意的
fail-safe，見設計文件 §6.1，但也代表這個檢查沒辦法只靠「查詢有沒有失敗」來做，
必須實際比對回應內容）。

# zonedns 節點端（agent）部署

`plugin/zonedns_agent` 判定發問 workload 的 zone、以 `(qname, qtype, zone)` 為
key 快取答案，並以 mTLS DoH 向 central 宣告 zone。跟 central 一樣是 external
CoreDNS plugin，必須編譯進 binary；不同的是它編譯進的不是普通 CoreDNS，而是
`sigs.k8s.io/node-local-dns`（NodeLocal DNSCache，本質上也是 CoreDNS）。

**這份文件的份量不是意外。** 這個系統幾乎每一種失效模式都會回一個看起來正常
的答案，而不是報錯 —— 設定錯了不會自己喊出來。以下每一節都在回答同一個問題：
哪一種設定錯誤會讓 zone 隔離安靜地失效。

## 建置

1. 取得 `sigs.k8s.io/node-local-dns` 原始碼。
2. 在 `cmd/node-cache/main.go` 的 blank import 區塊加入：

   ```go
   _ "github.com/jenting/zonedns/plugin/zonedns_agent"
   ```

3. 把 `"zonedns_agent"` 插進 `dnsserver.Directives`，**位置必須在 `"cache"`
   之前**。跟 central 端的 `CheckDirectiveOrder` 是同一種保護、同一個理由：
   node-local-dns 內建的 `cache` plugin 以 `(qname, qtype)` 為 key，不含發問者
   的 zone；若它排在前面，zone-a 的 pod 問過之後，zone-b 的 pod 會拿到同一份
   答案，而且執行期沒有任何徵兆。`setup()` 一啟動就會呼叫
   `CheckDirectiveOrder(dnsserver.Directives)`，順序錯誤會直接拒絕啟動而不是
   靜默接受（見 `plugin/zonedns_agent/setup.go`）。
4. 用 `sigs.k8s.io/node-local-dns` 既有的 `Makefile` 與 `Dockerfile.node-cache`
   建置 —— 部署形態完全沿用該專案的產物，不需要另外自建 CI/CD 管線。

## image 體積

上游的 `node-local-dns` 只相依 `k8s.io/apimachinery`，不含 `client-go`。
`zonedns_agent` 的 k8s 模式（`internal/podzone`）需要 `client-go` 建立本機
pod 的 node-scoped informer，因此自建 image 會明顯大於上游版本 —— 這是預期
之內的取捨，不是建置設定出錯的徵兆。VM 模式在執行期完全不會用到
`client-go`（見下方 Corefile），但因為 binary 是同一份，image 體積的差異
在兩種模式下都存在。

## 版本 pinning

`go.mod` 把 k8s 相關套件（`k8s.io/api`、`k8s.io/apimachinery`、
`k8s.io/client-go`）釘在 `v0.35.4`、`go` 指令釘在 `1.25.0`，刻意跟
`sigs.k8s.io/node-local-dns` 上游用的版本完全一致，**不是**跟著這個 repo 自己
的步調升級。往前推進任一個都會弄壞這個 plugin 存在的目的所要編譯進去的那個
專案：

- `go` 指令若領先上游，會要求一個比上游 `node-local-dns` 建置環境更新的
  Go toolchain；上游的建置腳本、CI image 未必配得起。
- k8s 函式庫若領先上游，等於把上游自己相依的那份 Kubernetes 函式庫一併往前
  拖，而那份函式庫底下還壓著 `k8s.io/kubernetes` 本身的版本相容性約束 ——
  這不是這個 repo 能單方面決定的事。

升級這三個版本前，先確認 `sigs.k8s.io/node-local-dns` 上游本身已經升級到
對應版本，而不是反過來。

## DaemonSet 的變更

部署形態（DaemonSet、每節點一份、link-local 位址、iptables 規則、pod 的
`resolv.conf`）完全不變 —— 這是 §7 開頭就承諾的：新增 zone 時節點不需任何
變更，換成 zone-aware image 也一樣不動既有拓樸。需要變更的只有三處：

1. **`image`** 指向前面建置出來的自建 registry。
2. **RBAC** 加上 pods 的 `get`/`list`/`watch`（見下方）。
3. **Corefile ConfigMap** 加一個新的 server block（見下方），其餘既有的
   `cluster.local:53`、`.:53` 區塊不動。

## Corefile

跟 central 端一樣，`zonedns_agent` 只負責參與 zone 路由的網域，放在獨立的
server block；node-local-dns 既有的 cluster-internal 解析與預設 forward 完全
不受影響。

### k8s 模式

```
cluster.local:53 { ... 既有設定完全不動 ... }

example.com:53 {
    zonedns_agent {
        mode              k8s
        node_name         {$NODE_NAME}
        zone_label        zone
        upstream          https://central.example.org:8443
        central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
        workload_api      unix:///run/spire/sockets/agent.sock
        cache_size        4096
    }
}

.:53 { ... 既有 cache + forward 完全不動 ... }
```

`{$NODE_NAME}` 由 downward API 注入的環境變數展開（`spec.nodeName`）。

### VM 模式

```
example.com:53 {
    zonedns_agent {
        mode              vm
        zone              zone-c
        upstream          https://central.example.org:8443
        central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
        workload_api      unix:///run/spire/sockets/agent.sock
        cache_size        4096
    }
}
```

VM 模式不需要 `node_name` 與 `zone_label`（沒有 per-query 判斷，整台機器一個
zone），改用 `zone` 直接指定。

### `zonedns_agent` 區塊的設定項

以下是 `plugin/zonedns_agent/setup.go` 的 `parseConfig` 實際支援、且僅支援的
選項；沒有列出的名字會被直接拒絕。

| 選項 | 必要性 | 說明 |
|---|---|---|
| `mode` | **必要**，`k8s` 或 `vm` | 決定用哪一種 `ZoneResolver`。其他值直接拒絕。 |
| `upstream` | **必要** | central 的位址，**不含路徑**。DoH 路徑固定是 `/dns-query`，由 CoreDNS 的 doh 套件自動接上；若自己寫進去，實際請求會變成 `/dns-query/dns-query`，central 回 HTTP 404，而 agent 端只看得到「上游回 404」，指不到原因 —— 因此帶路徑的值會在啟動時被拒絕。必須是 `https://` URL。純 `http://` 會在啟動時被拒絕 —— 不是風格偏好：走純文字傳輸時，`http.Transport` 的 `TLSClientConfig` 根本不會被用上，`central_spiffe_id` 的 SPIFFE pin 形同虛設，而且不會有任何錯誤或警告，查詢照常送出去。 |
| `central_spiffe_id` | **必要，無預設值** | 少了它，信任域內任何一張 SVID 都能冒充 central，而 agent 對收到的答案沒有任何獨立查核手段，會完整採信。 |
| `workload_api` | **必要** | agent 自己的 SPIRE Workload API socket，取得出示給 central 的 SVID。 |
| `zone` | `vm` 模式**必要** | 該 VM 所屬的 zone；必須通過 `ednszone.Valid`（字母、數字、`-`、`_`，長度不超過 63 bytes），否則 central 會靜默忽略這台 VM 的 zone 宣告。 |
| `node_name` | `k8s` 模式**必要** | 由 downward API 注入，`podzone.Watcher` 用它把 pod watch 過濾到本節點。 |
| `zone_label` | 選填，預設 `zone` | 讀取 pod 上哪一個 label 當作 zone；必須跟 SPIRE 的 `spiffeIDTemplate` 讀的是同一個 label（見 central 部署一節），否則節點端判定的 zone 會跟 registry 裡的 zone 對不上。 |
| `cache_size` | 選填，預設 `4096` | zone-aware 快取的筆數上限；必須是正整數。 |
| `node_ip` | 選填，也可用 `NODE_IP` 環境變數 | 本機節點自己的位址，僅用於偵測 masquerade（source IP 等於節點 IP 時無法判斷是哪個 workload 在問）。**兩個來源中任一個若給了格式錯誤的值，都是啟動失敗，不是被靜默忽略** —— 這個位址是 masquerade 偵測唯一的依據，DaemonSet manifest 裡打錯一個字元若被吞掉，就會沒有任何記錄地讓這個訊號永遠不動。Corefile 的 `node_ip` 優先於環境變數（後解析）。 |
| `edns0_code` | 選填，預設 `65001` | agent/central 之間攜帶 source zone 的 EDNS0 option code，須落在 IANA local/experimental 區間 `65001`–`65534`，驗證規則與 central 端的 `edns0_code`（見本文件前段）完全一致。**必須與 central Corefile 的 `edns0_code` 相同**，見下一節。 |

`central_spiffe_id`、`workload_api`、`cache_size` 在 k8s／vm 兩種模式下語意相同，
不隨模式改變。

## RBAC

k8s 模式需要的最小權限：

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: zonedns-agent
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]
```

繫結給 node-local-dns DaemonSet 使用的 ServiceAccount。VM 模式不需要這份
RBAC —— `NewStaticResolver` 不接觸 Kubernetes API。

## 必要的告警

以下 metric 定義於 `plugin/zonedns_agent/metrics.go`，皆以
`coredns_zonedns_agent_` 為字首（CoreDNS 的 metrics namespace 是 `coredns`，
subsystem 是 `zonedns_agent`）。

| Metric | 條件 | 意義 |
|---|---|---|
| `coredns_zonedns_agent_zone_resolution_total{result="node_ip"}` | 任何非零增長 | 查詢的 source IP 等於節點自己的 IP：節點上有東西在做 SNAT/masquerade 改寫來源位址，或這是一個 hostNetwork workload。兩種情況都無法判斷是哪個 workload 在問，整個節點會靜默退化成不宣告 zone |
| `coredns_zonedns_agent_zone_resolution_total{result="unknown"}` | 持續增長 | 有 pod 沒有 zone label，或本機 informer 落後於 pod 建立（k8s 模式）|
| `coredns_zonedns_agent_resolver_ready` | `== 0` 超過一個啟動週期 | pod watcher 尚未完成初次同步，所有查詢都不宣告 zone（VM 模式一律是 1，不適用） |
| `coredns_zonedns_agent_upstream_errors_total` | 任何非零增長 | 對 central 的 DoH exchange 失敗；查詢會回 SERVFAIL 而不是交給下一個 plugin（本 plugin 沒有下一個 plugin 可交） |
| `coredns_zonedns_agent_cache_total{result="miss"}` | 佔比異常高 | 快取容量（`cache_size`）不足，或 central 給的 TTL 過短，導致大部分查詢都要繞去問一次 central |

`coredns_zonedns_agent_zone_resolution_total{result="bad_source"}` 與
`{result="ok"}` 不是告警項，但排查時有用：`bad_source` 代表拿到的 source IP
無法解析（幾乎不該發生），`ok` 是正常判定成功的計數，可以拿來對照
`unknown`／`node_ip` 的比例是否異常。

## 兩端必須成對維護的設定

zone 路由的信任關係是雙向釘住的，兩邊都要改，改一邊就會有一邊靜默停止運作：

- **agent → central**：agent 出示給 central 的 SVID，其 SPIFFE ID 必須出現在
  central Corefile 的 `authorized_agent` 清單中（見本文件前段）。若不在清單
  裡，central 會忽略這個 agent 宣告的所有 zone，查詢一律走非 zone-aware 路徑
  —— 不會拒絕連線，`coredns_zonedns_source_zone_total{reason="unauthorized_agent"}`
  才是唯一會動的訊號。
- **central → agent**：central 自己的 SPIFFE ID 必須填在 agent Corefile 的
  `central_spiffe_id`。這一項本來就是啟動時的必填項，不會出現「忘了填」的
  情況，但若填的 SPIFFE ID 跟 central 實際出示的 SVID 不一致（例如 central
  換了憑證但這裡沒同步更新），mTLS 握手會直接失敗，`upstream_errors_total`
  上升、查詢回 SERVFAIL —— 這一側的失效不是靜默的，因為 `AuthorizeID` 拒絕連線
  本身就是可觀測事件。
- **agent ↔ central 的 `edns0_code`**：兩端 Corefile 的 `edns0_code` 必須是
  同一個值。兩邊都有各自的預設值 `65001`，只要都不改就自動一致；一旦其中一端
  被改成非預設值而另一端沒有同步，agent 會繼續在它自己的 code 上寫入 zone，
  但 central 端的 `ednszone.Get` 讀的是另一個 code，等於「沒有這個 option」——
  查詢仍然「正常」回應，只是每一筆都回退到非 zone-aware 的一般答案，
  且沒有任何一端的啟動流程能偵測出這個不一致（兩個值各自都通過各自的
  範圍檢查）。改動任一端的 `edns0_code` 之前，先確認另一端會同時改。

新增一個節點時，記得把它的 SPIFFE ID（由 SPIRE registration entry 決定，見
central 部署一節）加進 `authorized_agent`；除役一個節點時記得從清單移除，
否則舊節點的憑證只要還沒過期就仍是有效的授權來源。
