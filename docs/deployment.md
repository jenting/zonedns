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
