# zonedns 節點端 Kubernetes 部署

這裡是 node-local-dns 加上 `zonedns_agent` 的完整 manifest。中心端（`zonedns`）
不在這裡 —— 它部署在 VM 上，見 `docs/deployment.md`。

## 套用順序

```bash
kubectl apply -f 01-rbac.yaml
kubectl apply -f 02-configmap.yaml
kubectl apply -f 03-daemonset.yaml
kubectl apply -f 04-clusterspiffeid.yaml   # 需要 spire-controller-manager 的 CRD
```

## 必須替換的值

manifest 裡刻意留下需要按環境替換的地方，全部集中在這張表。

| 檔案 | 位置 | 換成什麼 |
|---|---|---|
| `02-configmap.yaml` | `example.com:53 {` | 你們 VirtualService `hosts:` 實際使用的網域。只有落在這個 block 的查詢會走 zone 路由 |
| `02-configmap.yaml` | `upstream` | central 的位址，**不含路徑** |
| `02-configmap.yaml` | `central_spiffe_id` | central 自己的 SPIFFE ID |
| `02-configmap.yaml` | `workload_api` | SPIRE agent 在節點上暴露 socket 的路徑 |
| `02-configmap.yaml` | `zone_label` | 若不是 `zone` |
| `03-daemonset.yaml` | `image` | 自建 image（見下） |
| `03-daemonset.yaml` | `spire-agent-socket` 的 `hostPath` | 同 `workload_api`，兩處必須一致 |
| `04-clusterspiffeid.yaml` | 兩個 `spiffeIDTemplate` 的 trust domain | 你們的 trust domain |

`__PILLAR__*` 佔位符照上游慣例保留，由你們既有的 node-local-dns 安裝流程替換。
若你們是直接 apply 已替換好的版本，把它們換成實際值即可。

## 自建 image

上游的 `k8s-dns-node-cache` 不含 `zonedns_agent` —— CoreDNS 的 plugin 是編譯期
連結的，沒有執行期載入機制。建置步驟見 `docs/deployment.md`「節點端（agent）部署 →
建置」。

要點：把 `zonedns_agent` 插進 `plugin.cfg` 時**必須排在 `cache` 之前**，否則
plugin 啟動時會直接拒絕啟動並說明原因。

## 這份 manifest 相對上游改了什麼

只有三處，其餘完全照 `kubernetes/kubernetes` 的
`cluster/addons/dns/nodelocaldns/nodelocaldns.yaml`：

1. **image** 指向自建版本
2. **RBAC**：上游的 ServiceAccount 沒有任何權限；這裡加上 pods 的
   `get`/`list`/`watch`，供 informer 把查詢的 source IP 對應到 pod 的 zone label
3. **DaemonSet 多兩個掛載與兩個環境變數**：SPIRE 的 Workload API socket，以及
   `NODE_NAME`、`NODE_IP`

上游原本就有、一項都不能省的：`hostNetwork`、`dnsPolicy: Default`、
`priorityClassName`、`-localip` 的兩個位址、`xtables-lock` 掛載、`NET_ADMIN`
capability、涵蓋所有 taint 的 tolerations。這些跟 zone 路由無關，是 node-local-dns
管理 dummy interface 與 iptables 規則所需要的。

## 兩端必須成對維護的設定

任一邊漏掉，zone 路由都會**靜默停止運作** —— 查詢照常有答案，只是不再分 zone。

- `04-clusterspiffeid.yaml` 產生的節點 SPIFFE ID，必須逐字出現在 central Corefile
  的 `authorized_agent` 清單
- central 的 SPIFFE ID，必須是本地 Corefile 的 `central_spiffe_id`
- 兩端的 `edns0_code` 必須相同
- 本地的 `zone_label` 必須跟 `04-clusterspiffeid.yaml` 的 `spiffeIDTemplate`
  讀的是同一個 label

## 驗證

RBAC 是否生效：

```bash
kubectl auth can-i list pods \
  --as=system:serviceaccount:kube-system:node-local-dns
```

zone 判定是否正常（在任一節點上）：

```bash
kubectl -n kube-system exec ds/node-local-dns -- \
  wget -qO- http://127.0.0.1:9253/metrics | grep zonedns_agent
```

`zone_resolution_total{result="node_ip"}` 有非零增長，代表節點上有東西在改寫
查詢的 source IP，整個節點會靜默退化成不宣告 zone。完整的告警清單見
`docs/deployment.md`。

## 已知限制

- **RBAC 無法限縮到單一節點。** informer 以 `spec.nodeName` 過濾，實際只讀本機
  的數十個 pod，但授予的權限是全 cluster 的 pod 讀取權。導入前值得讓安全審查
  知道這一點。
- **hostNetwork 的 pod 無法被辨識。** 它們的 source IP 就是節點 IP，同節點上所有
  hostNetwork pod 共用，因此一律退到非 zone-aware 路徑（spec §9 已知限制 4）。
- **一個 workload 只能有一個對外 FQDN**（spec §9 已知限制 1）。
