package zonedns_agent

import (
	"github.com/coredns/coredns/plugin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// zoneResolutionTotal 依判定結果分類。
	//
	// result="node_ip" 是最重要的一個：它表示查詢的 source IP 就是節點自己的 IP。
	// 正常情況下 pod 的查詢帶著 pod IP 抵達（node-local DNS 走 link-local 位址，
	// 不經 DNAT），所以這個數字跳升代表節點上有東西在做 SNAT/masquerade，而那會
	// 讓整個節點退化成單一 zone —— 靜默地。
	zoneResolutionTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns_agent",
		Name:      "zone_resolution_total",
		Help:      "Count of source zone resolution attempts by outcome.",
	}, []string{"result"})

	// cacheTotal 區分命中與未命中。
	cacheTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns_agent",
		Name:      "cache_total",
		Help:      "Count of zone-aware cache lookups by outcome.",
	}, []string{"result"})

	// upstreamErrorsTotal 記錄對 central 的查詢失敗次數。
	upstreamErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns_agent",
		Name:      "upstream_errors_total",
		Help:      "Count of failed DoH exchanges with the central server.",
	})

	// resolverReady 為 0 時所有查詢都不宣告 zone。
	resolverReady = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns_agent",
		Name:      "resolver_ready",
		Help:      "1 when the zone resolver has loaded its data, 0 otherwise.",
	})
)
