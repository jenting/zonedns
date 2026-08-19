package zonedns

import (
	"github.com/coredns/coredns/plugin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// sourceZoneTotal 依判定結果分類。reason="unauthorized_agent" 是攻擊訊號，
	// 應設定告警；reason="no_tls" 在遷移期間是正常的。
	sourceZoneTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns",
		Name:      "source_zone_total",
		Help:      "Count of source zone resolution attempts by outcome.",
	}, []string{"reason"})

	// decisionTotal 依動作分類。action="servfail" 表示設定漏了某個 zone 的
	// gateway，應設定告警。
	decisionTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns",
		Name:      "decision_total",
		Help:      "Count of routing decisions by action.",
	}, []string{"action"})

	// registryNames 是目前可解析的名稱數。掉到 0 表示 registry 出問題。
	registryNames = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns",
		Name:      "registry_names",
		Help:      "Number of resolvable names in the current registry snapshot.",
	})

	// registryConflicts 是因 zone 衝突而不可解析的名稱數。非 0 即為設定問題。
	registryConflicts = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns",
		Name:      "registry_conflicts",
		Help:      "Number of names removed due to conflicting zone declarations.",
	})

	// registryReady 為 0 時所有查詢都走非 zone-aware 路徑。
	registryReady = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns",
		Name:      "registry_ready",
		Help:      "1 when a registry snapshot is loaded, 0 otherwise.",
	})

	// registryPollErrors 是連續輪詢失敗次數（見 registry.Poller.ConsecutivePollErrors）。
	// 失敗時 Store 沿用上一份快照，registryReady 與 registryNames 都不會變 ——
	// 這是 SPIRE 變得不可達（admin SVID 過期、admin 權限被收回、網路分斷）時
	// 唯一會動的 metric，非 0 即應告警，見 spec §6.2。
	registryPollErrors = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns",
		Name:      "registry_poll_errors",
		Help:      "Consecutive SPIRE Entry API poll failures. Non-zero means the registry snapshot is stale.",
	})
)
