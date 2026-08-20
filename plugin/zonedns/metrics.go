package zonedns

import (
	"github.com/coredns/coredns/plugin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// sourceZoneTotal is broken down by verdict. reason="unauthorized_agent" is an
	// attack signal and should be alerted on; reason="no_tls" is normal during a
	// migration.
	sourceZoneTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns",
		Name:      "source_zone_total",
		Help:      "Count of source zone resolution attempts by outcome.",
	}, []string{"reason"})

	// decisionTotal is broken down by action. action="servfail" means the config is
	// missing a gateway for some zone and should be alerted on.
	decisionTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns",
		Name:      "decision_total",
		Help:      "Count of routing decisions by action.",
	}, []string{"action"})

	// registryNames is the number of currently resolvable names. Dropping to 0
	// means something is wrong with the registry.
	registryNames = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns",
		Name:      "registry_names",
		Help:      "Number of resolvable names in the current registry snapshot.",
	})

	// registryConflicts is the number of names left unresolvable by a zone
	// conflict. Anything but 0 is a configuration problem.
	registryConflicts = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns",
		Name:      "registry_conflicts",
		Help:      "Number of names removed due to conflicting zone declarations.",
	})

	// While registryReady is 0, every query takes the non-zone-aware path.
	registryReady = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns",
		Name:      "registry_ready",
		Help:      "1 when a registry snapshot is loaded, 0 otherwise.",
	})

	// registryPollErrors counts consecutive polling failures (see
	// registry.Poller.ConsecutivePollErrors). On failure the Store keeps the
	// previous snapshot, so neither registryReady nor registryNames changes — this
	// is the only metric that moves when SPIRE becomes unreachable (an expired
	// admin SVID, admin rights revoked, a network partition). Anything but 0 should
	// be alerted on; see spec §6.2.
	registryPollErrors = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns",
		Name:      "registry_poll_errors",
		Help:      "Consecutive SPIRE Entry API poll failures. Non-zero means the registry snapshot is stale.",
	})
)
