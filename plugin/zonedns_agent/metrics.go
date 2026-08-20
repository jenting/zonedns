package zonedns_agent

import (
	"github.com/coredns/coredns/plugin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// zoneResolutionTotal is broken down by outcome.
	//
	// result="node_ip" is the one that matters most: it means a query's source IP
	// was the node's own. Normally a pod's query arrives carrying the pod IP —
	// node-local DNS uses a link-local address and no DNAT — so a jump in this
	// number means something on the node is doing SNAT or masquerading, which
	// collapses the whole node into a single zone. Silently.
	zoneResolutionTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns_agent",
		Name:      "zone_resolution_total",
		Help:      "Count of source zone resolution attempts by outcome.",
	}, []string{"result"})

	// cacheTotal separates hits from misses.
	cacheTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns_agent",
		Name:      "cache_total",
		Help:      "Count of zone-aware cache lookups by outcome.",
	}, []string{"result"})

	// upstreamErrorsTotal counts failed queries to central.
	upstreamErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns_agent",
		Name:      "upstream_errors_total",
		Help:      "Count of failed DoH exchanges with the central server.",
	})

	// While resolverReady is 0, no query declares a zone.
	resolverReady = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "zonedns_agent",
		Name:      "resolver_ready",
		Help:      "1 when the zone resolver has loaded its data, 0 otherwise.",
	})
)
