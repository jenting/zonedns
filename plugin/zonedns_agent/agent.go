// Package zonedns_agent is the node-side CoreDNS plugin for zone-based DNS.
//
// It determines the asking workload's zone, makes that zone part of the cache
// key, and declares it in an EDNS0 option when querying central. It handles only
// the domains that take part in zone routing, as delimited by the Corefile's
// server block; every other query bypasses it entirely.
package zonedns_agent

import (
	"context"
	"net/netip"
	"strings"
	"time"

	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/jenting/zonedns/internal/ednszone"
	"github.com/jenting/zonedns/internal/zonecache"
	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin("zonedns_agent")

// timeNow lets tests control how cache expiry is judged.
var timeNow = time.Now

// Upstream sends queries to central.
type Upstream interface {
	Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error)
}

// Agent is the plugin's handler.
type Agent struct {
	Resolver  ZoneResolver
	Cache     *zonecache.Cache
	Upstream  Upstream
	EDNS0Code uint16

	// NodeIP is this node's own address, used only to detect masquerading. A query
	// whose source IP equals it had its pod IP rewritten along the way.
	NodeIP netip.Addr
}

// Name implements plugin.Handler.
func (a Agent) Name() string { return "zonedns_agent" }

// ServeDNS implements plugin.Handler.
func (a Agent) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	zone, haveZone := a.resolveZone(state.IP())

	now := timeNow()
	if cached, ok := a.Cache.Get(state.Name(), state.QType(), zone, now); ok {
		cacheTotal.WithLabelValues("hit").Inc()
		// SetReply forces Rcode to RcodeSuccess; the cached message's own Rcode
		// (e.g. a stored NXDOMAIN/SERVFAIL) must reach the client unchanged.
		rcode := cached.Rcode
		cached.SetReply(r)
		cached.Rcode = rcode
		if err := w.WriteMsg(cached); err != nil {
			log.Warningf("write cached reply for %q: %v", state.Name(), err)
		}
		return dns.RcodeSuccess, nil
	}
	cacheTotal.WithLabelValues("miss").Inc()

	outbound := r.Copy()
	// Strip any zone declaration the client itself attached, unconditionally
	// and before deciding whether to declare one. Central trusts whatever
	// this agent forwards; a client-supplied option under EDNS0Code must
	// never survive, whether or not the agent has a zone of its own to
	// assert.
	stripZoneOption(outbound, a.EDNS0Code)
	if haveZone {
		ednszone.Set(outbound, a.EDNS0Code, zone)
	}

	answer, err := a.Upstream.Exchange(ctx, outbound)
	if err != nil {
		upstreamErrorsTotal.Inc()
		log.Errorf("upstream exchange for %q failed: %v", state.Name(), err)
		return dns.RcodeServerFailure, nil
	}
	// central's identity is pinned by mTLS (see dohupstream), but that pins
	// *who* answered, not *what* they answered. A bug on central (e.g. a
	// pipelining/correlation mistake that hands back another query's reply)
	// would otherwise be forwarded, cached, and served as a well-formed
	// answer to a question nobody asked. Treat it exactly like any other
	// upstream failure rather than trusting content the agent has no
	// independent way to verify.
	if !answersQuestion(outbound, answer) {
		upstreamErrorsTotal.Inc()
		log.Errorf("upstream reply for %q did not answer the question that was asked (got %v)", state.Name(), answer.Question)
		return dns.RcodeServerFailure, nil
	}

	a.Cache.Put(state.Name(), state.QType(), zone, answer, now)

	// See the cache-hit path above: preserve the upstream's own Rcode across
	// SetReply so an in-band NXDOMAIN/SERVFAIL isn't rewritten to NOERROR.
	rcode := answer.Rcode
	answer.SetReply(r)
	answer.Rcode = rcode
	if err := w.WriteMsg(answer); err != nil {
		log.Warningf("write reply for %q: %v", state.Name(), err)
	}
	return dns.RcodeSuccess, nil
}

// stripZoneOption removes any existing EDNS0 local option under code from m,
// without creating an OPT record if none exists. The zone declaration sent
// to central must originate from this agent's own determination or not
// exist at all — never from whatever the client happened to attach to its
// query.
func stripZoneOption(m *dns.Msg, code uint16) {
	opt := m.IsEdns0()
	if opt == nil {
		return
	}
	kept := opt.Option[:0]
	for _, o := range opt.Option {
		if l, isLocal := o.(*dns.EDNS0_LOCAL); isLocal && l.Code == code {
			continue
		}
		kept = append(kept, o)
	}
	opt.Option = kept
}

// answersQuestion reports whether an answer's Question section corresponds
// exactly to the query that went out: the same qname (case-insensitively, as DNS
// names are), the same qtype, the same qclass. Central's identity is already
// pinned by mTLS (see dohupstream), but that guarantees only who answered, not
// that what came back answers this question.
func answersQuestion(outbound, answer *dns.Msg) bool {
	if len(answer.Question) != len(outbound.Question) {
		return false
	}
	for i, q := range outbound.Question {
		a := answer.Question[i]
		if !strings.EqualFold(q.Name, a.Name) || q.Qtype != a.Qtype || q.Qclass != a.Qclass {
			return false
		}
	}
	return true
}

// resolveZone determines the source's zone and records the outcome.
//
// An unrecognised source returns ok=false, and the caller forwards as usual
// without declaring a zone. This is deliberate: central takes the non-zone-aware
// path for an undeclared query and returns the ordinary answer, and given that
// zones are network-isolated, that answer is either usable or unreachable —
// either of which beats guessing the wrong zone and sending traffic to the wrong
// gateway.
func (a Agent) resolveZone(srcIP string) (string, bool) {
	src, err := netip.ParseAddr(srcIP)
	if err != nil {
		zoneResolutionTotal.WithLabelValues("bad_source").Inc()
		return "", false
	}
	if a.NodeIP.IsValid() && src == a.NodeIP {
		// Either something on the node is rewriting the source IP, or this is a
		// hostNetwork workload. In neither case can we tell which workload is
		// asking.
		zoneResolutionTotal.WithLabelValues("node_ip").Inc()
		return "", false
	}

	zone, ok := a.Resolver.Zone(src)
	if !ok {
		zoneResolutionTotal.WithLabelValues("unknown").Inc()
		return "", false
	}
	zoneResolutionTotal.WithLabelValues("ok").Inc()
	return zone, true
}
