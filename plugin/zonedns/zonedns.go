// Package zonedns is the central CoreDNS plugin for zone-based DNS.
//
// It decides the response from the asking workload's zone — declared by the
// node-local agent over mTLS with EDNS0 — and the zone the queried name belongs
// to, which comes from SPIRE registration entries: within a zone it hands the
// query downstream for the ordinary answer, and across zones it answers with that
// zone's gateway VIP.
//
// Only one case changes an answer, cross-zone with a configured gateway;
// everything else passes through untouched, which keeps the blast radius of
// importing this plugin as small as possible.
package zonedns

import (
	"context"
	"net"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
	"github.com/jenting/zonedns/internal/decision"
	"github.com/jenting/zonedns/internal/identity"
	"github.com/jenting/zonedns/internal/registry"
	"github.com/jenting/zonedns/internal/zonetable"
	"github.com/miekg/dns"
)

// ZoneDNS is the plugin's handler.
type ZoneDNS struct {
	Next     plugin.Handler
	Identity identity.Config
	Registry *registry.Store
	Zones    *zonetable.Table
	TTL      uint32
}

// Name implements plugin.Handler.
func (z ZoneDNS) Name() string { return "zonedns" }

// ServeDNS implements plugin.Handler.
func (z ZoneDNS) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	// Address queries only. SRV, TXT and the rest go downstream — this plugin has
	// no way to produce a meaningful cross-zone answer for them.
	if state.QType() != dns.TypeA && state.QType() != dns.TypeAAAA {
		return plugin.NextOrFailure(z.Name(), z.Next, ctx, w, r)
	}

	zone, reason := z.Identity.SourceZone(ctx, w, r)
	sourceZoneTotal.WithLabelValues(reason.String()).Inc()

	destZone, destOK := z.Registry.Lookup(state.Name())

	d := decision.Decide(decision.Input{
		SourceZone: zone,
		SourceOK:   reason == identity.ReasonOK,
		DestZone:   destZone,
		DestOK:     destOK,
	}, z.Zones.Gateway)
	decisionTotal.WithLabelValues(d.Action.String()).Inc()

	switch d.Action {
	case decision.ActionAnswerGateway:
		return z.answerGateway(state, d.Gateway.String())
	case decision.ActionServFail:
		log.Errorf("no gateway configured for zone %q while answering %q; check the zonedns gateway settings",
			destZone, state.Name())
		return dns.RcodeServerFailure, nil
	case decision.ActionPassThrough:
		return plugin.NextOrFailure(z.Name(), z.Next, ctx, w, r)
	default:
		// decision.Decide should never return anything else, but this project's
		// dominant failure mode is fail-open: a future action (e.g. "refuse" or
		// "drop") landing here by mistake must not be silently treated as
		// pass-through without at least a loud, alertable log line.
		log.Errorf("unhandled decision action %q for %q; treating as pass-through", d.Action, state.Name())
		return plugin.NextOrFailure(z.Name(), z.Next, ctx, w, r)
	}
}

// answerGateway responds with the gateway VIP.
//
// When the gateway is IPv4 and the query is AAAA, or the other way round, it
// returns NODATA (NOERROR with an empty answer) so the client falls back to the
// other address family as usual. NXDOMAIN would tell the client the name does not
// exist at all, and it would give up on the A query too.
func (z ZoneDNS) answerGateway(state request.Request, gw string) (int, error) {
	ip := net.ParseIP(gw)
	isV4 := ip.To4() != nil

	m := new(dns.Msg)
	m.SetReply(state.Req)
	m.Authoritative = true
	// The query necessarily carries an OPT record — it is where the EDNS0 option
	// holding the zone declaration lives, and reaching this point means the
	// declaration was read. SizeAndDo puts the corresponding OPT record back on the
	// response based on the request's; skipping it would make every gateway answer
	// a non-EDNS response to an EDNS0 query, which some resolvers treat as a format
	// error and retry or report.
	state.SizeAndDo(m)

	hdr := dns.RR_Header{
		Name:  state.QName(),
		Class: dns.ClassINET,
		Ttl:   z.TTL,
	}

	switch {
	case state.QType() == dns.TypeA && isV4:
		hdr.Rrtype = dns.TypeA
		m.Answer = []dns.RR{&dns.A{Hdr: hdr, A: ip.To4()}}
	case state.QType() == dns.TypeAAAA && !isV4:
		hdr.Rrtype = dns.TypeAAAA
		m.Answer = []dns.RR{&dns.AAAA{Hdr: hdr, AAAA: ip.To16()}}
	}

	if err := state.W.WriteMsg(m); err != nil {
		log.Errorf("write gateway answer for %q: %v", state.QName(), err)
	}
	return dns.RcodeSuccess, nil
}
