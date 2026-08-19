// Package zonedns 是 zone-based DNS 的中心端 CoreDNS plugin。
//
// 它依查詢者的 zone（由 node-local agent 經 mTLS + EDNS0 宣告）與被查詢名稱所屬的
// zone（來自 SPIRE registration entry）決定回應：同 zone 交給下游回一般答案，
// 跨 zone 則回該 zone 的 gateway VIP。
//
// 只有「跨 zone 且 gateway 已設定」這一種情況會改變答案，其餘一律不介入 ——
// 這讓匯入本 plugin 的影響面盡可能小。
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

// ZoneDNS 是 plugin 的處理器。
type ZoneDNS struct {
	Next     plugin.Handler
	Identity identity.Config
	Registry *registry.Store
	Zones    *zonetable.Table
	TTL      uint32
}

// Name 實作 plugin.Handler。
func (z ZoneDNS) Name() string { return "zonedns" }

// ServeDNS 實作 plugin.Handler。
func (z ZoneDNS) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	// 只處理位址查詢。SRV、TXT 等一律交給下游 —— 本 plugin 沒有能力為它們產生
	// 有意義的跨 zone 答案。
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

// answerGateway 以 gateway VIP 回應。
//
// gateway 是 IPv4 而查詢是 AAAA（或反之）時回 NODATA（NOERROR + 空 answer），
// 讓 client 正常退回另一種位址族。回 NXDOMAIN 會讓 client 認為整個名字不存在，
// 連 A 查詢也一併放棄。
func (z ZoneDNS) answerGateway(state request.Request, gw string) (int, error) {
	ip := net.ParseIP(gw)
	isV4 := ip.To4() != nil

	m := new(dns.Msg)
	m.SetReply(state.Req)
	m.Authoritative = true
	// 查詢一定帶 OPT record — 它是攜帶 zone 宣告的 EDNS0 option 所在，走到這裡
	// 代表宣告已經讀出來了。SizeAndDo 依請求的 OPT 在回應上補回對應的 OPT
	// record；漏了這一步會讓每個 gateway 答案都變成對一個帶 EDNS0 查詢的
	// 非 EDNS 回應，部分 resolver 會視為格式錯誤而重試或報錯。
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
