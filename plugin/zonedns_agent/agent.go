// Package zonedns_agent 是 zone-based DNS 的節點端 CoreDNS plugin。
//
// 它判定發問 workload 的 zone，以該 zone 為快取 key 的一部分，並在向 central 查詢
// 時把 zone 宣告在 EDNS0 option 裡。它只負責參與 zone 路由的網域（由 Corefile 的
// server block 界定），其餘查詢完全不經過它。
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

// timeNow 讓快取的過期判斷可在測試中控制。
var timeNow = time.Now

// Upstream 對 central 發送查詢。
type Upstream interface {
	Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error)
}

// Agent 是 plugin 的處理器。
type Agent struct {
	Resolver  ZoneResolver
	Cache     *zonecache.Cache
	Upstream  Upstream
	EDNS0Code uint16

	// NodeIP 是本機節點的位址，只用於偵測 masquerade。查詢的 source IP 等於它，
	// 代表 pod IP 在途中被改寫了。
	NodeIP netip.Addr
}

// Name 實作 plugin.Handler。
func (a Agent) Name() string { return "zonedns_agent" }

// ServeDNS 實作 plugin.Handler。
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

// answersQuestion 回報 answer 的 Question section 是否恰好對應到 outbound 送出的
// 那個查詢 —— 同一個 qname（大小寫不敏感，DNS 名稱本來就不分大小寫）、同一個
// qtype、同一個 qclass。central 的身分已經由 mTLS 釘住（見 dohupstream），但那
// 只保證「是誰回的」，不保證「回的是不是這一題」。
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

// resolveZone 判定來源的 zone 並記錄結果。
//
// 認不出來源時回 ok=false，呼叫端會照常轉發但不宣告 zone。這是刻意的：central 對
// 沒有宣告的查詢會走非 zone-aware 路徑並回一般答案，而在 zone 之間網路隔離的前提
// 下，那個答案要嘛可用、要嘛連不上 —— 都比猜錯 zone 把流量導向錯誤的 gateway 好。
func (a Agent) resolveZone(srcIP string) (string, bool) {
	src, err := netip.ParseAddr(srcIP)
	if err != nil {
		zoneResolutionTotal.WithLabelValues("bad_source").Inc()
		return "", false
	}
	if a.NodeIP.IsValid() && src == a.NodeIP {
		// 節點上有東西在改寫 source IP，或這是一個 hostNetwork 的 workload。
		// 兩種情況都無法分辨是哪個 workload 在問。
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
