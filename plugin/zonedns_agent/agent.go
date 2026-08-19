// Package zonedns_agent 是 zone-based DNS 的節點端 CoreDNS plugin。
//
// 它判定發問 workload 的 zone，以該 zone 為快取 key 的一部分，並在向 central 查詢
// 時把 zone 宣告在 EDNS0 option 裡。它只負責參與 zone 路由的網域（由 Corefile 的
// server block 界定），其餘查詢完全不經過它。
package zonedns_agent

import (
	"context"
	"net/netip"
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
		cached.SetReply(r)
		if err := w.WriteMsg(cached); err != nil {
			log.Warningf("write cached reply for %q: %v", state.Name(), err)
		}
		return dns.RcodeSuccess, nil
	}
	cacheTotal.WithLabelValues("miss").Inc()

	outbound := r.Copy()
	if haveZone {
		ednszone.Set(outbound, a.EDNS0Code, zone)
	}

	answer, err := a.Upstream.Exchange(ctx, outbound)
	if err != nil {
		upstreamErrorsTotal.Inc()
		log.Errorf("upstream exchange for %q failed: %v", state.Name(), err)
		return dns.RcodeServerFailure, nil
	}

	a.Cache.Put(state.Name(), state.QType(), zone, answer, now)

	answer.SetReply(r)
	if err := w.WriteMsg(answer); err != nil {
		log.Warningf("write reply for %q: %v", state.Name(), err)
	}
	return dns.RcodeSuccess, nil
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
