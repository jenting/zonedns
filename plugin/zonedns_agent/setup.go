package zonedns_agent

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"sync/atomic"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/jenting/zonedns/internal/dohupstream"
	"github.com/jenting/zonedns/internal/ednszone"
	"github.com/jenting/zonedns/internal/podzone"
	"github.com/jenting/zonedns/internal/zonecache"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type mode int

const (
	modeUnset mode = iota
	modeK8s
	modeVM
)

const defaultCacheSize = 4096

func init() { plugin.Register("zonedns_agent", setup) }

type config struct {
	mode            mode
	zone            string // vm 模式
	nodeName        string // k8s 模式
	zoneLabel       string // k8s 模式
	upstreamURL     string
	centralSPIFFEID string
	workloadAPI     string
	cacheSize       int
	edns0Code       uint16
	nodeIP          netip.Addr
}

// CheckDirectiveOrder 確認 zonedns_agent 排在 cache 之前。
//
// 這是正確性要求而非偏好：既有的 cache plugin 以 (qname, qtype) 為 key，不含發問者
// 的 zone。若它排在前面，zone-a 的 pod 問過之後，zone-b 的 pod 會拿到同一份答案 ——
// 而且拿得像模像樣，執行期沒有任何徵兆。順序由編譯期的 plugin.cfg 決定，所以這是
// 建置設定的檢查。
func CheckDirectiveOrder(directives []string) error {
	agentAt, cacheAt := -1, -1
	for i, d := range directives {
		switch d {
		case "zonedns_agent":
			agentAt = i
		case "cache":
			cacheAt = i
		}
	}
	if agentAt < 0 {
		return fmt.Errorf("zonedns_agent is not registered in dnsserver.Directives; add it to plugin.cfg before cache")
	}
	if cacheAt >= 0 && cacheAt < agentAt {
		return fmt.Errorf("zonedns_agent must be ordered before cache in plugin.cfg, but cache is at %d and zonedns_agent at %d; "+
			"with cache first, a pod in one zone would receive an answer cached for another", cacheAt, agentAt)
	}
	return nil
}

// resolverGeneration 為每一次啟動 k8s watcher 配發一個遞增的世代編號；
// resolverReadyGeneration 記錄「最近一次被標成就緒」的是哪個世代。兩者都是
// package 層級、跨越多次 setup() 呼叫共用的狀態。
//
// 理由：reload 期間新舊兩個 watcher 的生命週期會重疊 —— coredns/caddy 的
// Instance.Restart 先把新 instance 完整啟動（含這裡的 c.OnStartup）成功之後，
// 才去呼叫舊 instance 的 Stop 與 OnShutdown。若舊 watcher 因為自己的 ctx 被
// 取消而想把 resolverReady 歸零，這個歸零可能發生在新 watcher 已經同步完成、
// 把 gauge 設成 1 之後 —— 兩個 goroutine 之間沒有任何順序保證，較舊世代的
// 歸零會蓋掉較新世代已經回報的就緒狀態，而且蓋掉之後不會再有任何事件把它
// 修回來（每個 watcher 的 OnReady 只呼叫一次）。世代編號讓「要歸零」的那一刻
// 可以自問「我是不是最後一個真正就緒的世代」，不是的話就什麼都不做。
var (
	resolverGeneration      atomic.Uint64
	resolverReadyGeneration atomic.Uint64
)

// markResolverReady 記錄 gen 這個世代已經同步完成。呼叫端一律可以直接標成
// 就緒，因為 OnReady 只會在真正同步完成時觸發一次，永遠代表目前已知最新的
// 事實 —— 不需要跟任何人比較。
func markResolverReady(gen uint64) {
	resolverReadyGeneration.Store(gen)
	resolverReady.Set(1)
}

// markResolverStopped 記錄 gen 這個世代的 watcher 已經停止。只有在還沒有
// 更新的世代取得就緒狀態時才把 gauge 歸零，理由見 resolverGeneration 上的
// 註解。
func markResolverStopped(gen uint64) {
	if resolverReadyGeneration.Load() == gen {
		resolverReady.Set(0)
	}
}

func setup(c *caddy.Controller) error {
	if err := CheckDirectiveOrder(dnsserver.Directives); err != nil {
		return plugin.Error("zonedns_agent", err)
	}

	cfg, err := parseConfig(c)
	if err != nil {
		return plugin.Error("zonedns_agent", err)
	}

	cache, err := zonecache.New(cfg.cacheSize)
	if err != nil {
		return plugin.Error("zonedns_agent", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	up, cleanup, err := dohupstream.NewMTLS(ctx, dohupstream.Config{
		URL:             cfg.upstreamURL,
		WorkloadAPIAddr: cfg.workloadAPI,
		CentralSPIFFEID: cfg.centralSPIFFEID,
	})
	if err != nil {
		cancel()
		return plugin.Error("zonedns_agent", err)
	}

	var resolver ZoneResolver
	switch cfg.mode {
	case modeVM:
		resolver = NewStaticResolver(cfg.zone)
		// VM 模式沒有非同步的載入階段，解析器一建立就是就緒的。
		resolverReady.Set(1)
	case modeK8s:
		restCfg, err := rest.InClusterConfig()
		if err != nil {
			cancel()
			cleanup()
			return plugin.Error("zonedns_agent", fmt.Errorf("in-cluster config: %w", err))
		}
		client, err := kubernetes.NewForConfig(restCfg)
		if err != nil {
			cancel()
			cleanup()
			return plugin.Error("zonedns_agent", fmt.Errorf("kubernetes client: %w", err))
		}
		w := podzone.New(client, cfg.nodeName, cfg.zoneLabel)
		resolver = w

		// 這裡刻意不把 resolverReady 設成 0：此刻只是「正在解析新的設定」，
		// 舊 instance（如果這是一次 reload）仍在正常回答查詢，把全域共用的
		// gauge 提早歸零會製造一個假的「未就緒」窗口，讓每一次 reload 都觸發
		// resolver_ready==0 的告警，即使服務完全沒有中斷。gauge 維持它原本
		// 的值 —— 冷啟動時是 promauto 給的預設 0，reload 時是舊 instance 留下
		// 的 1 —— 直到下面兩個事件之一真正發生：這個 watcher 同步完成
		// （OnReady）或它被關閉（ctx.Done）。世代編號的用途見上方
		// resolverGeneration 的註解。
		gen := resolverGeneration.Add(1)
		w.OnReady = func() { markResolverReady(gen) }
		c.OnStartup(func() error {
			go func() {
				if err := w.Run(ctx); err != nil {
					log.Errorf("pod watcher stopped: %v", err)
				}
			}()
			go func() {
				<-ctx.Done()
				markResolverStopped(gen)
			}()
			return nil
		})
	}

	c.OnShutdown(func() error {
		cancel()
		cleanup()
		return nil
	})

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return Agent{
			Resolver:  resolver,
			Cache:     cache,
			Upstream:  up,
			EDNS0Code: cfg.edns0Code,
			NodeIP:    cfg.nodeIP,
		}
	})
	return nil
}

func parseConfig(c *caddy.Controller) (*config, error) {
	cfg := &config{
		cacheSize: defaultCacheSize,
		edns0Code: ednszone.DefaultCode,
		zoneLabel: "zone",
	}
	// 一個設了但解不開的 NODE_IP 必須是錯誤，而不是悄悄當成沒設：masquerade
	// 偵測（Agent.resolveZone 比對來源位址是不是節點自己的 IP）是唯一會告訴
	// 操作者「這個節點上有東西在改寫來源位址、已經退化成單一 zone」的訊號，
	// DaemonSet manifest 裡打錯一個字元就讓它悄悄失效，且沒有任何記錄，正是
	// 這個專案一路在消除的那種失敗模式。行為要跟下面 Corefile 的 node_ip
	// 選項一致——那裡同樣的解析錯誤會讓啟動失敗。
	if v := os.Getenv("NODE_IP"); v != "" {
		addr, err := netip.ParseAddr(v)
		if err != nil {
			return nil, c.Errf("invalid NODE_IP environment variable %q: %v", v, err)
		}
		cfg.nodeIP = addr
	}

	for c.Next() {
		for c.NextBlock() {
			switch c.Val() {
			case "mode":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				switch c.Val() {
				case "k8s":
					cfg.mode = modeK8s
				case "vm":
					cfg.mode = modeVM
				default:
					return nil, c.Errf("unknown mode %q; expected k8s or vm", c.Val())
				}

			case "zone":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				cfg.zone = c.Val()

			case "node_name":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				cfg.nodeName = c.Val()

			case "zone_label":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				cfg.zoneLabel = c.Val()

			case "upstream":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				cfg.upstreamURL = c.Val()

			case "central_spiffe_id":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				cfg.centralSPIFFEID = c.Val()

			case "workload_api":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				cfg.workloadAPI = c.Val()

			case "cache_size":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				n, err := strconv.Atoi(c.Val())
				if err != nil {
					return nil, c.Errf("invalid cache_size %q: %v", c.Val(), err)
				}
				if n <= 0 {
					return nil, c.Errf("cache_size must be positive, got %d", n)
				}
				cfg.cacheSize = n

			case "node_ip":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				addr, err := netip.ParseAddr(c.Val())
				if err != nil {
					return nil, c.Errf("invalid node_ip %q: %v", c.Val(), err)
				}
				cfg.nodeIP = addr

			default:
				return nil, c.Errf("unknown property %q", c.Val())
			}
		}
	}

	if cfg.mode == modeUnset {
		return nil, c.Err("mode is required (k8s or vm)")
	}
	if cfg.upstreamURL == "" {
		return nil, c.Err("upstream is required")
	}
	// upstream 必須是 https:// —— NewMTLS 建出來的 client 整套存在的理由就是
	// 用 SPIFFE ID 釘住 central 的身分；一個 http:// 的 upstream 會讓查詢走
	// 純文字傳輸，http.Transport 的 TLSClientConfig（也就是那個 AuthorizeID
	// pin）根本不會被用上，等於一個字元就讓 mTLS 釘住整套形同虛設，且沒有
	// 任何錯誤或警告，查詢照常送出去。
	u, err := url.Parse(cfg.upstreamURL)
	if err != nil {
		return nil, c.Errf("invalid upstream %q: %v", cfg.upstreamURL, err)
	}
	if u.Scheme != "https" {
		return nil, c.Errf("upstream %q must use https; a plain %q upstream would send DoH queries in "+
			"cleartext, bypassing the SPIFFE server pinning NewMTLS exists to provide entirely",
			cfg.upstreamURL, u.Scheme)
	}
	// central_spiffe_id 沒有安全的預設值：少了它就只剩憑證鏈驗證，信任域內任何
	// 一張 SVID 都能冒充 central 並回傳任意答案。
	if cfg.centralSPIFFEID == "" {
		return nil, c.Err("central_spiffe_id is required; without it any SVID in the trust domain could impersonate the central server")
	}
	if cfg.workloadAPI == "" {
		return nil, c.Err("workload_api is required")
	}

	switch cfg.mode {
	case modeVM:
		if cfg.zone == "" {
			return nil, c.Err("vm mode requires zone")
		}
		// zone 名稱必須是線上格式承載得了的 —— 否則 central 會靜默忽略宣告，
		// 這台 VM 的查詢會永遠拿到不分 zone 的答案。
		if !ednszone.Valid(cfg.zone) {
			return nil, c.Errf("zone %q is not a valid zone name (letters, digits, '-' and '_' only, at most %d bytes)",
				cfg.zone, ednszone.MaxLen)
		}
	case modeK8s:
		if cfg.nodeName == "" {
			return nil, c.Err("k8s mode requires node_name")
		}
	}

	return cfg, nil
}
