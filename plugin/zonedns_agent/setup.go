package zonedns_agent

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strconv"

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
		resolverReady.Set(0)
		// OnReady 在 informer 首次完成同步後被呼叫一次；在那之前 resolverReady
		// 必須留在 0，否則這個 gauge 會回報「就緒」而 watcher 其實還沒有任何
		// pod 的對照資料。
		w.OnReady = func() { resolverReady.Set(1) }
		c.OnStartup(func() error {
			go func() {
				if err := w.Run(ctx); err != nil {
					log.Errorf("pod watcher stopped: %v", err)
				}
			}()
			go func() {
				<-ctx.Done()
				resolverReady.Set(0)
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
	if v := os.Getenv("NODE_IP"); v != "" {
		if addr, err := netip.ParseAddr(v); err == nil {
			cfg.nodeIP = addr
		}
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
