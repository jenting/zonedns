package zonedns

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/pkg/transport"
	"github.com/jenting/zonedns/internal/ednszone"
	"github.com/jenting/zonedns/internal/identity"
	"github.com/jenting/zonedns/internal/registry"
	"github.com/jenting/zonedns/internal/zonetable"
	"github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var log = clog.NewWithPlugin("zonedns")

const (
	defaultPollInterval = 30 * time.Second
	defaultTTL          = uint32(30)
)

// workloadAPIDialTimeout 限制 dialSPIRE 等待本機 SPIRE agent 的 Workload API
// 交出第一筆 X509 SVID 更新的時間。
//
// go-spiffe 的 NewX509Source 文件明載：它會阻塞到第一筆更新抵達為止，且不帶
// 任何逾時。若 agent socket 沒起來（路徑寫錯、agent 還沒啟動、agent 掛了），
// setup() 會永遠卡住整個 Corefile 解析 —— 啟動時 CoreDNS 永遠起不來且沒有任何
// 錯誤訊息；`reload` 時則卡住 reload 本身，而舊的 instance 仍在提供服務，
// 讓卡住這件事更難被發現。改成變數（而非 const）是為了讓測試能縮短它，不必
// 真的等滿逾時。
var workloadAPIDialTimeout = 10 * time.Second

func init() { plugin.Register("zonedns", setup) }

// config 是從 Corefile 解析出來的設定。
type config struct {
	spireServer      string
	pollInterval     time.Duration
	authorizedAgents []string
	edns0Code        uint16
	ttl              uint32
	zones            *zonetable.Table
	workloadAPI      string // 僅在 spire_server 為網路位址時需要
	spireServerID    string // 同上，SPIRE Server 的 SPIFFE ID；network address 時必填，見下方驗證
}

// CheckDirectiveOrder 確認 zonedns 排在 cache 之前。
//
// 這個順序不是偏好而是正確性要求：cache 若排在前面，它會用 (qname, qtype) 這個
// 不含 zone 的 key 回答，於是跨 zone 的 client 會拿到別的 zone 快取的答案。這種
// 錯誤在執行期沒有任何徵兆，因此必須在啟動時就擋下來。
//
// 順序由編譯期的 plugin.cfg 決定，所以這是建置設定的檢查，不是使用者設定的檢查。
func CheckDirectiveOrder(directives []string) error {
	zonednsAt, cacheAt := -1, -1
	for i, d := range directives {
		switch d {
		case "zonedns":
			zonednsAt = i
		case "cache":
			cacheAt = i
		}
	}
	if zonednsAt < 0 {
		return fmt.Errorf("zonedns is not registered in dnsserver.Directives; add it to plugin.cfg before cache")
	}
	if cacheAt >= 0 && cacheAt < zonednsAt {
		return fmt.Errorf("zonedns must be ordered before cache in plugin.cfg, but cache is at %d and zonedns at %d; "+
			"with cache first, cross-zone clients would receive answers cached for another zone", cacheAt, zonednsAt)
	}
	return nil
}

// warnIfDoT 回傳 transport 為 DNS-over-TLS 時該顯示的警告文字，其餘傳輸方式回傳
// 空字串。
//
// 身分擷取在兩種傳輸上的做法不同：DoH 從 context 取出 *http.Request，這在其他
// plugin 包裝 ResponseWriter 之後仍然有效；DoT 則對 ResponseWriter 做
// dns.ConnectionStater 型別斷言 —— 而 CoreDNS 內建的 metrics plugin 會用一個把
// dns.ResponseWriter 存成 interface 欄位的 Recorder 包住 writer，導致這個斷言
// 失敗。後果是 DoT listener 上每個查詢都安靜地回報「沒有憑證」，zone 路由整個
// 關閉，未授權 agent 的告警永遠不會觸發 —— 而過程中沒有任何錯誤。因此本專案
// 決定的傳輸方式是 DoH，這裡只警告、不拒絕啟動。
func warnIfDoT(tr string) string {
	if tr != transport.TLS {
		return ""
	}
	return "zonedns is configured on a DNS-over-TLS (tls://) listener; zone-aware answers are unreliable there " +
		"because CoreDNS plugins (e.g. metrics) can wrap the ResponseWriter and defeat the client certificate " +
		"extraction zonedns relies on, silently disabling zone routing. Use a DNS-over-HTTPS (https://) listener instead."
}

func setup(c *caddy.Controller) error {
	if err := CheckDirectiveOrder(dnsserver.Directives); err != nil {
		return plugin.Error("zonedns", err)
	}

	if msg := warnIfDoT(dnsserver.GetConfig(c).Transport); msg != "" {
		log.Warning(msg)
	}

	cfg, err := parseConfig(c)
	if err != nil {
		return plugin.Error("zonedns", err)
	}

	store := registry.NewStore()
	// registryReady and registryPollErrors are package-level gauges shared across
	// Corefile reloads. Without this reset registryReady would keep reporting the
	// *previous* instance's readiness (1) for up to a full poll_interval after a
	// reload, while the new (empty) Store silently takes the non-zone-aware path on
	// every query; registryPollErrors would similarly keep reporting the previous
	// instance's error streak against a brand new Poller that has not failed at
	// all yet — either way the metric would lie exactly when it matters most.
	registryReady.Set(0)
	registryPollErrors.Set(0)

	conn, cleanup, err := dialSPIRE(cfg)
	if err != nil {
		return plugin.Error("zonedns", err)
	}
	lister := registry.NewSPIRELister(entryv1.NewEntryClient(conn))
	poller := registry.NewPoller(lister, store, cfg.pollInterval)
	poller.OnSnapshot = func(s registry.Stats) {
		registryNames.Set(float64(s.Names))
		registryConflicts.Set(float64(s.Conflicts))
		registryReady.Set(1)
		if s.Conflicts > 0 {
			log.Warningf("%d DNS names have conflicting zone declarations and are unresolvable", s.Conflicts)
		}
	}
	// OnPollErrors fires after every poll attempt, success or failure alike —
	// unlike OnSnapshot it must run on both outcomes, otherwise this gauge can
	// only ever go up (never reset to 0 on recovery) or never move at all.
	poller.OnPollErrors = func(count int64) {
		registryPollErrors.Set(float64(count))
	}

	ctx, cancel := context.WithCancel(context.Background())
	c.OnStartup(func() error {
		go poller.Run(ctx)
		return nil
	})
	c.OnShutdown(func() error {
		cancel()
		cleanup()
		return conn.Close()
	})

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return ZoneDNS{
			Next:     next,
			Identity: identity.NewConfig(cfg.authorizedAgents, cfg.edns0Code),
			Registry: store,
			Zones:    cfg.zones,
			TTL:      cfg.ttl,
		}
	})
	return nil
}

// dialSPIRE 連上 SPIRE Server 的 Entry API。
//
// 兩種部署形態：
//
//   - unix:// — central 與 SPIRE Server 同機，走本機管理 socket。該 socket 的存取
//     權由檔案權限控制，不需要 SVID。
//   - 其他（host:port）— 走 mTLS，憑證取自本機 SPIRE agent 的 Workload API。此時
//     central 自己的 registration entry 必須設 admin: true，否則 Entry API 會拒絕。
//
// 憑證用 X509Source 而非靜態檔案，SVID 輪替才不需要重新載入設定。
func dialSPIRE(cfg *config) (*grpc.ClientConn, func(), error) {
	if strings.HasPrefix(cfg.spireServer, "unix://") {
		conn, err := grpc.NewClient(cfg.spireServer, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return nil, nil, fmt.Errorf("dial spire server %q: %w", cfg.spireServer, err)
		}
		return conn, func() {}, nil
	}

	if cfg.workloadAPI == "" {
		return nil, nil, fmt.Errorf("spire_server %q is a network address, so workload_api must also be set "+
			"to obtain the admin SVID used to authenticate to the Entry API", cfg.spireServer)
	}
	// spire_server_id is required by parseConfig whenever spireServer is a network
	// address, so this should never actually fail — but dialSPIRE must not trust
	// that invariant blindly.
	serverID, err := spiffeid.FromString(cfg.spireServerID)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid spire_server_id %q: %w", cfg.spireServerID, err)
	}

	// NewX509Source blocks until the first Workload API update arrives, with
	// no timeout of its own — bound it here so a down or misconfigured agent
	// socket fails setup() loudly instead of hanging it forever (see
	// workloadAPIDialTimeout above).
	dialCtx, cancel := context.WithTimeout(context.Background(), workloadAPIDialTimeout)
	defer cancel()
	source, err := workloadapi.NewX509Source(dialCtx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(cfg.workloadAPI)))
	if err != nil {
		return nil, nil, fmt.Errorf("create X509Source from workload_api %q: waited %s for the SPIRE "+
			"Workload API to hand back the first SVID update and it did not arrive — check that the SPIRE "+
			"agent is running and its socket is reachable at that path: %w", cfg.workloadAPI, workloadAPIDialTimeout, err)
	}

	// AuthorizeID pins the exact SPIFFE ID that must present the server certificate.
	// AuthorizeMemberOf would instead accept *any* SVID in the trust domain as "the
	// SPIRE Server" — an attacker holding any workload SVID who can intercept this
	// connection could serve a forged registry and map arbitrary names to arbitrary
	// zones, compromising every routing decision the plugin makes.
	creds := grpccredentials.MTLSClientCredentials(source, source, tlsconfig.AuthorizeID(serverID))
	conn, err := grpc.NewClient(cfg.spireServer, grpc.WithTransportCredentials(creds))
	if err != nil {
		source.Close()
		return nil, nil, fmt.Errorf("dial spire server %q: %w", cfg.spireServer, err)
	}
	return conn, func() { source.Close() }, nil
}

func parseConfig(c *caddy.Controller) (*config, error) {
	cfg := &config{
		pollInterval: defaultPollInterval,
		edns0Code:    ednszone.DefaultCode,
		ttl:          defaultTTL,
	}
	gateways := map[string]netip.Addr{}

	for c.Next() {
		for c.NextBlock() {
			switch c.Val() {
			case "spire_server":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				cfg.spireServer = c.Val()

			case "poll_interval":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				d, err := time.ParseDuration(c.Val())
				if err != nil {
					return nil, c.Errf("invalid poll_interval %q: %v", c.Val(), err)
				}
				// A zero or negative interval reaches time.NewTicker inside the
				// OnStartup goroutine, which panics and crashes the process.
				if d <= 0 {
					return nil, c.Errf("poll_interval must be positive, got %q", c.Val())
				}
				cfg.pollInterval = d

			case "authorized_agent":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				cfg.authorizedAgents = append(cfg.authorizedAgents, c.Val())

			case "edns0_code":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				// strconv.ParseUint (unlike fmt.Sscanf with "%d") rejects trailing
				// garbage outright instead of silently stopping at the first
				// non-digit character.
				code, err := strconv.ParseUint(c.Val(), 10, 16)
				if err != nil {
					return nil, c.Errf("invalid edns0_code %q: %v", c.Val(), err)
				}
				if code < 65001 || code > 65534 {
					return nil, c.Errf("edns0_code %d is outside the local/experimental range 65001-65534", code)
				}
				cfg.edns0Code = uint16(code)

			case "workload_api":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				cfg.workloadAPI = c.Val()

			case "spire_server_id":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				cfg.spireServerID = c.Val()

			case "ttl":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				// strconv.ParseUint rejects duration-shaped values ("5m", "30s")
				// and trailing garbage ("30.5", "65001abc") outright, where
				// fmt.Sscanf with "%d" would silently stop at the first
				// non-digit and accept a truncated prefix.
				ttl, err := strconv.ParseUint(c.Val(), 10, 32)
				if err != nil {
					return nil, c.Errf("invalid ttl %q: %v", c.Val(), err)
				}
				cfg.ttl = uint32(ttl)

			case "gateway":
				args := c.RemainingArgs()
				if len(args) != 2 {
					return nil, c.Errf("gateway needs a zone and an address, got %d arguments", len(args))
				}
				// ednszone.Valid 是 registry 端（spiffezone.FromPath）也隱含依賴的
				// 字元集邊界：一個帶點的 zone 名稱（k8s label value 允許，但
				// ednszone.Valid 拒絕，見其註解與測試 "zone.a"）能在 gateway 表與
				// registry 裡運作良好，卻會讓每一筆從該 zone 送來的 source zone
				// 宣告在 identity.SourceZone 被 ednszone.Get 判定為不合法而丟棄
				// （ReasonNoDeclaration）——那些 workload 從此永遠拿到 zone-盲的
				// 答案，而且沒有被告警的 metric。在設定解析時就用同一套規則拒絕，
				// 讓不合規的 zone 在啟動時就爆炸，而不是在執行期悄悄降級。
				if !ednszone.Valid(args[0]) {
					return nil, c.Errf("gateway zone %q is not a valid zone name (must match the "+
						"identity/registry zone character set, see ednszone.Valid)", args[0])
				}
				if _, dup := gateways[args[0]]; dup {
					return nil, c.Errf("gateway for zone %q is already configured", args[0])
				}
				addr, err := netip.ParseAddr(args[1])
				if err != nil {
					return nil, c.Errf("invalid gateway address %q for zone %q: %v", args[1], args[0], err)
				}
				gateways[args[0]] = addr

			default:
				return nil, c.Errf("unknown property %q", c.Val())
			}
		}
	}

	if cfg.spireServer == "" {
		return nil, c.Err("spire_server is required")
	}
	// 沒有授權 agent 表示所有宣告都會被忽略，plugin 永遠不會 zone-aware。
	// 這一定是設定錯誤，不是合法組態。
	if len(cfg.authorizedAgents) == 0 {
		return nil, c.Err("at least one authorized_agent is required")
	}
	// spire_server 是網路位址時，dialSPIRE 走 mTLS，必須用 spire_server_id 釘住
	// SPIRE Server 的確切身分。少了它就只能驗證「trust domain 內的某個成員」，
	// 任何持有同 trust domain SVID 的攻擊者攔截連線後都能冒充 SPIRE Server、
	// 餵一份偽造的 registry，進而左右所有路由決策 —— 必須 fail closed。
	// unix:// 走本機 socket，不受影響，不需要這個欄位。
	if !strings.HasPrefix(cfg.spireServer, "unix://") && cfg.spireServerID == "" {
		return nil, c.Err("spire_server_id is required when spire_server is a network address, to authenticate " +
			"the SPIRE Server by its exact identity rather than merely by trust domain membership")
	}

	cfg.zones = zonetable.New(gateways)
	return cfg, nil
}
