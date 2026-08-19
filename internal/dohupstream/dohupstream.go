// Package dohupstream 是 agent 對 central 的 DoH client。
//
// 傳輸為 DoH over mTLS：agent 以自己的 SVID 出示身分，並且**必須**以 SPIFFE ID
// 釘住 central。只驗證憑證鏈是不夠的 —— 信任域內任何一張 SVID 都能冒充 central，
// 而偽造的 central 可以回傳任意答案（例如宣稱某個同 zone 服務是跨 zone 的，並給出
// 攻擊者控制的位址），agent 對答案沒有獨立查核手段。見 spec §7.5。
package dohupstream

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/coredns/coredns/plugin/pkg/doh"
	"github.com/miekg/dns"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// defaultDialTimeout 限制取得第一份 SVID 的等待時間。
//
// workloadapi.NewX509Source 會一直阻塞到 Workload API 首次回應為止，所以沒有這個
// 上限時，SPIRE agent 尚未就緒會讓 CoreDNS 的設定解析整個卡住，沒有逾時也沒有日誌。
const defaultDialTimeout = 10 * time.Second

// Config 是建立 mTLS client 所需的設定。
type Config struct {
	URL             string
	WorkloadAPIAddr string
	CentralSPIFFEID string
	DialTimeout     time.Duration
}

// Client 對 central 發送 DoH 查詢。
type Client struct {
	url string
	hc  *http.Client
}

// NewWithHTTPClient 以既有的 http.Client 建立 Client。測試用，也讓傳輸層的設定
// 與 DNS 邏輯分離。
func NewWithHTTPClient(url string, hc *http.Client) *Client {
	return &Client{url: url, hc: hc}
}

// NewMTLS 建立以 SPIFFE 身分互相驗證的 Client。
//
// 回傳的 cleanup 必須在關閉時呼叫，以釋放 X509Source。
func NewMTLS(ctx context.Context, cfg Config) (*Client, func(), error) {
	if cfg.CentralSPIFFEID == "" {
		return nil, nil, errors.New("dohupstream: central_spiffe_id is required; " +
			"without it any SVID in the trust domain could impersonate the central server")
	}
	id, err := spiffeid.FromString(cfg.CentralSPIFFEID)
	if err != nil {
		return nil, nil, fmt.Errorf("dohupstream: invalid central_spiffe_id %q: %w", cfg.CentralSPIFFEID, err)
	}

	timeout := cfg.DialTimeout
	if timeout == 0 {
		timeout = defaultDialTimeout
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	source, err := workloadapi.NewX509Source(dialCtx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(cfg.WorkloadAPIAddr)))
	if err != nil {
		return nil, nil, fmt.Errorf("dohupstream: obtain SVID from workload_api %q within %s: %w",
			cfg.WorkloadAPIAddr, timeout, err)
	}

	// 憑證取自 X509Source 而非靜態檔案，SVID 輪替才不需要重新載入設定。
	tlsCfg := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeID(id))
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}

	return &Client{url: cfg.URL, hc: hc}, func() { source.Close() }, nil
}

// Exchange 送出查詢並回傳答案。
func (c *Client) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	// RFC 8484 要求 DoH 查詢的 DNS ID 為 0；回應的 ID 由我們還原，否則呼叫端無法
	// 把答案對回原查詢。
	originalID := m.Id
	outbound := m.Copy()
	outbound.Id = 0

	req, err := doh.NewRequestWithContext(ctx, http.MethodPost, c.url, outbound)
	if err != nil {
		return nil, fmt.Errorf("dohupstream: build request: %w", err)
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dohupstream: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("dohupstream: upstream returned HTTP %d", resp.StatusCode)
	}

	// ResponseToMsg 會關閉 body。
	answer, err := doh.ResponseToMsg(resp)
	if err != nil {
		return nil, fmt.Errorf("dohupstream: decode response: %w", err)
	}
	answer.Id = originalID
	return answer, nil
}
