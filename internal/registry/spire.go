// Package registry（本檔）負責從 SPIRE Server 取得 registration entry。
//
// SPIRE 的 Entry API 沒有 watch/stream RPC：ListEntries 是分頁的一元呼叫，唯一的
// 串流 RPC（SyncAuthorizedEntries）是給 agent 同步自己被授權的 entry 用的，不能
// 列出全部 entry。因此本檔實作的是輪詢器而非監看器。
package registry

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	clog "github.com/coredns/coredns/plugin/pkg/log"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
)

var log = clog.NewWithPlugin("zonedns")

// EntryLister 取得一頁 registration entry。
//
// 抽成介面是為了讓輪詢邏輯（分頁、錯誤處理、快照替換）可以脫離 gRPC 測試。
type EntryLister interface {
	ListEntries(ctx context.Context, pageToken string) ([]Entry, string, error)
}

// pageSize 是每次向 SPIRE 索取的 entry 數。
const pageSize = 500

// maxPollPages 是單次 PollOnce 最多追隨的分頁數。
//
// 這是防禦性上限：SPIRE 沒有已知部署會逼近 pageSize(500) * maxPollPages =
// 5,000,000 筆 entry（SPIRE 官方文件描述的測試規模落在數萬筆等級），所以任何
// 合法的 registry 都不可能碰到這個上限。它存在的目的是防止一個行為異常的
// SPIRE server（例如永遠回傳非空的 NextPageToken）讓 PollOnce 無限迴圈：那樣
// all 會無限成長且永遠不會產生新快照，而 Run 也不會記錄任何錯誤 —— 對外看
// 起來像是「凍結在最後一次成功的快照」，但實際上是卡死且持續漏記憶體。超過
// 上限時視為錯誤，走既有的失敗路徑（保留舊快照）。
const maxPollPages = 10000

type spireLister struct {
	client entryv1.EntryClient
}

// NewSPIRELister 以 SPIRE Entry API 實作 EntryLister。
//
// 注意 Entry API 沒有 watch/stream RPC：ListEntries 是分頁的一元呼叫，唯一的串流
// RPC (SyncAuthorizedEntries) 是給 agent 同步自己被授權的 entry 用的，不能列出全部。
// 因此這裡是輪詢而非監看。
//
// 呼叫此 API 需要 admin SVID —— central 所在主機的 SPIRE registration entry 必須
// 設定 admin: true。
func NewSPIRELister(client entryv1.EntryClient) EntryLister {
	return &spireLister{client: client}
}

func (l *spireLister) ListEntries(ctx context.Context, pageToken string) ([]Entry, string, error) {
	resp, err := l.client.ListEntries(ctx, &entryv1.ListEntriesRequest{
		PageSize:  pageSize,
		PageToken: pageToken,
		// 只取需要的兩個欄位，避免把 selector 等大量無關資料拉過來。
		OutputMask: &types.EntryMask{
			SpiffeId: true,
			DnsNames: true,
		},
	})
	if err != nil {
		return nil, "", fmt.Errorf("registry: list entries: %w", err)
	}

	out := make([]Entry, 0, len(resp.Entries))
	for _, e := range resp.Entries {
		if e.SpiffeId == nil {
			continue
		}
		out = append(out, Entry{
			SPIFFEIDPath: e.SpiffeId.Path,
			DNSNames:     e.DnsNames,
		})
	}
	return out, resp.NextPageToken, nil
}

// Poller 週期性地把 SPIRE 的 entry 拉成新快照放進 Store。
type Poller struct {
	lister   EntryLister
	store    *Store
	interval time.Duration

	// pollErrors 記錄這個 Poller 連續輪詢失敗的次數。
	//
	// 這是 Poller 的欄位而非套件層級變數 —— 目前的部署只會建立一個 Poller，
	// 兩種做法效果相同，但套件層級的單一計數器會被「本 process 中每一個
	// Poller」共用：將來若有第二個 Poller（例如同時輪詢兩個 SPIRE Server），
	// 它會跟第一個共用同一個計數器而非各自獨立計數，讓 ConsecutivePollErrors
	// 這個「連續失敗次數」的意義變得不可靠。做成欄位讓每個 Poller 天生互相
	// 獨立，不必等到真的出現第二個 Poller 才發現這個問題。
	pollErrors atomic.Int64

	// OnSnapshot 在每次成功輪詢後被呼叫，帶入該次快照的 Stats。
	//
	// 這是 Run 把統計值交給外層（例如 plugin 層要把它們發布成 Prometheus
	// gauge）的唯一管道 —— PollOnce 的回傳值只在呼叫端手動呼叫時看得到，
	// Run 內部的輪詢迴圈本身不會回傳任何東西。可留空（nil）。
	OnSnapshot func(Stats)

	// OnPollErrors 在每次輪詢（成功或失敗）結束後被呼叫，帶入呼叫當下的連續
	// 失敗次數（與 ConsecutivePollErrors() 同步）。
	//
	// 這是 registry_poll_errors gauge 的唯一資料來源：與 OnSnapshot 不同，
	// 它在成功與失敗時都會被呼叫 —— 失敗時才能把次數往上發布，成功時才能把
	// gauge 歸零，缺一都會讓這個 metric 卡在舊值或永遠是 0。可留空（nil）。
	OnPollErrors func(count int64)
}

// NewPoller 建立 Poller。
func NewPoller(lister EntryLister, store *Store, interval time.Duration) *Poller {
	return &Poller{lister: lister, store: store, interval: interval}
}

// ConsecutivePollErrors 回傳這個 Poller 連續輪詢失敗的次數。0 表示最近一次
// 輪詢成功（或還沒輪詢過）。
//
// spec §6.2 要求輪詢失敗時「沿用上一份快照並遞增 metric」——這個方法（經
// OnPollErrors 或呼叫端輪詢）就是那個 metric 唯一的資料來源。SPIRE 變得不可
// 達（admin SVID 過期、admin 權限被收回、網路分斷）時，Store 會無限期沿用
// 最後一份快照：registry_ready 停在 1、registry_names 停在最後的值，唯一的
// 訊號就是這個計數器。
func (p *Poller) ConsecutivePollErrors() int64 { return p.pollErrors.Load() }

// PollOnce 拉取全部 entry 並替換快照。
//
// 失敗時**不會**動到既有快照：SPIRE 短暫不可用不應讓所有 zone 路由消失。首次輪詢
// 就失敗時 Store 維持未就緒（而非變成空快照），因為「還不知道」與「查得到但都不在
// registry」是不同的意思，後者會讓所有跨 zone 查詢靜默地退回一般答案。
//
// 分頁迴圈有兩道防線防止行為異常的 server 讓它不停下來：一是 maxPollPages 的頁數
// 上限，二是偵測「同一個 page token 被回傳第二次」——只有上限的話，一個卡住但每次
// 都回傳同一個 token 的 server 仍會把整個上限跑完才失敗；有了重複偵測，這種情況會
// 立刻被抓到。兩種情況都視為錯誤，走既有的失敗路徑（保留舊快照）。
func (p *Poller) PollOnce(ctx context.Context) (Stats, error) {
	var all []Entry
	seenTokens := make(map[string]struct{})
	token := ""
	for pages := 0; ; pages++ {
		if pages >= maxPollPages {
			return Stats{}, fmt.Errorf("registry: aborting poll after %d pages, SPIRE server may be misbehaving", maxPollPages)
		}
		if token != "" {
			if _, dup := seenTokens[token]; dup {
				return Stats{}, fmt.Errorf("registry: SPIRE server returned page token %q twice, aborting poll", token)
			}
			seenTokens[token] = struct{}{}
		}

		page, next, err := p.lister.ListEntries(ctx, token)
		if err != nil {
			return Stats{}, err
		}
		all = append(all, page...)
		if next == "" {
			break
		}
		token = next
	}

	snap, stats := BuildSnapshot(all)
	p.store.Replace(snap)
	return stats, nil
}

// Run 依設定的間隔持續輪詢，直到 ctx 結束。啟動時立即輪詢一次。
func (p *Poller) Run(ctx context.Context) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		stats, err := p.PollOnce(ctx)
		if err != nil {
			p.pollErrors.Add(1)
			log.Warningf("registry poll failed, keeping previous snapshot: %v", err)
		} else {
			p.pollErrors.Store(0)
			if p.OnSnapshot != nil {
				p.OnSnapshot(stats)
			}
		}
		if p.OnPollErrors != nil {
			p.OnPollErrors(p.pollErrors.Load())
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
