// Package zonecache 是節點端的 DNS 答案快取，以 zone 作為 key 的一部分。
//
// 為什麼不能用 CoreDNS 內建的 cache plugin：它的 key 是 (qname, qtype)，不含發問者
// 的 zone。同一個名字對不同 zone 的 client 有不同的正確答案（同 zone 回服務位址、
// 跨 zone 回 gateway VIP），所以 zone-盲的快取會把某個 zone 的答案回給另一個 zone
// 的 pod —— 而且回得像模像樣，不會有任何錯誤。
package zonecache

import (
	"errors"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/miekg/dns"
)

// maxTTL 是任何一筆快取項目實際存活時間的上限，不論上游答案自己宣告的 TTL
// 多長。
//
// spec §6.6 論證 central 的跨 zone 答案用 30 秒的 TTL 是刻意的：它是「服務搬
// zone」或「zone GW VIP 變更」這類拓樸變化，從發生到所有節點都看見新答案為止
// 的傳播延遲上限。但那個論證只涵蓋跨 zone 分支 —— 同 zone 分支的答案是原封不動
// 轉發的上游答案，TTL 是上游自己設的，可能長達數小時。少了這個上限，一個名字
// 被登記進 registry、或者改了 zone，這個節點會繼續回覆直連位址直到那個很長的
// TTL 走完；zone 之間網路隔離，那段時間裡答案是錯的，後果是連不上，而不是有
// 任何提示。
//
// 這裡選跟 central 端 defaultTTL（plugin/zonedns/setup.go）同一個量級的值，
// 讓 spec 承諾的傳播延遲上限對兩個分支都成立，不只是跨 zone 那一半。
const maxTTL = 30 * time.Second

// Cache 是有大小上限的 zone-aware 答案快取，可安全併發使用。
type Cache struct {
	mu sync.Mutex
	l  *lru.Cache[key, entry]
}

type key struct {
	qname string
	qtype uint16
	zone  string
}

type entry struct {
	msg    *dns.Msg
	expiry time.Time
}

// New 建立可容納 maxEntries 筆的快取。
func New(maxEntries int) (*Cache, error) {
	if maxEntries <= 0 {
		return nil, errors.New("zonecache: maxEntries must be positive")
	}
	l, err := lru.New[key, entry](maxEntries)
	if err != nil {
		return nil, err
	}
	return &Cache{l: l}, nil
}

// makeKey 正規化 qname —— DNS 名稱大小寫不敏感，不正規化會讓同一個名字的不同寫法
// 各佔一個快取項目，並在下游看來像是快取失效。
func makeKey(qname string, qtype uint16, zone string) key {
	return key{qname: strings.ToLower(qname), qtype: qtype, zone: zone}
}

// Put 收下一筆答案。
//
// 沒有 answer 的回應不快取：它沒有可依循的 TTL，而拿 SOA 的 minimum 做否定快取是
// 另一個決策，不在本套件範圍內。存起來的是副本，呼叫端之後改動原訊息不影響快取。
func (c *Cache) Put(qname string, qtype uint16, zone string, m *dns.Msg, now time.Time) {
	if m == nil || len(m.Answer) == 0 {
		return
	}

	minTTL := m.Answer[0].Header().Ttl
	for _, rr := range m.Answer[1:] {
		if t := rr.Header().Ttl; t < minTTL {
			minTTL = t
		}
	}
	if minTTL == 0 {
		return
	}

	ttl := time.Duration(minTTL) * time.Second
	if ttl > maxTTL {
		ttl = maxTTL
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.l.Add(makeKey(qname, qtype, zone), entry{
		msg:    m.Copy(),
		expiry: now.Add(ttl),
	})
}

// Get 取出未過期的答案，並把每筆記錄的 TTL 扣掉已經過的時間。
//
// 扣 TTL 不是修飾：若照原值回傳，下游 resolver 會從收到的那一刻重新計時，答案實際
// 存活的時間就會比我們設定的長。
func (c *Cache) Get(qname string, qtype uint16, zone string, now time.Time) (*dns.Msg, bool) {
	c.mu.Lock()
	e, ok := c.l.Get(makeKey(qname, qtype, zone))
	c.mu.Unlock()
	if !ok {
		return nil, false
	}

	remaining := e.expiry.Sub(now)
	if remaining <= 0 {
		return nil, false
	}

	out := e.msg.Copy()
	ttl := uint32(remaining / time.Second)
	for _, rr := range out.Answer {
		rr.Header().Ttl = ttl
	}
	for _, rr := range out.Ns {
		rr.Header().Ttl = ttl
	}
	for _, rr := range out.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			rr.Header().Ttl = ttl
		}
	}
	return out, true
}

// Len 回傳目前的項目數。
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.l.Len()
}
