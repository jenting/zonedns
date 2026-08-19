// Package podzone 維護本機節點上 pod IP 到 zone 的對照。
//
// 資料來自 Kubernetes API，以 spec.nodeName 過濾成只看本節點的 pod —— 數十筆，
// 不是全 cluster 的 watch。讀到的 zone label 正是產生該 pod SPIFFE ID 所用的同一個
// 值，因此節點端算出的 zone 與 central 從 registry 查到的 zone 由建構方式保證一致。
package podzone

import (
	"context"
	"net/netip"
	"sync"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// Watcher 持有本機 pod 的 IP → zone 對照。
type Watcher struct {
	client    kubernetes.Interface
	nodeName  string
	zoneLabel string

	// OnReady 在 informer 首次完成同步後被呼叫一次。
	OnReady func()

	mu    sync.RWMutex
	byIP  map[netip.Addr]string
	ready bool
}

// New 建立尚未啟動的 Watcher。
func New(client kubernetes.Interface, nodeName, zoneLabel string) *Watcher {
	return &Watcher{
		client:    client,
		nodeName:  nodeName,
		zoneLabel: zoneLabel,
		byIP:      make(map[netip.Addr]string),
	}
}

// Run 啟動 informer 並持續同步，直到 ctx 結束。
func (w *Watcher) Run(ctx context.Context) error {
	factory := informers.NewSharedInformerFactoryWithOptions(w.client, 0,
		informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
			opts.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", w.nodeName).String()
		}))

	informer := factory.Core().V1().Pods().Informer()
	if _, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { w.upsert(obj) },
		UpdateFunc: func(_, obj any) { w.upsert(obj) },
		DeleteFunc: func(obj any) { w.remove(obj) },
	}); err != nil {
		return err
	}

	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		return ctx.Err()
	}

	w.mu.Lock()
	w.ready = true
	w.mu.Unlock()

	if w.OnReady != nil {
		w.OnReady()
	}

	<-ctx.Done()

	// informer 停止後，表上的內容就不再跟得上真實狀態。標回未就緒，讓查詢改走
	// 不宣告 zone 的路徑，而不是繼續拿一份會愈來愈舊的對照回答。
	w.mu.Lock()
	w.ready = false
	w.mu.Unlock()
	return nil
}

// upsert 收下一個 pod。
//
// 三種 pod 刻意不進表：
//   - hostNetwork：它的 IP 就是節點 IP，同節點上所有 hostNetwork pod 共用，
//     分辨不出是誰，任何對應都是任意的
//   - 沒有 zone label：不可對應到空字串 zone，那會被下游當成一個真的 zone
//   - 還沒拿到 IP（Pending）：沒有可索引的鍵
func (w *Watcher) upsert(obj any) {
	pod, ok := obj.(*corev1.Pod)
	if !ok || pod.Spec.HostNetwork || pod.Status.PodIP == "" {
		return
	}
	zone, ok := pod.Labels[w.zoneLabel]
	if !ok || zone == "" {
		return
	}
	ip, err := netip.ParseAddr(pod.Status.PodIP)
	if err != nil {
		return
	}

	w.mu.Lock()
	w.byIP[ip] = zone
	w.mu.Unlock()
}

// remove 移除一個 pod 的對照。
//
// 立即移除是必要的：pod IP 會被回收給新的 pod，沿用舊值會讓新 pod 拿到前一個
// 租用者的 zone —— 而那個答案看起來完全正常。
func (w *Watcher) remove(obj any) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		// informer 在 relist 時可能給出 DeletedFinalStateUnknown。
		tombstone, isTombstone := obj.(cache.DeletedFinalStateUnknown)
		if !isTombstone {
			return
		}
		pod, ok = tombstone.Obj.(*corev1.Pod)
		if !ok {
			return
		}
	}
	if pod.Status.PodIP == "" {
		return
	}
	ip, err := netip.ParseAddr(pod.Status.PodIP)
	if err != nil {
		return
	}

	w.mu.Lock()
	delete(w.byIP, ip)
	w.mu.Unlock()
}

// Zone 查出該 IP 所屬的 zone。
//
// 尚未就緒時一律回 false：啟動期間的查詢會走非 zone-aware 路徑，而不是猜一個
// 可能錯誤的 zone。
func (w *Watcher) Zone(ip netip.Addr) (string, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if !w.ready {
		return "", false
	}
	zone, ok := w.byIP[ip]
	return zone, ok
}

// Ready 回報 informer 是否已完成首次同步。
func (w *Watcher) Ready() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.ready
}

// Len 回傳目前索引的 pod 數。
func (w *Watcher) Len() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.byIP)
}
