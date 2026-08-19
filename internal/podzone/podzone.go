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

// podKey 是一個 pod 在其存續期間穩定不變的識別 —— namespace/name。不用 UID：
// fake clientset 建立的物件經常留空 UID，多個 pod 會因此共用同一把空鍵；
// namespace/name 在測試與正式環境下都保證存在且唯一。
type podKey struct {
	namespace string
	name      string
}

// Watcher 持有本機 pod 的 IP → zone 對照。
type Watcher struct {
	client    kubernetes.Interface
	nodeName  string
	zoneLabel string

	// OnReady 在 informer 首次完成同步後被呼叫一次。
	OnReady func()

	mu sync.RWMutex
	// byPod 記錄每個已索引 pod 目前佔用的 IP，用來在該 pod 換 IP、失去資格
	// （拿掉/清空 zone label）或被刪除時，準確回收舊映射，而不是只會新增。
	byPod map[podKey]netip.Addr
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
		byPod:     make(map[podKey]netip.Addr),
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

// upsert 收下一個 pod 的最新狀態。
//
// 三種 pod 刻意不進表：
//   - hostNetwork：它的 IP 就是節點 IP，同節點上所有 hostNetwork pod 共用，
//     分辨不出是誰，任何對應都是任意的
//   - 沒有 zone label（或值為空字串）：不可對應到空字串 zone，那會被下游當成
//     一個真的 zone
//   - 還沒拿到 IP（Pending）：沒有可索引的鍵
//
// 這些條件不只決定「要不要新增」，也決定「要不要回收」：一個 pod 換了 IP、被
// 拿掉 zone label，或 label 被清空，都是從「有效」轉為「這次不索引」的轉換，
// 舊映射必須跟著移除 —— 否則舊 IP（或舊 zone）會無限期停留在表裡，效果和刪除
// 沒清乾淨一樣：新租用該 IP 的 pod 會拿到前一個租用者的 zone，而答案看起來
// 完全正常。byPod 記住每個 pod 上一次成功索引時用的是哪個 IP，讓這裡能精準
// 回收，而不是猜。
func (w *Watcher) upsert(obj any) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return
	}

	var (
		newIP     netip.Addr
		zone      string
		qualifies = true
	)
	switch {
	case pod.Spec.HostNetwork, pod.Status.PodIP == "":
		qualifies = false
	default:
		z, hasLabel := pod.Labels[w.zoneLabel]
		if !hasLabel || z == "" {
			qualifies = false
			break
		}
		ip, err := netip.ParseAddr(pod.Status.PodIP)
		if err != nil {
			qualifies = false
			break
		}
		newIP, zone = ip, z
	}

	key := podKey{namespace: pod.Namespace, name: pod.Name}

	w.mu.Lock()
	defer w.mu.Unlock()

	oldIP, hadOld := w.byPod[key]
	if !qualifies {
		if hadOld {
			delete(w.byIP, oldIP)
			delete(w.byPod, key)
		}
		return
	}
	if hadOld && oldIP != newIP {
		delete(w.byIP, oldIP)
	}
	w.byIP[newIP] = zone
	w.byPod[key] = newIP
}

// remove 移除一個 pod 的對照。
//
// 立即移除是必要的：pod IP 會被回收給新的 pod，沿用舊值會讓新 pod 拿到前一個
// 租用者的 zone —— 而那個答案看起來完全正常。查 byPod 而不是重新解析
// pod.Status.PodIP：這樣一律精準回收「這個 pod 當時實際被索引的那個 IP」，
// 也涵蓋了該 pod 從未合格、byPod 裡本來就沒有它的情況（此時什麼都不用做）。
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

	key := podKey{namespace: pod.Namespace, name: pod.Name}

	w.mu.Lock()
	defer w.mu.Unlock()
	if ip, ok := w.byPod[key]; ok {
		delete(w.byIP, ip)
		delete(w.byPod, key)
	}
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
