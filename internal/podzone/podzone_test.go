package podzone

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

const (
	nodeName  = "node-1"
	zoneLabel = "zone"
)

func pod(name, ip, zone string, hostNetwork bool) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "prod",
			Labels:    map[string]string{zoneLabel: zone},
		},
		Spec:   corev1.PodSpec{NodeName: nodeName, HostNetwork: hostNetwork},
		Status: corev1.PodStatus{PodIP: ip},
	}
}

// waitUntil 輪詢 cond 直到為真或逾時，逾時就讓測試失敗。
func waitUntil(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal(msg)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// start 啟動 watcher 並等到就緒，回傳停止函式。
func start(t *testing.T, pods ...*corev1.Pod) (*Watcher, func()) {
	t.Helper()

	objs := make([]runtime.Object, 0, len(pods))
	for _, p := range pods {
		objs = append(objs, p)
	}
	client := fake.NewSimpleClientset(objs...)

	w := New(client, nodeName, zoneLabel)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()

	deadline := time.Now().Add(2 * time.Second)
	for !w.Ready() {
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("watcher never became ready")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return w, func() { cancel(); <-done }
}

func TestZoneFromPodIP(t *testing.T) {
	w, stop := start(t, pod("payments-abc", "10.1.0.5", "zone-a", false))
	defer stop()

	zone, ok := w.Zone(netip.MustParseAddr("10.1.0.5"))
	if !ok {
		t.Fatal("pod IP not found")
	}
	if zone != "zone-a" {
		t.Fatalf("zone = %q, want zone-a", zone)
	}
}

func TestUnknownIP(t *testing.T) {
	w, stop := start(t, pod("payments-abc", "10.1.0.5", "zone-a", false))
	defer stop()

	if _, ok := w.Zone(netip.MustParseAddr("10.1.0.99")); ok {
		t.Fatal("an unknown IP must not resolve")
	}
}

// hostNetwork pod 共用節點 IP，無法分辨彼此，因此絕不可進表 —— 否則節點 IP 會
// 對應到某一個 hostNetwork pod 的 zone，而那個對應是任意的。
func TestHostNetworkPodIsNotIndexed(t *testing.T) {
	w, stop := start(t,
		pod("payments-abc", "10.1.0.5", "zone-a", false),
		pod("node-exporter", "192.168.1.10", "zone-b", true),
	)
	defer stop()

	if _, ok := w.Zone(netip.MustParseAddr("192.168.1.10")); ok {
		t.Fatal("a hostNetwork pod was indexed; its IP is the node's and identifies nothing")
	}
	if _, ok := w.Zone(netip.MustParseAddr("10.1.0.5")); !ok {
		t.Fatal("the ordinary pod should still resolve")
	}
}

// zone.a 是合法的 k8s label value，但帶點的字元不合 ednszone.Valid（見該套件
// 的測試與註解），central 一定會把它的宣告當成不存在丟棄。這種 pod 必須跟沒有
// zone label 的 pod 一樣不進表 —— 否則本機會回報 result="ok"、看起來一切正常，
// 但 central 那一側其實從未採信過這個宣告，兩端的判定完全對不上。
func TestPodWithInvalidZoneLabelIsNotIndexed(t *testing.T) {
	w, stop := start(t, pod("payments-abc", "10.1.0.5", "zone.a", false))
	defer stop()

	if _, ok := w.Zone(netip.MustParseAddr("10.1.0.5")); ok {
		t.Fatal("a pod whose zone label the wire format cannot carry must not resolve")
	}
	if w.Len() != 0 {
		t.Fatalf("Len = %d, want 0 — an invalid zone label must not be indexed", w.Len())
	}
}

func TestPodWithoutZoneLabelIsNotIndexed(t *testing.T) {
	p := pod("legacy-abc", "10.1.0.6", "", false)
	delete(p.Labels, zoneLabel)

	w, stop := start(t, p)
	defer stop()

	if _, ok := w.Zone(netip.MustParseAddr("10.1.0.6")); ok {
		t.Fatal("a pod without the zone label must not resolve to an empty zone")
	}
}

func TestPodWithoutIPIsNotIndexed(t *testing.T) {
	w, stop := start(t, pod("pending-abc", "", "zone-a", false))
	defer stop()

	if w.Len() != 0 {
		t.Fatalf("Len = %d, want 0 — a pod with no IP yet has nothing to index", w.Len())
	}
}

// 刪除必須立刻讓映射失效。IP 會被回收給新的 pod，沿用舊值會回答錯誤的 zone。
//
// 這裡刻意放兩個 pod：只清單一個被刪除 pod 的映射還不夠，必須確認刪除事件
// 沒有波及其他還活著的 pod —— 一個「刪除時清空整張表」的錯誤實作，如果只有
// 一個 pod 在場，測試也會通過。
func TestDeleteRemovesTheMapping(t *testing.T) {
	p := pod("payments-abc", "10.1.0.5", "zone-a", false)
	sibling := pod("checkout-def", "10.1.0.7", "zone-b", false)
	client := fake.NewSimpleClientset(p, sibling)

	w := New(client, nodeName, zoneLabel)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	waitUntil(t, w.Ready, "watcher never became ready")

	if err := client.CoreV1().Pods("prod").Delete(ctx, "payments-abc", metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete: %v", err)
	}

	waitUntil(t, func() bool {
		_, ok := w.Zone(netip.MustParseAddr("10.1.0.5"))
		return !ok
	}, "mapping survived the pod's deletion")

	if zone, ok := w.Zone(netip.MustParseAddr("10.1.0.7")); !ok || zone != "zone-b" {
		t.Fatalf("an unrelated pod's mapping was disturbed by its sibling's deletion: zone=%q ok=%v", zone, ok)
	}
}

// pod IP 會改變（例如重建但沿用同一個 Deployment/Name，或 CNI 重新配發）。
// upsert 若只新增不回收，舊 IP 會永遠停留在表裡 —— 和刪除沒有清乾淨是同一種錯誤，
// 只是從「更新」這個方向進來。
func TestPodIPChangeRemovesOldMapping(t *testing.T) {
	p := pod("payments-abc", "10.1.0.5", "zone-a", false)
	client := fake.NewSimpleClientset(p)

	w := New(client, nodeName, zoneLabel)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	waitUntil(t, w.Ready, "watcher never became ready")

	updated := p.DeepCopy()
	updated.Status.PodIP = "10.1.0.6"
	if _, err := client.CoreV1().Pods("prod").Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update: %v", err)
	}

	waitUntil(t, func() bool {
		_, ok := w.Zone(netip.MustParseAddr("10.1.0.6"))
		return ok
	}, "new IP never took effect after the pod's IP changed")

	if zone, ok := w.Zone(netip.MustParseAddr("10.1.0.5")); ok {
		t.Fatalf("STALE: old IP 10.1.0.5 still resolves to zone %q", zone)
	}
	if zone, _ := w.Zone(netip.MustParseAddr("10.1.0.6")); zone != "zone-a" {
		t.Fatalf("zone = %q, want zone-a", zone)
	}
}

// 拿掉 zone label（IP 不變）必須讓映射跟著失效，理由和 pod 被刪除時一樣：
// 沿用舊值會回答一個不再成立的 zone，而那個答案看起來完全正常。
func TestZoneLabelRemovedStopsResolving(t *testing.T) {
	p := pod("payments-abc", "10.1.0.5", "zone-a", false)
	client := fake.NewSimpleClientset(p)

	w := New(client, nodeName, zoneLabel)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	waitUntil(t, w.Ready, "watcher never became ready")

	updated := p.DeepCopy()
	delete(updated.Labels, zoneLabel)
	if _, err := client.CoreV1().Pods("prod").Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update: %v", err)
	}

	waitUntil(t, func() bool {
		_, ok := w.Zone(netip.MustParseAddr("10.1.0.5"))
		return !ok
	}, "STALE: IP still resolves after its pod's zone label was removed")
}

// 把 zone label 的值改成空字串，效果必須和拿掉 label 一樣：不可索引，
// 因為空字串一樣會被下游當成一個真的 zone。
func TestZoneLabelEmptiedStopsResolving(t *testing.T) {
	p := pod("payments-abc", "10.1.0.5", "zone-a", false)
	client := fake.NewSimpleClientset(p)

	w := New(client, nodeName, zoneLabel)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	waitUntil(t, w.Ready, "watcher never became ready")

	updated := p.DeepCopy()
	updated.Labels[zoneLabel] = ""
	if _, err := client.CoreV1().Pods("prod").Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update: %v", err)
	}

	waitUntil(t, func() bool {
		_, ok := w.Zone(netip.MustParseAddr("10.1.0.5"))
		return !ok
	}, "STALE: IP still resolves after its pod's zone label was emptied")
}

// 改標成另一個非空 zone 是合格的轉換：同一個 IP 鍵被覆寫即可，這條路徑本來就
// 是對的。把它釘住，避免之後的重構（例如改成先刪後寫）不小心破壞它。
func TestRelabelToDifferentZoneResolvesNewZone(t *testing.T) {
	p := pod("payments-abc", "10.1.0.5", "zone-a", false)
	client := fake.NewSimpleClientset(p)

	w := New(client, nodeName, zoneLabel)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	waitUntil(t, w.Ready, "watcher never became ready")

	updated := p.DeepCopy()
	updated.Labels[zoneLabel] = "zone-b"
	if _, err := client.CoreV1().Pods("prod").Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update: %v", err)
	}

	waitUntil(t, func() bool {
		zone, ok := w.Zone(netip.MustParseAddr("10.1.0.5"))
		return ok && zone == "zone-b"
	}, "IP never resolved to the pod's new zone after relabel")
}

// 尚未就緒時一律回 false —— 「還不知道」與「查得到但不在表裡」是不同的答案。
func TestNotReadyResolvesNothing(t *testing.T) {
	w := New(fake.NewSimpleClientset(), nodeName, zoneLabel)
	if w.Ready() {
		t.Fatal("a watcher that has not run must not report ready")
	}
	if _, ok := w.Zone(netip.MustParseAddr("10.1.0.5")); ok {
		t.Fatal("an unready watcher must not resolve")
	}
}

// resyncPeriod 過後，informer 必須重新對現有的 pod 送出 Update，並藉此修好
// upsert/remove 上方描述的 IP 回收競態遺留下來的損壞狀態 —— 不是重新計數，是
// 原地覆寫回目前真正的值。這裡直接破壞 byIP（模擬另一個 pod 的 Delete 事件
// 在錯的時機把它清掉），確認 resync 能把它修回來，且 Len() 全程維持 1，證明
// 是覆寫而不是疊加。
func TestResyncRebuildsMapping(t *testing.T) {
	origResync := resyncPeriod
	// client-go clamps anything below 1s to 1s (with a warning); use a value
	// just above that floor so the test both avoids the warning and still
	// finishes quickly.
	resyncPeriod = 1100 * time.Millisecond
	defer func() { resyncPeriod = origResync }()

	w, stop := start(t, pod("payments-abc", "10.1.0.5", "zone-a", false))
	defer stop()

	if zone, ok := w.Zone(netip.MustParseAddr("10.1.0.5")); !ok || zone != "zone-a" {
		t.Fatalf("initial sync: got (%q,%v), want (zone-a,true)", zone, ok)
	}

	// 模擬競態遺留下來的損壞狀態：byPod 仍指向這個 IP（下面沒有動它），但
	// byIP 這一側被清掉了 —— 見 upsert/remove 上方對這個競態的完整說明。
	w.mu.Lock()
	delete(w.byIP, netip.MustParseAddr("10.1.0.5"))
	w.mu.Unlock()

	if _, ok := w.Zone(netip.MustParseAddr("10.1.0.5")); ok {
		t.Fatal("test setup failed to corrupt byIP")
	}

	waitUntil(t, func() bool {
		zone, ok := w.Zone(netip.MustParseAddr("10.1.0.5"))
		return ok && zone == "zone-a"
	}, "periodic resync never rebuilt the corrupted mapping")

	if got := w.Len(); got != 1 {
		t.Fatalf("Len = %d after resync, want 1 — resync must reconcile in place, not double-count", got)
	}
}

// OnReady 必須在 informer 首次完成同步後、Ready() 開始回報 true 之後，
// 恰好被呼叫一次 —— Task 5 靠這個時機點把 resolver_ready 這個 gauge 設成 1；
// 沒有輪詢 Ready() 的人，這是唯一能觀察到「就緒那一刻」的機會。
func TestOnReadyFiresOnceAfterSync(t *testing.T) {
	client := fake.NewSimpleClientset(pod("payments-abc", "10.1.0.5", "zone-a", false))

	w := New(client, nodeName, zoneLabel)

	var calls int32
	w.OnReady = func() { atomic.AddInt32(&calls, 1) }

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	deadline := time.Now().Add(2 * time.Second)
	for !w.Ready() {
		if time.Now().After(deadline) {
			t.Fatal("watcher never became ready")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// 給 OnReady 一點時間執行；它在標記就緒之後、非持鎖狀態下才被呼叫。
	deadline = time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&calls) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("OnReady was never called")
		}
		time.Sleep(5 * time.Millisecond)
	}

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("OnReady called %d times, want 1", got)
	}
}
