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
func TestDeleteRemovesTheMapping(t *testing.T) {
	p := pod("payments-abc", "10.1.0.5", "zone-a", false)
	client := fake.NewSimpleClientset(p)

	w := New(client, nodeName, zoneLabel)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	deadline := time.Now().Add(2 * time.Second)
	for !w.Ready() {
		if time.Now().After(deadline) {
			t.Fatal("watcher never became ready")
		}
		time.Sleep(5 * time.Millisecond)
	}

	if err := client.CoreV1().Pods("prod").Delete(ctx, "payments-abc", metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete: %v", err)
	}

	deadline = time.Now().Add(2 * time.Second)
	for {
		if _, ok := w.Zone(netip.MustParseAddr("10.1.0.5")); !ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("mapping survived the pod's deletion")
		}
		time.Sleep(5 * time.Millisecond)
	}
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
