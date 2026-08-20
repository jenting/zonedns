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

// waitUntil polls cond until it holds or the deadline passes, failing the test
// on timeout.
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

// start runs the watcher, waits until it is ready, and returns a stop function.
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

// hostNetwork pods share the node IP and cannot be told apart, so they must
// never enter the table — otherwise the node IP would map to one hostNetwork
// pod's zone, and which one is arbitrary.
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

// zone.a is a legal Kubernetes label value, but the dot breaks ednszone.Valid
// (see that package's tests and docs) and central is certain to discard the
// declaration as absent. Such a pod must stay out of the table exactly like one
// with no zone label — otherwise the node reports result="ok" and everything
// looks fine, while central never once believed the declaration and the two
// sides' verdicts disagree completely.
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

// Deletion must invalidate the mapping at once. IPs are recycled to new pods,
// and keeping the old value answers with the wrong zone.
//
// Two pods are used deliberately: clearing the deleted pod's mapping is not
// enough on its own, the delete must also be shown not to disturb the pods still
// alive. An implementation that wrongly wipes the whole table on delete would
// pass this test with only one pod present.
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

// A pod's IP can change — recreated under the same Deployment/Name, or
// reassigned by the CNI. If upsert only adds and never reclaims, the old IP stays
// in the table forever: the same fault as a deletion that did not clean up,
// arriving from the update direction instead.
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

// Removing the zone label while the IP stays the same must invalidate the
// mapping too, for the same reason as a deletion: keeping the old value answers
// with a zone that no longer holds, and the answer looks entirely normal.
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

// Emptying the zone label's value must behave exactly like removing the label:
// not indexed, because downstream would treat the empty string as a real zone
// all the same.
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

// Relabelling to another non-empty zone is a valid transition: the same IP key is
// overwritten, and this path was always correct. Pinned here so a later refactor
// — switching to delete-then-write, say — cannot break it by accident.
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

// Before it is ready it always returns false — "not known yet" and "resolvable
// but absent from the table" are different answers.
func TestNotReadyResolvesNothing(t *testing.T) {
	w := New(fake.NewSimpleClientset(), nodeName, zoneLabel)
	if w.Ready() {
		t.Fatal("a watcher that has not run must not report ready")
	}
	if _, ok := w.Zone(netip.MustParseAddr("10.1.0.5")); ok {
		t.Fatal("an unready watcher must not resolve")
	}
}

// After resyncPeriod the informer must re-deliver Updates for the pods it
// already knows, and thereby repair the damage left by the IP reuse race
// described above upsert/remove — not by recounting, but by overwriting in place
// with the value as it now stands. This test damages byIP directly, simulating
// another pod's Delete wiping it at the wrong moment, and confirms the resync
// repairs it while Len() stays at 1 throughout, proving an overwrite rather than
// an accumulation.
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

	// Simulate the damage the race leaves behind: byPod still points at this IP
	// (nothing below touches it) while the byIP side has been wiped — see the full
	// account of the race above upsert/remove.
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

// OnReady must fire exactly once, after the informer completes its first sync
// and after Ready() begins reporting true. Task 5 uses that moment to set the
// resolver_ready gauge to 1; for anyone not polling Ready(), it is the only
// chance to observe the instant readiness arrives.
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

	// Give OnReady a moment to run; it is called after readiness is marked, and
	// without the lock held.
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
