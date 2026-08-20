// Package podzone maintains the pod IP to zone mapping for the local node.
//
// The data comes from the Kubernetes API, filtered by spec.nodeName to this
// node's pods alone — a few dozen, not a cluster-wide watch. The zone label it
// reads is the very value used to produce that pod's SPIFFE ID, so the zone the
// node computes and the zone central looks up in the registry agree by
// construction.
package podzone

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/jenting/zonedns/internal/ednszone"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// podKey identifies a pod stably for its whole lifetime: namespace/name. Not the
// UID — objects created by the fake clientset routinely leave the UID empty, and
// several pods would then share one empty key. namespace/name is guaranteed to
// exist and be unique both in tests and in production.
type podKey struct {
	namespace string
	name      string
}

// Watcher holds the IP to zone mapping for local pods.
type Watcher struct {
	client    kubernetes.Interface
	nodeName  string
	zoneLabel string

	// OnReady is called once after the informer completes its first sync.
	OnReady func()

	mu sync.RWMutex
	// byPod records the IP each indexed pod currently occupies, so that when a pod
	// changes IP, loses eligibility (its zone label removed or emptied) or is
	// deleted, the old mapping is reclaimed precisely rather than only ever added
	// to.
	byPod map[podKey]netip.Addr
	byIP  map[netip.Addr]string
	ready bool
}

// New builds a Watcher that has not started yet.
func New(client kubernetes.Interface, nodeName, zoneLabel string) *Watcher {
	return &Watcher{
		client:    client,
		nodeName:  nodeName,
		zoneLabel: zoneLabel,
		byIP:      make(map[netip.Addr]string),
		byPod:     make(map[podKey]netip.Addr),
	}
}

// resyncPeriod is how often the informer re-delivers Update events even when an
// object has not really changed. Overridable in tests, following the
// timeNow/newUpstream test hooks used elsewhere in this repo.
//
// This is the self-healing mechanism for the pod IP reuse race described above
// upsert/remove: if the Add for a reused IP arrives before the old pod's Delete,
// that Delete wipes the byIP entry the new pod just wrote while byPod still
// points at the IP. The informer re-delivers events only when an object really
// changes, so without a resync the inconsistency sits there until that pod
// happens to change again — which is to say it never heals on its own. A resync
// forces one Update for every object currently known, letting upsert overwrite
// byIP back to the correct value from the PodIP as it actually stands, even
// though the object itself has not changed.
//
// Ten minutes is chosen to be far longer than the race window, which is the
// delivery-order gap between two single events. The node holds pods on the order
// of dozens (see the package doc), so re-running upsert over all of them every
// ten minutes costs nothing measurable, while still bounding a window that would
// otherwise last until the next real change.
var resyncPeriod = 10 * time.Minute

// Run starts the informer and keeps it synced until ctx ends.
func (w *Watcher) Run(ctx context.Context) error {
	factory := informers.NewSharedInformerFactoryWithOptions(w.client, resyncPeriod,
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

	// Once the informer stops, the table no longer tracks reality. Mark it
	// not-ready so queries take the path that declares no zone, rather than keep
	// answering from a mapping that only grows staler.
	w.mu.Lock()
	w.ready = false
	w.mu.Unlock()
	return nil
}

// upsert takes in a pod's latest state.
//
// Four kinds of pod are deliberately left out of the table:
//   - hostNetwork: its IP is the node IP, shared by every hostNetwork pod on the
//     node, so they cannot be told apart and any mapping would be arbitrary
//   - no zone label, or an empty value: it must not map to the empty-string zone,
//     which downstream would treat as a real zone
//   - a zone label value that ednszone.Valid rejects — "zone.a" with its dot, a
//     legal Kubernetes label value the wire format cannot carry. The reason is
//     the same one that makes internal/registry and plugin/zonedns/setup.go
//     refuse the same strings: such a pod's zone declaration, once it reaches
//     central, is certain to be judged invalid by ednszone.Get and discarded (see
//     that package's Valid doc), meaning central necessarily treats it as no
//     declaration at all. Indexing it here anyway would have the local
//     zone_resolution_total report result="ok" and the answer go out normally,
//     looking entirely fine, while this pod's zone declaration has never once
//     been believed by central — the agent's verdict of "success" and central's
//     verdict of "failure" would disagree completely, with no metric to point at
//     the gap. Leaving it unindexed, so it lands in result="unknown" like a pod
//     with no label, reports the truth: this pod is not getting zone-aware
//     answers.
//   - no IP yet (Pending): there is no key to index by
//
// These conditions decide not only what to add but what to reclaim. A pod
// changing IP, losing its zone label, or having that label emptied is a
// transition from eligible to not-indexed-this-time, and the old mapping must go
// with it — otherwise the old IP, or the old zone, stays in the table
// indefinitely, with the same effect as a deletion that did not clean up: the pod
// that next leases that IP inherits the previous tenant's zone, and the answer
// looks entirely normal. byPod remembers which IP each pod was last successfully
// indexed under, so the reclaim here is precise rather than a guess.
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
		if !hasLabel || z == "" || !ednszone.Valid(z) {
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

// remove drops a pod's mapping.
//
// Removing immediately is necessary: pod IPs are recycled to new pods, and
// keeping the old value would give the new pod the previous tenant's zone — an
// answer that looks entirely normal. It consults byPod rather than re-parsing
// pod.Status.PodIP, so it always reclaims exactly the IP this pod was actually
// indexed under, and covers the case where the pod never qualified and byPod
// never held it (nothing to do).
func (w *Watcher) remove(obj any) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		// On a relist the informer may hand over a DeletedFinalStateUnknown.
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

// Zone finds the zone an IP belongs to.
//
// Before the watcher is ready it always returns false: queries during startup
// take the non-zone-aware path rather than guess a zone that could be wrong.
func (w *Watcher) Zone(ip netip.Addr) (string, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if !w.ready {
		return "", false
	}
	zone, ok := w.byIP[ip]
	return zone, ok
}

// Ready reports whether the informer has completed its first sync.
func (w *Watcher) Ready() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.ready
}

// Len returns the number of pods currently indexed.
func (w *Watcher) Len() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.byIP)
}
