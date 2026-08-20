//go:build cluster

// These tests need a real Kubernetes cluster with at least two nodes, so they
// sit behind a build tag and an ordinary go test ./... does not reach them. CI
// brings up a kind cluster and runs them with -tags=cluster.
//
// Why a real cluster is required: the fake.NewSimpleClientset used by the unit
// tests does not apply field selectors — its object tracker ignores them
// outright. So "the informer sees only this node's pods" has never actually
// happened in any other test, and it is the premise for the node mapping a source
// IP to the right workload.
package podzone

import (
	"context"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// Matching deploy/k8s/01-rbac.yaml — what these tests check is whether the
	// permissions that manifest grants are sufficient, so no separate, more
	// permissive ServiceAccount is created.
	saNamespace = "kube-system"
	saName      = "node-local-dns"
	pauseImage  = "registry.k8s.io/pause:3.10"
)

// namespaceFor gives every test its own namespace.
//
// Sharing one breaks: namespace deletion is asynchronous, so cleanup from the
// previous test leaves it in Terminating, and creating resources in that state is
// refused — reorder the tests and it falls over.
func namespaceFor(t *testing.T) string {
	t.Helper()
	name := "zonedns-it-" + strings.ToLower(t.Name())
	name = strings.NewReplacer("/", "-", "_", "-").Replace(name)
	if len(name) > 63 {
		name = name[:63]
	}
	return strings.Trim(name, "-")
}

// adminClient builds a client with the KUBECONFIG identity, used only to set up
// and clean up test data.
func adminClient(t *testing.T) *kubernetes.Clientset {
	t.Helper()
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(), nil).ClientConfig()
	if err != nil {
		t.Fatalf("loading kubeconfig: %v", err)
	}
	c, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("building the admin client: %v", err)
	}
	return c
}

// scopedClient builds a client from the node-local-dns ServiceAccount's token.
//
// The informer uses this client, so a passing test means the permissions granted
// by deploy/k8s/01-rbac.yaml really are sufficient; were the RBAC short, the
// informer could not sync and the test would fail on timeout.
func scopedClient(t *testing.T, admin *kubernetes.Clientset) *kubernetes.Clientset {
	t.Helper()
	ctx := context.Background()

	tok, err := admin.CoreV1().ServiceAccounts(saNamespace).CreateToken(ctx, saName,
		&authv1.TokenRequest{Spec: authv1.TokenRequestSpec{
			ExpirationSeconds: ptr(int64(3600)),
		}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("obtaining a token for %s/%s (was the RBAC manifest applied?): %v", saNamespace, saName, err)
	}

	base, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(), nil).ClientConfig()
	if err != nil {
		t.Fatalf("loading kubeconfig: %v", err)
	}
	// Keep only the connection details and the CA, swapping the identity for the
	// ServiceAccount's token.
	cfg := &rest.Config{
		Host:            base.Host,
		TLSClientConfig: rest.TLSClientConfig{CAData: base.CAData, CAFile: base.CAFile},
		BearerToken:     tok.Status.Token,
	}
	c, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("building the scoped client: %v", err)
	}
	return c
}

func ptr[T any](v T) *T { return &v }

// twoNodes returns the names of two different nodes.
func twoNodes(t *testing.T, c *kubernetes.Clientset) (string, string) {
	t.Helper()
	nodes, err := c.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("listing nodes: %v", err)
	}
	if len(nodes.Items) < 2 {
		t.Fatalf("verifying the field selector needs at least two nodes, found %d", len(nodes.Items))
	}
	return nodes.Items[0].Name, nodes.Items[1].Name
}

// createPod sets nodeName directly, bypassing the scheduler so the placement is
// certain.
func createPod(t *testing.T, c *kubernetes.Clientset, ns, name, node, zone string) *corev1.Pod {
	t.Helper()
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.PodSpec{
			NodeName:      node,
			RestartPolicy: corev1.RestartPolicyNever,
			Tolerations:   []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
			Containers:    []corev1.Container{{Name: "pause", Image: pauseImage}},
		},
	}
	if zone != "" {
		p.Labels = map[string]string{"zone": zone}
	}
	got, err := c.CoreV1().Pods(ns).Create(context.Background(), p, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("creating pod %s: %v", name, err)
	}
	return got
}

// waitForPodIP waits until the pod has an IP.
func waitForPodIP(t *testing.T, c *kubernetes.Clientset, ns, name string) netip.Addr {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		p, err := c.CoreV1().Pods(ns).Get(context.Background(), name, metav1.GetOptions{})
		if err == nil && p.Status.PodIP != "" {
			addr, err := netip.ParseAddr(p.Status.PodIP)
			if err == nil {
				return addr
			}
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("pod %s did not get an IP in time", name)
	return netip.Addr{}
}

// setupNamespace creates the test namespace and registers its cleanup.
func setupNamespace(t *testing.T, c *kubernetes.Clientset) string {
	t.Helper()
	ctx := context.Background()
	ns := namespaceFor(t)
	_, err := c.CoreV1().Namespaces().Create(ctx,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("creating the namespace: %v", err)
	}
	t.Cleanup(func() {
		_ = c.CoreV1().Namespaces().Delete(context.Background(), ns, metav1.DeleteOptions{})
	})
	return ns
}

// startWatcher runs the watcher and waits until it is ready. Readiness is itself
// the evidence that the RBAC suffices.
func startWatcher(t *testing.T, c *kubernetes.Clientset, nodeName string) *Watcher {
	t.Helper()
	w := New(c, nodeName, "zone")
	ready := make(chan struct{})
	w.OnReady = func() { close(ready) }

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = w.Run(ctx) }()

	select {
	case <-ready:
	case <-time.After(60 * time.Second):
		t.Fatal("the informer was not ready within 60s — most likely the permissions in deploy/k8s/01-rbac.yaml are insufficient")
	}
	return w
}

// eventually re-checks until the condition holds or the deadline passes. The
// informer is asynchronous, so assertions must tolerate delay.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timed out: %s", what)
}

// This is the file's reason to exist: proving the field selector takes effect
// against a real API server. The fake clientset ignores field selectors, so this
// has never actually happened in any other test.
func TestClusterFieldSelectorScopesToLocalNode(t *testing.T) {
	if os.Getenv("KUBECONFIG") == "" && os.Getenv("HOME") == "" {
		t.Skip("no kubeconfig")
	}
	admin := adminClient(t)
	ns := setupNamespace(t, admin)
	nodeA, nodeB := twoNodes(t, admin)
	t.Logf("nodeA=%s nodeB=%s", nodeA, nodeB)

	createPod(t, admin, ns, "local-a", nodeA, "zone-a")
	createPod(t, admin, ns, "remote-b", nodeB, "zone-b")
	localIP := waitForPodIP(t, admin, ns, "local-a")
	remoteIP := waitForPodIP(t, admin, ns, "remote-b")

	w := startWatcher(t, scopedClient(t, admin), nodeA)

	eventually(t, "the local pod should be indexed", func() bool {
		z, ok := w.Zone(localIP)
		return ok && z == "zone-a"
	})
	// The pod on the other node has an IP and a zone label; the node is the only
	// difference — were the field selector not in effect, it would be indexed.
	if z, ok := w.Zone(remoteIP); ok {
		t.Fatalf("a pod from another node was indexed (zone=%q) — the field selector is not in effect", z)
	}
}

// A pod with no zone label must not be indexed under the empty zone.
func TestClusterPodWithoutZoneLabelNotIndexed(t *testing.T) {
	admin := adminClient(t)
	ns := setupNamespace(t, admin)
	nodeA, _ := twoNodes(t, admin)

	createPod(t, admin, ns, "labelled", nodeA, "zone-a")
	createPod(t, admin, ns, "unlabelled", nodeA, "")
	labelledIP := waitForPodIP(t, admin, ns, "labelled")
	unlabelledIP := waitForPodIP(t, admin, ns, "unlabelled")

	w := startWatcher(t, scopedClient(t, admin), nodeA)

	eventually(t, "the labelled pod should be indexed", func() bool {
		_, ok := w.Zone(labelledIP)
		return ok
	})
	if z, ok := w.Zone(unlabelledIP); ok {
		t.Fatalf("a pod with no zone label was indexed as %q", z)
	}
}

// Removing the zone label from a live pod must invalidate the mapping at once.
//
// The unit test for this path uses the fake clientset; what is checked here is a
// real informer's update event. It guards a Critical the Task 3 review caught:
// the original upsert only added and never removed, so a pod that lost its
// eligibility left behind a mapping that never expired, and once its IP was
// recycled the new pod inherited the previous tenant's zone.
func TestClusterLabelRemovalEvictsImmediately(t *testing.T) {
	admin := adminClient(t)
	ns := setupNamespace(t, admin)
	nodeA, _ := twoNodes(t, admin)

	pod := createPod(t, admin, ns, "relabelled", nodeA, "zone-a")
	ip := waitForPodIP(t, admin, ns, pod.Name)

	w := startWatcher(t, scopedClient(t, admin), nodeA)
	eventually(t, "should be indexed initially", func() bool {
		z, ok := w.Zone(ip)
		return ok && z == "zone-a"
	})

	// Remove the label
	cur, err := admin.CoreV1().Pods(ns).Get(context.Background(), pod.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("getting the pod: %v", err)
	}
	delete(cur.Labels, "zone")
	if _, err := admin.CoreV1().Pods(ns).Update(context.Background(), cur, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("updating the pod: %v", err)
	}

	eventually(t, "should be invalidated immediately after the label is removed", func() bool {
		_, ok := w.Zone(ip)
		return !ok
	})
}
