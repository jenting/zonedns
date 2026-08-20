//go:build cluster

// These tests need a real Kubernetes cluster with the Istio VirtualService CRD
// installed, so they sit behind a build tag and an ordinary go test ./... does
// not reach them.
//
// Why a real cluster is required: the fake dynamic client used by the unit tests
// validates nothing about the GVR — a misspelled group, a wrong resource plural,
// a version that is not served at all, and it lists happily anyway. Which means
// "this tool can actually read VirtualServices" has never been proven by any
// other test, and it is the premise of the whole check: not being able to read
// them looks exactly like having no drift, a nice clean report.
package drift

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func config(t *testing.T) *rest.Config {
	t.Helper()
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(), nil).ClientConfig()
	if err != nil {
		t.Fatalf("loading kubeconfig: %v", err)
	}
	return cfg
}

func clients(t *testing.T) (*kubernetes.Clientset, dynamic.Interface) {
	t.Helper()
	cfg := config(t)
	typed, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("building the typed client: %v", err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("building the dynamic client: %v", err)
	}
	return typed, dyn
}

func makeNamespace(t *testing.T, typed *kubernetes.Clientset, name string) {
	t.Helper()
	ctx := context.Background()
	_, err := typed.CoreV1().Namespaces().Create(ctx,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("creating namespace %s: %v", name, err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		if err := typed.CoreV1().Namespaces().Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
			t.Errorf("deleting namespace %s: %v", name, err)
			return
		}
		// Wait until it is really gone. Namespace deletion is asynchronous: the
		// pods inside linger in Terminating and are still returned by a list, so
		// later steps in the same CI job read them and a host that should be
		// unclaimed suddenly has a claimant.
		waitNamespaceGone(ctx, t, typed, name)
	})
}

// applyVirtualService creates a real VirtualService through the dynamic client.
//
// It deliberately does no version fallback: the point is to prove that
// CollectVirtualServiceHosts finds the object, so creation pins v1beta1 — every
// Istio release from 1.10 onwards serves that version.
func applyVirtualService(t *testing.T, dyn dynamic.Interface, namespace, name string, gateways, hosts []string) {
	t.Helper()
	gvr := VirtualServiceGVRs()[len(VirtualServiceGVRs())-1]

	spec := map[string]any{
		"hosts": anySlice(hosts),
		// route is a required field of the CRD. Where it points does not matter
		// here — the tool reads only hosts.
		"http": []any{map[string]any{
			"route": []any{map[string]any{
				"destination": map[string]any{"host": hosts[0]},
			}},
		}},
	}
	if gateways != nil {
		spec["gateways"] = anySlice(gateways)
	}
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": gvr.GroupVersion().String(),
		"kind":       "VirtualService",
		"metadata":   map[string]any{"name": name},
		"spec":       spec,
	}}

	ctx := context.Background()
	if _, err := dyn.Resource(gvr).Namespace(namespace).Create(ctx, obj, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating VirtualService %s/%s: %v", namespace, name, err)
	}
}

func anySlice(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

func applyPod(t *testing.T, typed *kubernetes.Clientset, namespace, name, host string) {
	t.Helper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    map[string]string{HostLabel: host},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name:  "pause",
			Image: "registry.k8s.io/pause:3.10",
		}}},
	}
	if _, err := typed.CoreV1().Pods(namespace).Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating pod %s/%s: %v", namespace, name, err)
	}
}

// TestClusterReadsRealVirtualServices proves the GVR matches a real API server,
// and that the version fallback really falls back on a cluster serving only
// v1beta1.
func TestClusterReadsRealVirtualServices(t *testing.T) {
	typed, dyn := clients(t)
	ns := "zonedns-drift-read"
	makeNamespace(t, typed, ns)

	applyVirtualService(t, dyn, ns, "payments", nil,
		[]string{"payments.example.com", "payments", "payments." + ns + ".svc.cluster.local"})

	hosts, skipped, err := CollectVirtualServiceHosts(context.Background(), dyn, DefaultClusterDomain, ns)
	if err != nil {
		t.Fatalf("CollectVirtualServiceHosts: %v", err)
	}
	if !contains(hosts, "payments.example.com") {
		t.Errorf("the external name was not read, hosts = %v", hosts)
	}
	// The reverse check: if the skip rules stop working, short names and
	// cluster-internal names join the comparison and produce false alarms.
	for _, unwanted := range []string{"payments", "payments." + ns + ".svc.cluster.local"} {
		if contains(hosts, unwanted) {
			t.Errorf("%q must not take part in the comparison, hosts = %v", unwanted, hosts)
		}
	}
	if len(skipped) < 2 {
		t.Errorf("the excluded names left no record, skipped = %v", skipped)
	}
}

// TestClusterDetectsDrift is a mutation check: same data, only the label changed
// to a misspelled name, and the check must go from clean to alarming. If both
// cases report clean, the check is not checking anything.
func TestClusterDetectsDrift(t *testing.T) {
	typed, dyn := clients(t)
	ns := "zonedns-drift-detect"
	makeNamespace(t, typed, ns)

	applyVirtualService(t, dyn, ns, "payments", nil, []string{"payments.example.com"})
	applyPod(t, typed, ns, "payments-matching", "payments.example.com")

	report := compareCluster(t, typed, dyn, ns)
	if !report.OK() {
		t.Fatalf("drift reported while the names agree: %+v", report)
	}

	// Change the label — this is drift as it happens in the real world: somebody
	// renamed the service and changed only one side.
	applyPod(t, typed, ns, "payments-drifted", "paymnets.example.com")

	report = compareCluster(t, typed, dyn, ns)
	if report.OK() {
		t.Fatal("no drift reported after the label was misspelled")
	}
	if !contains(report.UnroutedLabels, "paymnets.example.com") {
		t.Errorf("the misspelled label was not named, UnroutedLabels = %v", report.UnroutedLabels)
	}
}

func compareCluster(t *testing.T, typed *kubernetes.Clientset, dyn dynamic.Interface, ns string) Report {
	t.Helper()
	ctx := context.Background()
	vsHosts, _, err := CollectVirtualServiceHosts(ctx, dyn, DefaultClusterDomain, ns)
	if err != nil {
		t.Fatalf("CollectVirtualServiceHosts: %v", err)
	}
	podHosts, err := CollectPodHosts(ctx, typed, HostLabel, ns)
	if err != nil {
		t.Fatalf("CollectPodHosts: %v", err)
	}
	return Compare(vsHosts, podHosts)
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// TestClusterUnservedVersionIsNotFound pins the assumption the version fallback
// rests on: a real API server answers NotFound for a version it does not serve.
//
// If it answered something else (some discovery error, say), listVirtualServices
// would give up on the first version, and an older cluster carrying only v1beta1
// would be told there is "no CRD" — an error message contrary to the fact, and
// users would conclude they had not installed Istio.
func TestClusterUnservedVersionIsNotFound(t *testing.T) {
	_, dyn := clients(t)
	gvr := VirtualServiceGVRs()[0]
	gvr.Version = "v1alpha9" // a version that does not exist

	_, err := dyn.Resource(gvr).Namespace(metav1.NamespaceAll).
		List(context.Background(), metav1.ListOptions{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("listing an unserved version gave %v, want NotFound", err)
	}
}

// waitNamespaceGone waits until the namespace really disappears from the API
// server.
func waitNamespaceGone(ctx context.Context, t *testing.T, typed *kubernetes.Clientset, name string) {
	t.Helper()
	for {
		_, err := typed.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return
		}
		select {
		case <-ctx.Done():
			t.Errorf("timed out waiting for namespace %s to disappear", name)
			return
		case <-time.After(time.Second):
		}
	}
}
