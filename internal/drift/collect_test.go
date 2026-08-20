package drift

import (
	"context"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func virtualService(version, namespace, name string, gateways, hosts []string) *unstructured.Unstructured {
	spec := map[string]any{"hosts": toAnySlice(hosts)}
	if gateways != nil {
		spec["gateways"] = toAnySlice(gateways)
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "networking.istio.io/" + version,
		"kind":       "VirtualService",
		"metadata":   map[string]any{"namespace": namespace, "name": name},
		"spec":       spec,
	}}
}

func toAnySlice(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

// newDynamic builds a fake dynamic client that serves only servedVersion.
//
// The fake client panics on an unregistered list kind, whereas a real API server
// returns 404. Both versions are registered here and a reactor makes the
// unserved one return a genuine NotFound, so the version-fallback branch faces
// the error type it will meet in production.
func newDynamic(t *testing.T, servedVersion string, objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	t.Helper()

	listKinds := map[schema.GroupVersionResource]string{}
	for _, gvr := range VirtualServiceGVRs() {
		listKinds[gvr] = "VirtualServiceList"
	}
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, objs...)

	client.PrependReactor("list", "virtualservices", func(action k8stesting.Action) (bool, runtime.Object, error) {
		gvr := action.GetResource()
		if gvr.Version == servedVersion {
			return false, nil, nil // let the default tracker handle it
		}
		return true, nil, errors.NewNotFound(gvr.GroupResource(), "")
	})
	return client
}

func TestCollectVirtualServiceHosts(t *testing.T) {
	client := newDynamic(t, "v1",
		virtualService("v1", "prod", "payments", nil, []string{"payments.example.com", "payments", "payments.prod.svc.cluster.local"}),
		virtualService("v1", "prod", "ingress", []string{"istio-ingressgateway"}, []string{"www.example.com"}),
		virtualService("v1", "prod", "wild", nil, []string{"*.example.com"}),
	)

	hosts, skipped, err := CollectVirtualServiceHosts(context.Background(), client, DefaultClusterDomain, "")
	if err != nil {
		t.Fatalf("CollectVirtualServiceHosts: %v", err)
	}
	if want := []string{"payments.example.com"}; !reflect.DeepEqual(hosts, want) {
		t.Errorf("hosts = %v, want %v", hosts, want)
	}

	// What was skipped must leave a trace: a "no drift" report that really
	// filtered every name away looks exactly like one with no drift in it.
	gotReasons := map[string]SkipReason{}
	for _, s := range skipped {
		gotReasons[s.Host] = s.Reason
	}
	wantReasons := map[string]SkipReason{
		"payments":                        SkipShortName,
		"payments.prod.svc.cluster.local": SkipClusterLocal,
		"www.example.com":                 SkipGatewayBound,
		"*.example.com":                   SkipWildcard,
	}
	if !reflect.DeepEqual(gotReasons, wantReasons) {
		t.Errorf("skipped = %v, want %v", gotReasons, wantReasons)
	}
}

func TestCollectVirtualServiceHostsFallsBackToV1beta1(t *testing.T) {
	client := newDynamic(t, "v1beta1",
		virtualService("v1beta1", "prod", "payments", nil, []string{"payments.example.com"}),
	)
	hosts, _, err := CollectVirtualServiceHosts(context.Background(), client, DefaultClusterDomain, "")
	if err != nil {
		t.Fatalf("CollectVirtualServiceHosts: %v", err)
	}
	if want := []string{"payments.example.com"}; !reflect.DeepEqual(hosts, want) {
		t.Errorf("hosts = %v, want %v", hosts, want)
	}
}

func TestCollectVirtualServiceHostsRejectsMalformedSpec(t *testing.T) {
	// hosts written as a string instead of an array. Quietly treating that as
	// "this VirtualService has no hosts" would let it escape the comparison
	// entirely — and it may be precisely the one that drifted.
	bad := virtualService("v1", "prod", "payments", nil, nil)
	bad.Object["spec"].(map[string]any)["hosts"] = "payments.example.com"

	client := newDynamic(t, "v1", bad)
	if _, _, err := CollectVirtualServiceHosts(context.Background(), client, DefaultClusterDomain, ""); err == nil {
		t.Fatal("expected an error for a malformed spec.hosts, got nil")
	}
}

func TestCollectPodHosts(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: "prod", Name: "payments-1",
			Labels: map[string]string{HostLabel: "payments.example.com", "zone": "zone-a"},
		}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: "prod", Name: "payments-2",
			Labels: map[string]string{HostLabel: "payments.example.com", "zone": "zone-b"},
		}},
	)
	hosts, err := CollectPodHosts(context.Background(), client, HostLabel, "")
	if err != nil {
		t.Fatalf("CollectPodHosts: %v", err)
	}
	if want := []string{"payments.example.com", "payments.example.com"}; !reflect.DeepEqual(hosts, want) {
		t.Errorf("hosts = %v, want %v", hosts, want)
	}
}

func TestCollectVirtualServiceHostsErrorsWhenNoCRD(t *testing.T) {
	// A cluster without the Istio CRD and a cluster without any VirtualService
	// are entirely different things to this tool: the latter means no drift, the
	// former means the check examined nothing at all. Returning an empty list
	// would print "Istio is not installed" as a nice clean report.
	client := newDynamic(t, "no-such-version")
	_, _, err := CollectVirtualServiceHosts(context.Background(), client, DefaultClusterDomain, "")
	if err == nil {
		t.Fatal("expected an error when no VirtualService version is served, got nil")
	}
}

func TestCollectVirtualServiceHostsPropagatesNonNotFoundErrors(t *testing.T) {
	// Insufficient permission (403) is not "this version is not served".
	// Treating it as NotFound and moving on to the next version ends in a
	// misleading "no CRD" when the real cause is RBAC.
	client := newDynamic(t, "v1")
	client.PrependReactor("list", "virtualservices", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.NewForbidden(action.GetResource().GroupResource(), "", nil)
	})
	_, _, err := CollectVirtualServiceHosts(context.Background(), client, DefaultClusterDomain, "")
	if !errors.IsForbidden(err) {
		t.Fatalf("err = %v, want the Forbidden error to propagate unchanged", err)
	}
}

func TestCollectScopesToNamespace(t *testing.T) {
	// This check was once thrown off in CI by a pod left behind in another
	// namespace. The scoping has to actually take effect, or --namespace is just
	// a flag that looks useful.
	client := newDynamic(t, "v1",
		virtualService("v1", "wanted", "a", nil, []string{"a.example.com"}),
		virtualService("v1", "other", "b", nil, []string{"b.example.com"}),
	)
	hosts, _, err := CollectVirtualServiceHosts(context.Background(), client, DefaultClusterDomain, "wanted")
	if err != nil {
		t.Fatalf("CollectVirtualServiceHosts: %v", err)
	}
	if want := []string{"a.example.com"}; !reflect.DeepEqual(hosts, want) {
		t.Errorf("hosts = %v, want %v", hosts, want)
	}
}

func TestCollectPodHostsScopesToNamespace(t *testing.T) {
	pod := func(ns, name, host string) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name, Labels: map[string]string{HostLabel: host},
		}}
	}
	client := fake.NewSimpleClientset(
		pod("wanted", "a", "a.example.com"),
		pod("other", "b", "b.example.com"),
	)
	hosts, err := CollectPodHosts(context.Background(), client, HostLabel, "wanted")
	if err != nil {
		t.Fatalf("CollectPodHosts: %v", err)
	}
	if want := []string{"a.example.com"}; !reflect.DeepEqual(hosts, want) {
		t.Errorf("hosts = %v, want %v", hosts, want)
	}
}
