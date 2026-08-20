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

// newDynamic 建出一個只服務 servedVersion 的 fake dynamic client。
//
// fake client 對未註冊的 list kind 會 panic，而真的 API server 是回 404。
// 這裡把兩個版本都註冊起來，再用 reactor 讓沒被服務的那個回傳真正的 NotFound，
// 讓版本回退的分支面對的是它在正式環境會遇到的那個錯誤型別。
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
			return false, nil, nil // 交給預設的 tracker 處理
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

	hosts, skipped, err := CollectVirtualServiceHosts(context.Background(), client, DefaultClusterDomain)
	if err != nil {
		t.Fatalf("CollectVirtualServiceHosts: %v", err)
	}
	if want := []string{"payments.example.com"}; !reflect.DeepEqual(hosts, want) {
		t.Errorf("hosts = %v, want %v", hosts, want)
	}

	// 被跳過的東西必須留下痕跡：一份「沒有漂移」的報告如果其實是把所有名稱都
	// 濾掉了，看起來會跟真的沒有漂移一模一樣。
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
	hosts, _, err := CollectVirtualServiceHosts(context.Background(), client, DefaultClusterDomain)
	if err != nil {
		t.Fatalf("CollectVirtualServiceHosts: %v", err)
	}
	if want := []string{"payments.example.com"}; !reflect.DeepEqual(hosts, want) {
		t.Errorf("hosts = %v, want %v", hosts, want)
	}
}

func TestCollectVirtualServiceHostsRejectsMalformedSpec(t *testing.T) {
	// hosts 寫成字串而不是陣列。靜靜當成「這個 VirtualService 沒有 host」會讓它
	// 完全逃過比對 —— 而它可能正是漂移的那一個。
	bad := virtualService("v1", "prod", "payments", nil, nil)
	bad.Object["spec"].(map[string]any)["hosts"] = "payments.example.com"

	client := newDynamic(t, "v1", bad)
	if _, _, err := CollectVirtualServiceHosts(context.Background(), client, DefaultClusterDomain); err == nil {
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
	hosts, err := CollectPodHosts(context.Background(), client, HostLabel)
	if err != nil {
		t.Fatalf("CollectPodHosts: %v", err)
	}
	if want := []string{"payments.example.com", "payments.example.com"}; !reflect.DeepEqual(hosts, want) {
		t.Errorf("hosts = %v, want %v", hosts, want)
	}
}

func TestCollectVirtualServiceHostsErrorsWhenNoCRD(t *testing.T) {
	// 叢集裡沒裝 Istio CRD，和叢集裡沒有任何 VirtualService，對這支工具是天差
	// 地別的兩件事：後者代表沒有漂移，前者代表這次檢查根本什麼都沒檢查到。
	// 回空清單會讓「沒裝 Istio」被印成一份漂亮的乾淨報告。
	client := newDynamic(t, "no-such-version")
	_, _, err := CollectVirtualServiceHosts(context.Background(), client, DefaultClusterDomain)
	if err == nil {
		t.Fatal("expected an error when no VirtualService version is served, got nil")
	}
}

func TestCollectVirtualServiceHostsPropagatesNonNotFoundErrors(t *testing.T) {
	// 權限不足（403）不是「這個版本沒被服務」。當成 NotFound 而繼續試下一個版本，
	// 最後會產生一句誤導的「沒有 CRD」—— 真正的原因是 RBAC。
	client := newDynamic(t, "v1")
	client.PrependReactor("list", "virtualservices", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.NewForbidden(action.GetResource().GroupResource(), "", nil)
	})
	_, _, err := CollectVirtualServiceHosts(context.Background(), client, DefaultClusterDomain)
	if !errors.IsForbidden(err) {
		t.Fatalf("err = %v, want the Forbidden error to propagate unchanged", err)
	}
}
