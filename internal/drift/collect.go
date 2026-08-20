package drift

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// HostLabel 是 workload 用來宣告自己對外名稱的 label —— 同一個值會被
// ClusterSPIFFEID 的 dnsNameTemplates 渲染成 SPIRE entry 的 dns_name。
const HostLabel = "zonedns.io/host"

// VirtualServiceGVRs 是要嘗試的 VirtualService 資源版本，依序嘗試。
//
// Istio 1.22 起主推 v1，先前是 v1beta1，兩者服務同一批物件。這裡不做 discovery：
// 依序試、第一個列得出來的就用它，少一次 API 往返也少一份權限需求。
func VirtualServiceGVRs() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{
		{Group: "networking.istio.io", Version: "v1", Resource: "virtualservices"},
		{Group: "networking.istio.io", Version: "v1beta1", Resource: "virtualservices"},
	}
}

// Skipped 記錄一筆被排除在比對之外的名稱，以及排除的理由。
//
// 這些不是漂移，但要能印出來：一個「乾淨」的報告如果其實是把所有東西都跳過了，
// 那跟真的沒有漂移看起來一模一樣 —— 正是這個專案反覆在抓的那種失敗形狀。
type Skipped struct {
	Source string // VirtualService 的 namespace/name
	Host   string
	Reason SkipReason
}

// CollectVirtualServiceHosts 走訪 VirtualService，取出要參與比對的 host。
//
// namespace 為空字串代表整個 cluster —— 那是正式用途的預設值。指定 namespace 只
// 適合測試與範圍受限的檢查：Istio 允許 A namespace 的 VirtualService 指向 B
// namespace 的服務，所以縮小範圍會把那種情形誤報成「沒有 pod 認領」。
func CollectVirtualServiceHosts(ctx context.Context, client dynamic.Interface, clusterDomain, namespace string) (hosts []string, skipped []Skipped, err error) {
	list, err := listVirtualServices(ctx, client, namespace)
	if err != nil {
		return nil, nil, err
	}

	for i := range list.Items {
		vs := &list.Items[i]
		source := vs.GetNamespace() + "/" + vs.GetName()

		gateways, err := stringSlice(vs, "spec", "gateways")
		if err != nil {
			return nil, nil, fmt.Errorf("VirtualService %s: %w", source, err)
		}
		vsHosts, err := stringSlice(vs, "spec", "hosts")
		if err != nil {
			return nil, nil, fmt.Errorf("VirtualService %s: %w", source, err)
		}

		if reason := ShouldSkipVirtualService(gateways); reason != "" {
			for _, h := range vsHosts {
				skipped = append(skipped, Skipped{Source: source, Host: h, Reason: reason})
			}
			continue
		}
		for _, h := range vsHosts {
			if reason := ShouldSkipHost(h, clusterDomain); reason != "" {
				skipped = append(skipped, Skipped{Source: source, Host: h, Reason: reason})
				continue
			}
			hosts = append(hosts, h)
		}
	}
	return hosts, skipped, nil
}

// listVirtualServices 依序嘗試各個 API 版本，回傳第一個列得出來的結果。
//
// 全部版本都不存在時回傳錯誤而不是空清單：叢集裡沒有 Istio CRD，和叢集裡沒有
// VirtualService，對這支工具而言是天差地別的兩件事 —— 後者代表沒有漂移，
// 前者代表這次檢查根本沒檢查到東西。
func listVirtualServices(ctx context.Context, client dynamic.Interface, namespace string) (*unstructured.UnstructuredList, error) {
	var lastErr error
	for _, gvr := range VirtualServiceGVRs() {
		list, err := client.Resource(gvr).Namespace(namespace).List(ctx, metav1.ListOptions{})
		if err == nil {
			return list, nil
		}
		if !errors.IsNotFound(err) {
			return nil, fmt.Errorf("listing %s: %w", gvr.GroupVersion(), err)
		}
		lastErr = err
	}
	return nil, fmt.Errorf("no VirtualService CRD served at any known version (%v): %w", VirtualServiceGVRs(), lastErr)
}

// CollectPodHosts 取出帶 hostLabel 的 pod 所宣告的名稱。namespace 為空字串代表
// 整個 cluster，語意與 CollectVirtualServiceHosts 相同。
func CollectPodHosts(ctx context.Context, client kubernetes.Interface, hostLabel, namespace string) ([]string, error) {
	pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: hostLabel,
	})
	if err != nil {
		return nil, fmt.Errorf("listing pods with label %s: %w", hostLabel, err)
	}
	hosts := make([]string, 0, len(pods.Items))
	for i := range pods.Items {
		hosts = append(hosts, pods.Items[i].Labels[hostLabel])
	}
	return hosts, nil
}

// stringSlice 讀出一個字串陣列欄位。欄位不存在視為空陣列；存在但型別不對則報錯 ——
// 這種 VirtualService 的意圖無從得知，靜靜當成沒有 host 會讓它逃過比對。
func stringSlice(obj *unstructured.Unstructured, fields ...string) ([]string, error) {
	out, found, err := unstructured.NestedStringSlice(obj.Object, fields...)
	if err != nil {
		return nil, fmt.Errorf("field %v is not a list of strings: %w", fields, err)
	}
	if !found {
		return nil, nil
	}
	return out, nil
}
