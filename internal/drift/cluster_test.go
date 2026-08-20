//go:build cluster

// 這些測試需要一個裝了 Istio VirtualService CRD 的真實 Kubernetes cluster，
// 因此以 build tag 隔開，一般的 go test ./... 不會跑到。
//
// 為什麼非得要真實 cluster：單元測試用的 fake dynamic client 對 GVR 不做任何
// 驗證 —— 群組名打錯、資源複數形寫錯、版本根本沒被服務，它一樣照列不誤。
// 也就是說「這支工具真的讀得到 VirtualService」這件事，在其他測試裡從來沒有
// 被證明過，而它是整個檢查的前提：讀不到就等於沒有漂移，一份漂亮的乾淨報告。
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
		t.Fatalf("載入 kubeconfig: %v", err)
	}
	return cfg
}

func clients(t *testing.T) (*kubernetes.Clientset, dynamic.Interface) {
	t.Helper()
	cfg := config(t)
	typed, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("建立 typed client: %v", err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("建立 dynamic client: %v", err)
	}
	return typed, dyn
}

func makeNamespace(t *testing.T, typed *kubernetes.Clientset, name string) {
	t.Helper()
	ctx := context.Background()
	_, err := typed.CoreV1().Namespaces().Create(ctx,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("建立 namespace %s: %v", name, err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		if err := typed.CoreV1().Namespaces().Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
			t.Errorf("刪除 namespace %s: %v", name, err)
			return
		}
		// 一定要等到真的消失。namespace 的刪除是非同步的，裡面的 pod 會停在
		// Terminating 而依然被 list 得到 —— 同一個 CI job 裡後續的步驟會讀到
		// 它們，於是一個「無人認領」的 host 突然變成有人認領。
		waitNamespaceGone(ctx, t, typed, name)
	})
}

// applyVirtualService 用 dynamic client 建一個真的 VirtualService。
//
// 這裡刻意不做版本回退：測試要證明的是 CollectVirtualServiceHosts 找得到它，
// 所以建立時就固定用 v1beta1 —— 從 Istio 1.10 到現在每個版本都服務這個版本。
func applyVirtualService(t *testing.T, dyn dynamic.Interface, namespace, name string, gateways, hosts []string) {
	t.Helper()
	gvr := VirtualServiceGVRs()[len(VirtualServiceGVRs())-1]

	spec := map[string]any{
		"hosts": anySlice(hosts),
		// route 是 CRD 的必填欄位。指到哪裡對這個檢查不重要 —— 工具只讀 hosts。
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
		t.Fatalf("建立 VirtualService %s/%s: %v", namespace, name, err)
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
		t.Fatalf("建立 pod %s/%s: %v", namespace, name, err)
	}
}

// TestClusterReadsRealVirtualServices 證明 GVR 對得上真實 API server，而且
// 版本回退在只服務 v1beta1 的叢集上真的會回退。
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
		t.Errorf("沒有讀到對外名稱，hosts = %v", hosts)
	}
	// 反向確認：如果排除規則失效，短名和 cluster 內部名稱會混進比對而造成假警報。
	for _, unwanted := range []string{"payments", "payments." + ns + ".svc.cluster.local"} {
		if contains(hosts, unwanted) {
			t.Errorf("%q 不該參與比對，hosts = %v", unwanted, hosts)
		}
	}
	if len(skipped) < 2 {
		t.Errorf("被排除的名稱沒有留下記錄，skipped = %v", skipped)
	}
}

// TestClusterDetectsDrift 是變異驗證：同一組資料，只把 label 改成打錯的名字，
// 檢查必須從乾淨變成報警。若兩種情況都說乾淨，這個檢查等於沒在檢查。
func TestClusterDetectsDrift(t *testing.T) {
	typed, dyn := clients(t)
	ns := "zonedns-drift-detect"
	makeNamespace(t, typed, ns)

	applyVirtualService(t, dyn, ns, "payments", nil, []string{"payments.example.com"})
	applyPod(t, typed, ns, "payments-matching", "payments.example.com")

	report := compareCluster(t, typed, dyn, ns)
	if !report.OK() {
		t.Fatalf("名稱一致時仍報出漂移：%+v", report)
	}

	// 改掉 label —— 這正是真實世界的漂移：有人改了名字，只改了一邊。
	applyPod(t, typed, ns, "payments-drifted", "paymnets.example.com")

	report = compareCluster(t, typed, dyn, ns)
	if report.OK() {
		t.Fatal("label 打錯字後仍報告沒有漂移")
	}
	if !contains(report.UnroutedLabels, "paymnets.example.com") {
		t.Errorf("沒有指出打錯字的 label，UnroutedLabels = %v", report.UnroutedLabels)
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

// TestClusterUnservedVersionIsNotFound 釘住版本回退所依賴的那個假設：真實 API
// server 對沒有被服務的版本回的是 NotFound。
//
// 如果它回的是別的東西（例如某種 discovery 錯誤），listVirtualServices 會在第一個
// 版本就放棄，於是只裝了 v1beta1 的舊叢集會拿到「沒有 CRD」——  一句與事實相反
// 的錯誤訊息，而使用者會以為自己沒裝 Istio。
func TestClusterUnservedVersionIsNotFound(t *testing.T) {
	_, dyn := clients(t)
	gvr := VirtualServiceGVRs()[0]
	gvr.Version = "v1alpha9" // 不存在的版本

	_, err := dyn.Resource(gvr).Namespace(metav1.NamespaceAll).
		List(context.Background(), metav1.ListOptions{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("列出未被服務的版本得到 %v，預期是 NotFound", err)
	}
}

// waitNamespaceGone 等到 namespace 真的從 API server 消失。
func waitNamespaceGone(ctx context.Context, t *testing.T, typed *kubernetes.Clientset, name string) {
	t.Helper()
	for {
		_, err := typed.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return
		}
		select {
		case <-ctx.Done():
			t.Errorf("等待 namespace %s 消失逾時", name)
			return
		case <-time.After(time.Second):
		}
	}
}
