//go:build cluster

// 這些測試需要一個至少兩個節點的真實 Kubernetes cluster，因此以 build tag 隔開，
// 一般的 go test ./... 不會跑到。CI 用 kind 起 cluster 後以 -tags=cluster 執行。
//
// 為什麼非得要真實 cluster：單元測試用的 fake.NewSimpleClientset 不套用 field
// selector —— 它的 object tracker 直接忽略。所以「informer 只看本機節點的 pod」
// 這個行為在其他測試裡從來沒有真正發生過，而那正是節點端把 source IP 對應到
// 正確 workload 的前提。
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
	// 與 deploy/k8s/01-rbac.yaml 一致 —— 這個測試要驗的就是那份 manifest 給的
	// 權限夠不夠，所以刻意不另外建一個寬鬆的 ServiceAccount。
	saNamespace = "kube-system"
	saName      = "node-local-dns"
	pauseImage  = "registry.k8s.io/pause:3.10"
)

// namespaceFor 讓每個測試用自己的 namespace。
//
// 共用一個會出問題：namespace 的刪除是非同步的，前一個測試清理時它會停在
// Terminating，而在那個狀態下建立資源會被拒絕 —— 測試順序一換就壞。
func namespaceFor(t *testing.T) string {
	t.Helper()
	name := "zonedns-it-" + strings.ToLower(t.Name())
	name = strings.NewReplacer("/", "-", "_", "-").Replace(name)
	if len(name) > 63 {
		name = name[:63]
	}
	return strings.Trim(name, "-")
}

// adminClient 用 KUBECONFIG 的身分建立 client，只用來準備與清理測試資料。
func adminClient(t *testing.T) *kubernetes.Clientset {
	t.Helper()
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(), nil).ClientConfig()
	if err != nil {
		t.Fatalf("載入 kubeconfig: %v", err)
	}
	c, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("建立 admin client: %v", err)
	}
	return c
}

// scopedClient 以 node-local-dns ServiceAccount 的 token 建立 client。
//
// informer 用這個 client，所以測試若通過，代表 deploy/k8s/01-rbac.yaml 給的權限
// 確實足夠；若 RBAC 不足，informer 會同步不了而測試逾時失敗。
func scopedClient(t *testing.T, admin *kubernetes.Clientset) *kubernetes.Clientset {
	t.Helper()
	ctx := context.Background()

	tok, err := admin.CoreV1().ServiceAccounts(saNamespace).CreateToken(ctx, saName,
		&authv1.TokenRequest{Spec: authv1.TokenRequestSpec{
			ExpirationSeconds: ptr(int64(3600)),
		}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("為 %s/%s 取得 token（RBAC manifest 套用了嗎？）: %v", saNamespace, saName, err)
	}

	base, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(), nil).ClientConfig()
	if err != nil {
		t.Fatalf("載入 kubeconfig: %v", err)
	}
	// 只保留連線資訊與 CA，把身分換成 ServiceAccount 的 token。
	cfg := &rest.Config{
		Host:            base.Host,
		TLSClientConfig: rest.TLSClientConfig{CAData: base.CAData, CAFile: base.CAFile},
		BearerToken:     tok.Status.Token,
	}
	c, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("建立 scoped client: %v", err)
	}
	return c
}

func ptr[T any](v T) *T { return &v }

// twoNodes 回傳兩個不同節點的名稱。
func twoNodes(t *testing.T, c *kubernetes.Clientset) (string, string) {
	t.Helper()
	nodes, err := c.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("列出節點: %v", err)
	}
	if len(nodes.Items) < 2 {
		t.Fatalf("需要至少兩個節點才能驗證 field selector，目前只有 %d 個", len(nodes.Items))
	}
	return nodes.Items[0].Name, nodes.Items[1].Name
}

// createPod 直接指定 nodeName，繞過排程器，讓落點確定。
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
		t.Fatalf("建立 pod %s: %v", name, err)
	}
	return got
}

// waitForPodIP 等到 pod 拿到 IP。
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
	t.Fatalf("pod %s 在期限內沒有拿到 IP", name)
	return netip.Addr{}
}

// setupNamespace 建立測試 namespace，並註冊清理。
func setupNamespace(t *testing.T, c *kubernetes.Clientset) string {
	t.Helper()
	ctx := context.Background()
	ns := namespaceFor(t)
	_, err := c.CoreV1().Namespaces().Create(ctx,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("建立 namespace: %v", err)
	}
	t.Cleanup(func() {
		_ = c.CoreV1().Namespaces().Delete(context.Background(), ns, metav1.DeleteOptions{})
	})
	return ns
}

// startWatcher 啟動 watcher 並等到就緒。就緒本身就是 RBAC 足夠的證據。
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
		t.Fatal("informer 在 60 秒內未就緒 —— 最可能的原因是 deploy/k8s/01-rbac.yaml 的權限不足")
	}
	return w
}

// eventually 反覆檢查直到條件成立或逾時。informer 是非同步的，斷言必須容忍延遲。
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("逾時：%s", what)
}

// 這是本檔存在的理由：驗證 field selector 對真實 API server 生效。
// fake clientset 忽略 field selector，所以這件事在其他測試裡從未真正發生。
func TestClusterFieldSelectorScopesToLocalNode(t *testing.T) {
	if os.Getenv("KUBECONFIG") == "" && os.Getenv("HOME") == "" {
		t.Skip("沒有 kubeconfig")
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

	eventually(t, "本機 pod 應被索引", func() bool {
		z, ok := w.Zone(localIP)
		return ok && z == "zone-a"
	})
	// 另一個節點的 pod 有 IP、有 zone label，唯一的差別就是節點 —— 若 field
	// selector 沒生效，它會被索引。
	if z, ok := w.Zone(remoteIP); ok {
		t.Fatalf("其他節點的 pod 被索引了（zone=%q）—— field selector 沒有生效", z)
	}
}

// 沒有 zone label 的 pod 不可被索引成空 zone。
func TestClusterPodWithoutZoneLabelNotIndexed(t *testing.T) {
	admin := adminClient(t)
	ns := setupNamespace(t, admin)
	nodeA, _ := twoNodes(t, admin)

	createPod(t, admin, ns, "labelled", nodeA, "zone-a")
	createPod(t, admin, ns, "unlabelled", nodeA, "")
	labelledIP := waitForPodIP(t, admin, ns, "labelled")
	unlabelledIP := waitForPodIP(t, admin, ns, "unlabelled")

	w := startWatcher(t, scopedClient(t, admin), nodeA)

	eventually(t, "有 label 的 pod 應被索引", func() bool {
		_, ok := w.Zone(labelledIP)
		return ok
	})
	if z, ok := w.Zone(unlabelledIP); ok {
		t.Fatalf("沒有 zone label 的 pod 被索引成 %q", z)
	}
}

// 移除活著的 pod 的 zone label，對應必須立刻失效。
//
// 這條路徑的單元測試用的是 fake clientset；這裡驗的是真實 informer 的 update
// 事件。它守的是 Task 3 審查抓到的一個 Critical：原本的 upsert 只增不刪，
// 失去索引資格的 pod 會留下永不過期的對應，而它的 IP 被回收後，新 pod 會繼承
// 前一個租用者的 zone。
func TestClusterLabelRemovalEvictsImmediately(t *testing.T) {
	admin := adminClient(t)
	ns := setupNamespace(t, admin)
	nodeA, _ := twoNodes(t, admin)

	pod := createPod(t, admin, ns, "relabelled", nodeA, "zone-a")
	ip := waitForPodIP(t, admin, ns, pod.Name)

	w := startWatcher(t, scopedClient(t, admin), nodeA)
	eventually(t, "初始應被索引", func() bool {
		z, ok := w.Zone(ip)
		return ok && z == "zone-a"
	})

	// 移除 label
	cur, err := admin.CoreV1().Pods(ns).Get(context.Background(), pod.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("取得 pod: %v", err)
	}
	delete(cur.Labels, "zone")
	if _, err := admin.CoreV1().Pods(ns).Update(context.Background(), cur, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("更新 pod: %v", err)
	}

	eventually(t, "移除 label 後應立即失效", func() bool {
		_, ok := w.Zone(ip)
		return !ok
	})
}
