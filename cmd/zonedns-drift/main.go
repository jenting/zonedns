// zonedns-drift 檢查 Istio VirtualService 的 hosts 與 pod 的 zonedns.io/host
// label 有沒有分歧。
//
// 一個 workload 的對外名稱在這套設計裡被寫了兩份：pod label 決定 SPIRE entry 的
// dns_name（也就是 central registry 的 key），VirtualService 決定 client 實際查
// 什麼名字。兩份宣告漂移時沒有任何東西會報錯 —— central 查不到那個名字，就把它
// 當成不歸自己管而交給下游，於是那個服務靜靜地失去 zone 路由，DNS 查詢照常有答案。
//
// 這支工具是設計文件 §9 限制 2 所要求的那個比對檢查。適合放進 CI，或以 CronJob
// 定期執行。
//
// 離開碼：0 沒有漂移；1 發現漂移；2 檢查本身失敗（連不上、權限不足、沒有 CRD）。
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/jenting/zonedns/internal/drift"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	exitClean  = 0
	exitDrift  = 1
	exitFailed = 2
)

func main() {
	var (
		kubeconfig    = flag.String("kubeconfig", "", "path to a kubeconfig file (default: in-cluster config, else $KUBECONFIG, else ~/.kube/config)")
		clusterDomain = flag.String("cluster-domain", drift.DefaultClusterDomain, "cluster DNS domain; VirtualService hosts under it are cluster-internal names and are not compared")
		hostLabel     = flag.String("host-label", drift.HostLabel, "pod label carrying the workload's external name")
		showSkipped   = flag.Bool("show-skipped", false, "list the VirtualService hosts that were excluded from the comparison, and why")
	)
	flag.Parse()

	code, err := run(context.Background(), *kubeconfig, *clusterDomain, *hostLabel, *showSkipped)
	if err != nil {
		fmt.Fprintf(os.Stderr, "zonedns-drift: %v\n", err)
		os.Exit(exitFailed)
	}
	os.Exit(code)
}

func run(ctx context.Context, kubeconfig, clusterDomain, hostLabel string, showSkipped bool) (int, error) {
	config, err := loadConfig(kubeconfig)
	if err != nil {
		return exitFailed, err
	}
	typed, err := kubernetes.NewForConfig(config)
	if err != nil {
		return exitFailed, fmt.Errorf("building the kubernetes client: %w", err)
	}
	dyn, err := dynamic.NewForConfig(config)
	if err != nil {
		return exitFailed, fmt.Errorf("building the dynamic client: %w", err)
	}

	vsHosts, skipped, err := drift.CollectVirtualServiceHosts(ctx, dyn, clusterDomain)
	if err != nil {
		return exitFailed, err
	}
	podHosts, err := drift.CollectPodHosts(ctx, typed, hostLabel)
	if err != nil {
		return exitFailed, err
	}

	return printReport(os.Stdout, drift.Compare(vsHosts, podHosts), skipped, hostLabel, showSkipped), nil
}

// printReport 印出結果並回傳離開碼。
func printReport(w io.Writer, report drift.Report, skipped []drift.Skipped, hostLabel string, showSkipped bool) int {
	if showSkipped && len(skipped) > 0 {
		fmt.Fprintf(w, "Excluded from the comparison (%d):\n", len(skipped))
		for _, s := range skipped {
			fmt.Fprintf(w, "  %-45s %-20s (%s)\n", s.Host, s.Source, s.Reason)
		}
		fmt.Fprintln(w)
	}

	if report.OK() {
		fmt.Fprintln(w, "No drift: every compared VirtualService host is claimed by a pod, and every labelled name is routed.")
		return exitClean
	}

	if len(report.UnclaimedHosts) > 0 {
		fmt.Fprintf(w, "VirtualService hosts that no pod claims via %s (%d):\n", hostLabel, len(report.UnclaimedHosts))
		for _, h := range report.UnclaimedHosts {
			fmt.Fprintf(w, "  %s\n", h)
		}
		fmt.Fprintln(w, "  Clients resolve these names, but they are absent from the central registry,")
		fmt.Fprintln(w, "  so cross-zone lookups for them silently fall through without zone routing.")
		fmt.Fprintln(w)
	}

	if len(report.UnroutedLabels) > 0 {
		fmt.Fprintf(w, "Names labelled on pods that no VirtualService declares (%d):\n", len(report.UnroutedLabels))
		for _, h := range report.UnroutedLabels {
			fmt.Fprintf(w, "  %s\n", h)
		}
		fmt.Fprintln(w, "  These occupy a registry entry that nothing ever queries — usually a typo or a leftover.")
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "Note: this compares names only. It does not verify that a host routes to the pod")
	fmt.Fprintln(w, "that claims it — a name matched on both sides can still point at the wrong workload.")
	return exitDrift
}

// loadConfig 依序嘗試 in-cluster 設定與 kubeconfig，讓同一支程式在 CronJob 裡
// 和在工程師的筆電上都能跑。
func loadConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig == "" {
		if config, err := rest.InClusterConfig(); err == nil {
			return config, nil
		}
	}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("loading kubeconfig: %w", err)
	}
	return config, nil
}
