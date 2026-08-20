// zonedns-drift checks whether the hosts of Istio VirtualServices and the
// zonedns.io/host labels on pods have diverged.
//
// This design writes a workload's external name twice: the pod label determines
// the dns_name of the SPIRE entry (and therefore the key of the central
// registry), while the VirtualService determines the name clients actually
// query. When the two declarations drift, nothing raises an error — central
// cannot find the name, treats it as not its own, hands it downstream, and the
// service silently loses zone routing while DNS queries keep returning answers.
//
// This tool is the comparison the design doc calls for in §9, limitation 2. It
// suits CI, or a CronJob running on a schedule.
//
// Exit codes: 0 no drift; 1 drift found; 2 the check itself failed (cannot
// connect, insufficient permission, no CRD).
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
		namespace     = flag.String("namespace", "", "limit the check to one namespace (default: the whole cluster). Scoping narrows correctness: a VirtualService may route to a service in another namespace, and that reads as unclaimed here")
	)
	flag.Parse()

	code, err := run(context.Background(), *kubeconfig, *clusterDomain, *hostLabel, *namespace, *showSkipped)
	if err != nil {
		fmt.Fprintf(os.Stderr, "zonedns-drift: %v\n", err)
		os.Exit(exitFailed)
	}
	os.Exit(code)
}

func run(ctx context.Context, kubeconfig, clusterDomain, hostLabel, namespace string, showSkipped bool) (int, error) {
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

	vsHosts, skipped, err := drift.CollectVirtualServiceHosts(ctx, dyn, clusterDomain, namespace)
	if err != nil {
		return exitFailed, err
	}
	podHosts, err := drift.CollectPodHosts(ctx, typed, hostLabel, namespace)
	if err != nil {
		return exitFailed, err
	}

	return printReport(os.Stdout, drift.Compare(vsHosts, podHosts), skipped, hostLabel, showSkipped), nil
}

// printReport prints the result and returns the exit code.
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

// loadConfig tries the in-cluster config and then a kubeconfig, so one binary
// runs both inside a CronJob and on an engineer's laptop.
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
