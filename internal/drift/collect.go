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

// HostLabel is the label a workload uses to declare its own external name. The
// same value is rendered by the ClusterSPIFFEID's dnsNameTemplates into the
// dns_name of the SPIRE entry.
const HostLabel = "zonedns.io/host"

// VirtualServiceGVRs are the VirtualService resource versions to try, in order.
//
// Istio has led with v1 since 1.22 and with v1beta1 before that; both serve the
// same objects. This does no discovery: try them in order and use the first one
// that lists, which saves an API round trip and a permission requirement.
func VirtualServiceGVRs() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{
		{Group: "networking.istio.io", Version: "v1", Resource: "virtualservices"},
		{Group: "networking.istio.io", Version: "v1beta1", Resource: "virtualservices"},
	}
}

// Skipped records one name excluded from the comparison, and why.
//
// These are not drift, but they must be printable: a "clean" report that is
// really the result of skipping everything looks exactly like a report with no
// drift in it — the failure shape this project keeps catching.
type Skipped struct {
	Source string // namespace/name of the VirtualService
	Host   string
	Reason SkipReason
}

// CollectVirtualServiceHosts walks the VirtualServices and returns the hosts
// that should take part in the comparison.
//
// An empty namespace means the whole cluster, which is the default for real
// use. Naming a namespace suits testing and deliberately scoped checks only:
// Istio lets a VirtualService in namespace A point at a service in namespace B,
// so narrowing the scope reports that arrangement as "no pod claims it".
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

// listVirtualServices tries each API version in order and returns the first
// listing that succeeds.
//
// When no version exists it returns an error rather than an empty list: a
// cluster with no Istio CRD and a cluster with no VirtualServices are entirely
// different things to this tool. The latter means there is no drift; the former
// means the check examined nothing at all.
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

// CollectPodHosts returns the names declared by pods carrying hostLabel. An
// empty namespace means the whole cluster, as in CollectVirtualServiceHosts.
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

// stringSlice reads a field holding an array of strings. A missing field counts
// as an empty array; a present one of the wrong type is an error — the intent of
// such a VirtualService is unknowable, and quietly treating it as having no
// hosts would let it escape the comparison entirely.
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
