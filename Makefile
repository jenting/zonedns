# zonedns
#
# Both components are external CoreDNS plugins. Plugins are linked at compile time
# with no runtime loading mechanism, so "building" means rebuilding the host
# binary: ordinary CoreDNS for the central side, sigs.k8s.io/node-local-dns for
# the node side.

SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

REGISTRY ?= zonedns
TAG      ?= dev
CENTRAL_IMAGE ?= $(REGISTRY)-central:$(TAG)
AGENT_IMAGE   ?= $(REGISTRY)-agent:$(TAG)

# Kept in step with go.mod. These versions are not arbitrary: CoreDNS must match
# upstream node-local-dns, and the Kubernetes libraries must sit on the same line,
# or the agent plugin will not link.
COREDNS_VERSION ?= $(shell grep -oE 'github.com/coredns/coredns v[0-9.]+' go.mod | head -1 | awk '{print $$2}')
GO_VERSION      ?= $(shell grep -oE '^go [0-9.]+' go.mod | awk '{print $$2}' | cut -d. -f1-2)

# Aligned with deploy/k8s/03-daemonset.yaml: upstream's addon manifest currently
# uses 1.26.8.
NODE_LOCAL_DNS_REF ?= 1.26.8

KIND_CLUSTER ?= zonedns-dev

# The drift check must be verified against a real VirtualService CRD — the fake
# dynamic client validates nothing about the GVR and lists happily with a
# misspelled group or plural. Note the path is base/files/, not base/crds/, which
# has not existed since 1.20.
ISTIO_VERSION ?= release-1.24
ISTIO_CRD_URL ?= https://raw.githubusercontent.com/istio/istio/$(ISTIO_VERSION)/manifests/charts/base/files/crd-all.gen.yaml

.PHONY: help
help: ## List the available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk -F':.*?## ' '{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

## ── Checks ────────────────────────────────────────────────────────────

.PHONY: check
check: fmt-check vet build test ## Run everything CI's test job runs

.PHONY: fmt
fmt: ## Format
	gofmt -w .

.PHONY: fmt-check
fmt-check: ## Check formatting (CI blocks on this)
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then echo "not formatted:"; echo "$$unformatted"; exit 1; fi

.PHONY: vet
vet: ## go vet
	go vet ./...

.PHONY: build
build: ## Compile every package
	go build ./...

.PHONY: test
test: ## Unit tests and the two-ends integration tests
	go test ./... -race -cover

.PHONY: tidy-check
tidy-check: ## Confirm go mod tidy is a no-op (this is what holds the version pins)
	@cp go.mod /tmp/zonedns-go.mod && cp go.sum /tmp/zonedns-go.sum; \
	go mod tidy; \
	if ! diff -q go.mod /tmp/zonedns-go.mod >/dev/null || ! diff -q go.sum /tmp/zonedns-go.sum >/dev/null; then \
	  echo "go mod tidy produced a diff; please commit the result"; exit 1; fi

## ── Tests that need a real cluster ────────────────────────────────────

.PHONY: kind-up
kind-up: ## Create a two-node kind cluster and apply the RBAC
	kind create cluster --name $(KIND_CLUSTER) --config deploy/kind/two-node.yaml --wait 120s
	kubectl apply -f deploy/k8s/01-rbac.yaml
	kubectl wait --for=condition=Ready node --all --timeout=180s

.PHONY: kind-down
kind-down: ## Delete the kind cluster
	kind delete cluster --name $(KIND_CLUSTER)

.PHONY: test-cluster
test-cluster: ## Run the informer tests against the current cluster (run make kind-up first)
	go test -tags=cluster ./internal/podzone/ -run TestCluster -v -count=1 -timeout 10m

.PHONY: istio-crds
istio-crds: ## Install the Istio CRDs (the drift tests need a real VirtualService CRD)
	kubectl apply -f $(ISTIO_CRD_URL)
	kubectl wait --for=condition=Established --timeout=60s \
	  crd/virtualservices.networking.istio.io

.PHONY: test-drift
test-drift: ## Run the drift tests against the current cluster (run make istio-crds first)
	go test -tags=cluster ./internal/drift/ -run TestCluster -v -count=1 -timeout 10m

## ── Drift check ───────────────────────────────────────────────────────

.PHONY: drift
drift: ## Check VirtualServices against pod labels for drift, using the current kubeconfig
	go run ./cmd/zonedns-drift --show-skipped

## ── Image ─────────────────────────────────────────────────────────────

.PHONY: images
images: image-central image-agent ## Build both images

.PHONY: image-central
image-central: ## Build the central image (CoreDNS + zonedns)
	docker build \
	  --build-arg GO_VERSION=$(GO_VERSION) \
	  --build-arg COREDNS_VERSION=$(COREDNS_VERSION) \
	  -f build/Dockerfile.central -t $(CENTRAL_IMAGE) .

.PHONY: image-agent
image-agent: ## Build the node image (node-local-dns + zonedns_agent)
	docker build \
	  --build-arg GO_VERSION=$(GO_VERSION) \
	  --build-arg NODE_LOCAL_DNS_REF=$(NODE_LOCAL_DNS_REF) \
	  -f build/Dockerfile.agent -t $(AGENT_IMAGE) .

.PHONY: kind-load
kind-load: ## Load both images into the kind cluster
	kind load docker-image $(CENTRAL_IMAGE) --name $(KIND_CLUSTER)
	kind load docker-image $(AGENT_IMAGE) --name $(KIND_CLUSTER)

## ── Manifest ──────────────────────────────────────────────────────────

.PHONY: manifests-check
manifests-check: ## Server-side dry-run against the current cluster (install the ClusterSPIFFEID CRD first)
	@for f in deploy/k8s/*.yaml; do echo "── $$f"; kubectl apply --dry-run=server -f "$$f"; done
