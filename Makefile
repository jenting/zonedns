# zonedns
#
# 兩個元件都是 external CoreDNS plugin —— plugin 是編譯期連結的，沒有執行期載入
# 機制，所以「建置」指的是重建宿主 binary：中心端是普通 CoreDNS，節點端是
# sigs.k8s.io/node-local-dns。

SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

REGISTRY ?= zonedns
TAG      ?= dev
CENTRAL_IMAGE ?= $(REGISTRY)-central:$(TAG)
AGENT_IMAGE   ?= $(REGISTRY)-agent:$(TAG)

# 與 go.mod 一致。這些版本不是隨意選的：CoreDNS 必須與上游 node-local-dns 相同，
# k8s 函式庫必須落在同一條線上，否則 agent plugin 連結不進去。
COREDNS_VERSION ?= $(shell grep -oE 'github.com/coredns/coredns v[0-9.]+' go.mod | head -1 | awk '{print $$2}')
GO_VERSION      ?= $(shell grep -oE '^go [0-9.]+' go.mod | awk '{print $$2}' | cut -d. -f1-2)

# 與 deploy/k8s/03-daemonset.yaml 對齊：上游 addon manifest 目前用 1.26.8。
NODE_LOCAL_DNS_REF ?= 1.26.8

KIND_CLUSTER ?= zonedns-dev

# 漂移檢查要對「真的」VirtualService CRD 驗證 —— fake dynamic client 對 GVR
# 不做任何檢查，群組名或複數形打錯它一樣照列不誤。注意路徑是 base/files/，
# 不是 base/crds/（後者在 1.20 之後就不存在了）。
ISTIO_VERSION ?= release-1.24
ISTIO_CRD_URL ?= https://raw.githubusercontent.com/istio/istio/$(ISTIO_VERSION)/manifests/charts/base/files/crd-all.gen.yaml

.PHONY: help
help: ## 列出可用的目標
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk -F':.*?## ' '{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

## ── 檢查 ──────────────────────────────────────────────────────────────

.PHONY: check
check: fmt-check vet build test ## 跑 CI 的 test job 會跑的全部檢查

.PHONY: fmt
fmt: ## 格式化
	gofmt -w .

.PHONY: fmt-check
fmt-check: ## 檢查格式（CI 會擋）
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then echo "未格式化："; echo "$$unformatted"; exit 1; fi

.PHONY: vet
vet: ## go vet
	go vet ./...

.PHONY: build
build: ## 編譯全部套件
	go build ./...

.PHONY: test
test: ## 單元測試與兩端對接測試
	go test ./... -race -cover

.PHONY: tidy-check
tidy-check: ## 確認 go mod tidy 是 no-op（版本 pin 靠這個守住）
	@cp go.mod /tmp/zonedns-go.mod && cp go.sum /tmp/zonedns-go.sum; \
	go mod tidy; \
	if ! diff -q go.mod /tmp/zonedns-go.mod >/dev/null || ! diff -q go.sum /tmp/zonedns-go.sum >/dev/null; then \
	  echo "go mod tidy 產生了差異，請提交結果"; exit 1; fi

## ── 需要真實 cluster 的測試 ───────────────────────────────────────────

.PHONY: kind-up
kind-up: ## 建立兩節點 kind cluster 並套用 RBAC
	kind create cluster --name $(KIND_CLUSTER) --config deploy/kind/two-node.yaml --wait 120s
	kubectl apply -f deploy/k8s/01-rbac.yaml
	kubectl wait --for=condition=Ready node --all --timeout=180s

.PHONY: kind-down
kind-down: ## 刪除 kind cluster
	kind delete cluster --name $(KIND_CLUSTER)

.PHONY: test-cluster
test-cluster: ## 對現有 cluster 跑 informer 測試（需先 make kind-up）
	go test -tags=cluster ./internal/podzone/ -run TestCluster -v -count=1 -timeout 10m

.PHONY: istio-crds
istio-crds: ## 裝上 Istio CRD（漂移檢查的測試需要真的 VirtualService CRD）
	kubectl apply -f $(ISTIO_CRD_URL)
	kubectl wait --for=condition=Established --timeout=60s \
	  crd/virtualservices.networking.istio.io

.PHONY: test-drift
test-drift: ## 對現有 cluster 跑漂移檢查的測試（需先 make istio-crds）
	go test -tags=cluster ./internal/drift/ -run TestCluster -v -count=1 -timeout 10m

## ── 漂移檢查 ──────────────────────────────────────────────────────────

.PHONY: drift
drift: ## 用目前的 kubeconfig 檢查 VirtualService 與 pod label 是否漂移
	go run ./cmd/zonedns-drift --show-skipped

## ── Image ─────────────────────────────────────────────────────────────

.PHONY: images
images: image-central image-agent ## 建置兩個 image

.PHONY: image-central
image-central: ## 建置中心端 image（CoreDNS + zonedns）
	docker build \
	  --build-arg GO_VERSION=$(GO_VERSION) \
	  --build-arg COREDNS_VERSION=$(COREDNS_VERSION) \
	  -f build/Dockerfile.central -t $(CENTRAL_IMAGE) .

.PHONY: image-agent
image-agent: ## 建置節點端 image（node-local-dns + zonedns_agent）
	docker build \
	  --build-arg GO_VERSION=$(GO_VERSION) \
	  --build-arg NODE_LOCAL_DNS_REF=$(NODE_LOCAL_DNS_REF) \
	  -f build/Dockerfile.agent -t $(AGENT_IMAGE) .

.PHONY: kind-load
kind-load: ## 把兩個 image 載進 kind cluster
	kind load docker-image $(CENTRAL_IMAGE) --name $(KIND_CLUSTER)
	kind load docker-image $(AGENT_IMAGE) --name $(KIND_CLUSTER)

## ── Manifest ──────────────────────────────────────────────────────────

.PHONY: manifests-check
manifests-check: ## 對現有 cluster 做 server-side dry-run（需先裝 ClusterSPIFFEID CRD）
	@for f in deploy/k8s/*.yaml; do echo "── $$f"; kubectl apply --dry-run=server -f "$$f"; done
