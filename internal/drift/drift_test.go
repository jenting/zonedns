package drift

import (
	"reflect"
	"testing"
)

func TestCompareReportsHostsNoPodClaims(t *testing.T) {
	// 這是危險的一邊：VirtualService 把 client 導向 payments.example.com，
	// 但沒有任何 pod 用 zonedns.io/host 認領它，所以 central registry 查不到，
	// 於是這個服務永遠拿不到 zone 路由 —— 而查詢照常成功，沒有人會發現。
	got := Compare(
		[]string{"payments.example.com", "orders.example.com"},
		[]string{"orders.example.com"},
	)
	if want := []string{"payments.example.com"}; !reflect.DeepEqual(got.UnclaimedHosts, want) {
		t.Errorf("UnclaimedHosts = %v, want %v", got.UnclaimedHosts, want)
	}
	if len(got.UnroutedLabels) != 0 {
		t.Errorf("UnroutedLabels = %v, want empty", got.UnroutedLabels)
	}
	if got.OK() {
		t.Error("OK() = true, want false when a VirtualService host is unclaimed")
	}
}

func TestCompareReportsLabelsNoVirtualServiceDeclares(t *testing.T) {
	got := Compare(
		[]string{"orders.example.com"},
		[]string{"orders.example.com", "paymnets.example.com"}, // 打錯字
	)
	if want := []string{"paymnets.example.com"}; !reflect.DeepEqual(got.UnroutedLabels, want) {
		t.Errorf("UnroutedLabels = %v, want %v", got.UnroutedLabels, want)
	}
	if len(got.UnclaimedHosts) != 0 {
		t.Errorf("UnclaimedHosts = %v, want empty", got.UnclaimedHosts)
	}
	if got.OK() {
		t.Error("OK() = true, want false when a label is unrouted")
	}
}

func TestCompareBothDirectionsAtOnce(t *testing.T) {
	// 最典型的漂移：有人改了 VirtualService 的名字，忘了改 pod label。
	// 一次改名會同時觸發兩邊 —— 舊名沒人認領、新名沒人查。
	got := Compare(
		[]string{"payments-v2.example.com"},
		[]string{"payments.example.com"},
	)
	if want := []string{"payments-v2.example.com"}; !reflect.DeepEqual(got.UnclaimedHosts, want) {
		t.Errorf("UnclaimedHosts = %v, want %v", got.UnclaimedHosts, want)
	}
	if want := []string{"payments.example.com"}; !reflect.DeepEqual(got.UnroutedLabels, want) {
		t.Errorf("UnroutedLabels = %v, want %v", got.UnroutedLabels, want)
	}
}

func TestCompareMatchedIsClean(t *testing.T) {
	got := Compare(
		[]string{"payments.example.com", "orders.example.com"},
		[]string{"orders.example.com", "payments.example.com"},
	)
	if !got.OK() {
		t.Errorf("OK() = false, want true; report = %+v", got)
	}
}

func TestCompareDeduplicates(t *testing.T) {
	// 多個 VirtualService 可以宣告同一個 host，多個 pod（同一個 Deployment 的
	// 副本）一定會帶同一個 label。重複不是漂移，報告裡不該出現兩次。
	got := Compare(
		[]string{"payments.example.com", "payments.example.com"},
		[]string{"orders.example.com", "orders.example.com"},
	)
	if want := []string{"payments.example.com"}; !reflect.DeepEqual(got.UnclaimedHosts, want) {
		t.Errorf("UnclaimedHosts = %v, want %v", got.UnclaimedHosts, want)
	}
	if want := []string{"orders.example.com"}; !reflect.DeepEqual(got.UnroutedLabels, want) {
		t.Errorf("UnroutedLabels = %v, want %v", got.UnroutedLabels, want)
	}
}

func TestCompareIgnoresEmptyStrings(t *testing.T) {
	// label 值可以是空字串（zonedns.io/host: ""）。那不是一個名字，
	// 不該被當成一筆漂移報出來。
	got := Compare([]string{""}, []string{""})
	if !got.OK() {
		t.Errorf("OK() = false, want true; report = %+v", got)
	}
}

func TestCompareEmptyInputsAreClean(t *testing.T) {
	if got := Compare(nil, nil); !got.OK() {
		t.Errorf("OK() = false, want true; report = %+v", got)
	}
}

func TestReportIsSorted(t *testing.T) {
	// 這支工具會在 CI 裡跑，輸出要能穩定 diff —— map 迭代順序不能外洩。
	got := Compare([]string{"c.example.com", "a.example.com", "b.example.com"}, nil)
	want := []string{"a.example.com", "b.example.com", "c.example.com"}
	if !reflect.DeepEqual(got.UnclaimedHosts, want) {
		t.Errorf("UnclaimedHosts = %v, want %v", got.UnclaimedHosts, want)
	}
}
