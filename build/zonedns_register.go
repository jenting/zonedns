//go:build ignore

// 這個檔案會被複製進 sigs.k8s.io/node-local-dns 的 cmd/node-cache/ 套件裡。
//
// 為什麼用「加一個檔案」而不是改上游的 main.go：後者要靠 sed 在別人的原始碼上
// 做字串取代，上游一改格式就會壞，而且壞掉的方式是「patch 沒套用但建置成功」——
// 產出一個看起來正常、卻沒有 zonedns_agent 的 binary。多加一個檔案則是編譯期
// 就決定的事：檔案在，plugin 就在。
//
// 帶 ignore tag 是為了不讓它參與本 repo 的建置（它是 package main 卻沒有 main
// 函式）。Dockerfile 複製進去時會剝掉那一行。
package main

import (
	"github.com/coredns/coredns/core/dnsserver"

	// blank import 讓 plugin 把自己註冊進 CoreDNS。
	_ "github.com/jenting/zonedns/plugin/zonedns_agent"
)

func init() {
	insertBeforeCache("zonedns_agent")
}

// insertBeforeCache 把 directive 插進 dnsserver.Directives 中 cache 之前。
//
// 順序不是偏好：node-local-dns 內建的 cache plugin 以 (qname, qtype) 為 key，
// 不含發問者的 zone。若它排在前面，一個 zone 的 pod 會拿到另一個 zone 快取的
// 答案，而執行期沒有任何徵兆。plugin 的 setup() 會在啟動時檢查這個順序並拒絕
// 啟動，所以這裡插錯位置不會靜默通過 —— 但正確地插在這裡，才是讓它一開始就對。
func insertBeforeCache(name string) {
	for _, d := range dnsserver.Directives {
		if d == name {
			return
		}
	}
	out := make([]string, 0, len(dnsserver.Directives)+1)
	for _, d := range dnsserver.Directives {
		if d == "cache" {
			out = append(out, name)
		}
		out = append(out, d)
	}
	dnsserver.Directives = out
}
