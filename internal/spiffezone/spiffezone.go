// Package spiffezone 從 SPIFFE ID 取出 zone。
//
// 約定：zone 是 SPIFFE ID path 的第一組 key/value，形如 /zone/<zone>/...
// 這個約定同時被 central plugin（取 dest zone）與 agent plugin（取 source zone）
// 使用，因此放在共用套件裡，避免兩邊各寫一份而發生解析差異。
package spiffezone

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ErrNoZone 表示 path 裡沒有合法的 zone 段。
var ErrNoZone = errors.New("spiffezone: no zone segment in path")

// FromPath 從 SPIFFE ID 的 path 取出 zone。
func FromPath(path string) (string, error) {
	segs := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(segs) < 2 || segs[0] != "zone" || segs[1] == "" {
		return "", ErrNoZone
	}
	return segs[1], nil
}

// FromID 從完整的 SPIFFE ID 取出 zone。
func FromID(id string) (string, error) {
	u, err := url.Parse(id)
	if err != nil {
		return "", fmt.Errorf("spiffezone: parse %q: %w", id, err)
	}
	if u.Scheme != "spiffe" {
		return "", fmt.Errorf("spiffezone: %q is not a spiffe ID", id)
	}
	return FromPath(u.Path)
}
