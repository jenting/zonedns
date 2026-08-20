// Package spiffezone extracts the zone from a SPIFFE ID.
//
// The convention: the zone is the first key/value pair in the SPIFFE ID path,
// of the form /zone/<zone>/... Both the central plugin (for the dest zone) and
// the agent plugin (for the source zone) rely on this convention, so it lives
// in a shared package — two independent copies could drift apart in how they
// parse it.
package spiffezone

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ErrNoZone reports that the path contains no valid zone segment.
var ErrNoZone = errors.New("spiffezone: no zone segment in path")

// FromPath extracts the zone from the path of a SPIFFE ID.
func FromPath(path string) (string, error) {
	segs := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(segs) < 2 || segs[0] != "zone" || segs[1] == "" {
		return "", ErrNoZone
	}
	return segs[1], nil
}

// FromID extracts the zone from a complete SPIFFE ID.
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
