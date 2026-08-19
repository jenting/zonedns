package spiffezone

import (
	"errors"
	"testing"
)

func TestFromPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		want    string
		wantErr error
	}{
		{"k8s workload", "/zone/zone-a/ns/prod/sa/payments", "zone-a", nil},
		{"vm workload", "/zone/zone-c/vm/billing-01", "zone-c", nil},
		{"zone only", "/zone/zone-b", "zone-b", nil},
		{"no leading slash", "zone/zone-a/ns/prod", "zone-a", nil},
		{"missing zone segment", "/ns/prod/sa/payments", "", ErrNoZone},
		{"zone key but no value", "/zone", "", ErrNoZone},
		{"zone key with empty value", "/zone//ns/prod", "", ErrNoZone},
		{"empty path", "", "", ErrNoZone},
		{"zone not first segment", "/ns/prod/zone/zone-a", "", ErrNoZone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FromPath(tt.path)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFromID(t *testing.T) {
	got, err := FromID("spiffe://example.org/zone/zone-a/ns/prod/sa/payments")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "zone-a" {
		t.Fatalf("got %q, want %q", got, "zone-a")
	}
}

func TestFromIDRejectsNonSPIFFE(t *testing.T) {
	if _, err := FromID("https://example.org/zone/zone-a"); err == nil {
		t.Fatal("expected error for non-spiffe scheme")
	}
}
