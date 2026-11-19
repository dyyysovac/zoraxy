package acme

import (
	"reflect"
	"testing"
)

// The requested domains must stay first and in order when the SANs of an
// existing certificate are merged in, the first domain becomes the CN
func TestMergeDomainsKeepOrder(t *testing.T) {
	got := mergeDomainsKeepOrder(
		[]string{"example.com", "www.example.com", "alias.example.net"},
		[]string{"www.example.com", "old.example.com", "example.com"},
	)
	want := []string{"example.com", "www.example.com", "alias.example.net", "old.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}

	if got := mergeDomainsKeepOrder([]string{"a.com", "a.com"}, nil); !reflect.DeepEqual(got, []string{"a.com"}) {
		t.Fatalf("duplicates in the primary list not removed: %v", got)
	}
}
