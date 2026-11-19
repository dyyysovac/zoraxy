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

// An empty entry (trailing comma, empty alias) used to fail the whole request
// with "domain is empty"
func TestParseDomainList(t *testing.T) {
	for input, want := range map[string][]string{
		"a.com,b.com,":    {"a.com", "b.com"},
		"a.com,,b.com":    {"a.com", "b.com"},
		" a.com , b.com ": {"a.com", "b.com"},
		",a.com":          {"a.com"},
		"a.com":           {"a.com"},
	} {
		got, err := parseDomainList(input)
		if err != nil {
			t.Errorf("%q: %v", input, err)
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%q: got %v, want %v", input, got, want)
		}
	}

	for _, input := range []string{",", " , ", ""} {
		if _, err := parseDomainList(input); err == nil {
			t.Errorf("%q: expected an error", input)
		}
	}
}
