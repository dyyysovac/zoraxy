package main

import (
	"reflect"
	"testing"
)

func TestCleanHostnameList(t *testing.T) {
	got := cleanHostnameList([]string{"a.com", " b.com ", "", "  "})
	want := []string{"a.com", "b.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if got := cleanHostnameList(nil); got == nil || len(got) != 0 {
		t.Fatalf("expected an empty, non-nil list, got %#v", got)
	}
}
