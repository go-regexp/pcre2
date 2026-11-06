package main

import "testing"

func TestRename(t *testing.T) {
	src := []byte("package p\nfunc f() { GET(a); x.GET; \"GET\" }\n")
	got := string(rename(src, map[string]string{"GET": "xGET"}))
	want := "package p\nfunc f() { xGET(a); x.GET; \"GET\" }\n"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestKeep(t *testing.T) {
	if !keep("Compile") || !keep("PCRE2_CASELESS") || keep("GET") {
		t.Fatal("keep")
	}
}
