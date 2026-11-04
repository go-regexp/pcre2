package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEsc(t *testing.T) {
	if got := esc("ab 1\n\\\xc3"); got != "ab 1\\x0a\\x5c\\xc3" {
		t.Fatalf("esc = %q", got)
	}
}

func TestTestinput(t *testing.T) {
	b := bench{Pattern: "x+", Flags: "utf", Prefix: "p", Unit: "ab", Count: 3, Suffix: "s"}
	want := "/x+/utf\n    p\\[ab]{3}s\n\n"
	if got := b.testinput(); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if got := string(b.subject()); got != "pabababs" {
		t.Fatalf("subject %q", got)
	}
}

func TestMedian(t *testing.T) {
	if m := median([]float64{3, 1, 2}); m != 2 {
		t.Fatal(m)
	}
	if m := median([]float64{4, 1, 2, 3}); m != 2.5 {
		t.Fatal(m)
	}
}

func TestBenchesWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, b := range benches() {
		if seen[b.Name] || b.Iterations <= 0 || b.Pattern == "" {
			t.Errorf("bad benchmark %+v", b.Name)
		}
		seen[b.Name] = true
		if strings.Contains(b.testinput(), "\n\n\n") {
			t.Errorf("%s: malformed testinput", b.Name)
		}
	}
}

// TestOracleParse runs the oracle on every benchmark input (a few iterations)
// and checks that the timings are parsed. It needs $PCRE2TEST_ORACLE.
func TestOracleParse(t *testing.T) {
	bin := os.Getenv("PCRE2TEST_ORACLE")
	if bin == "" {
		t.Skip("PCRE2TEST_ORACLE not set")
	}
	dir := t.TempDir()
	for _, b := range benches() {
		f := filepath.Join(dir, b.Name+".txt")
		if err := os.WriteFile(f, []byte(b.testinput()), 0o644); err != nil {
			t.Fatal(err)
		}
		m, err := oracleRun(bin, f, 3)
		if err != nil {
			t.Fatalf("%s: %v", b.Name, err)
		}
		if m.Compile < 0 || m.Match < 0 {
			t.Errorf("%s: %+v", b.Name, m)
		}
	}
}
