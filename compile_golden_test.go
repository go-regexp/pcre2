package pcre2_test

// TestCompileGolden measures the compiler alone against the golden corpus: it
// runs every counted case whose reference output contains no match result (no
// " 0: ", "No match", "Partial match" or "Callout" lines), that is, cases made of
// compile errors, /B, /D, /I (info) dumps and the like. The cases that still
// differ are listed in testdata/golden/COMPILE_KNOWN_FAIL.txt; a case that
// fails and is not listed is a regression.
//
//	PCRE2_COMPILE_GOLDEN_UPDATE=1 go test -run TestCompileGolden .   rewrite the list
//	PCRE2_COMPILE_GOLDEN_VERBOSE=1                                   print every diff

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/go-regexp/pcre2/internal/pcre2testgo"
	"github.com/go-regexp/pcre2/internal/pcre2testgo/corpus"
)

var matchLine = regexp.MustCompile(`(?m)^\s*\d+(\+|L|C)?: |^No match|^Partial match|^Callout|^ *\d+: |^Match limit|^\*\*\* Failed|^Failed: error -`)

func TestCompileGolden(t *testing.T) {
	if ok, why := libAvailable(); !ok {
		t.Skip(why)
	}
	dir := filepath.Join("testdata", "golden")
	man, err := corpus.LoadManifest(filepath.Join(dir, "MANIFEST.json"))
	if err != nil {
		t.Fatal(err)
	}
	knownPath := filepath.Join(dir, "COMPILE_KNOWN_FAIL.txt")
	known := map[string]bool{}
	if b, err := os.ReadFile(knownPath); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if l = strings.TrimSpace(l); l != "" && l[0] != '#' {
				known[l] = true
			}
		}
	}
	update := os.Getenv("PCRE2_COMPILE_GOLDEN_UPDATE") != ""
	verbose := os.Getenv("PCRE2_COMPILE_GOLDEN_VERBOSE") != ""
	var failing []string
	total, pass := 0, 0
	for _, e := range man.Entries {
		if !e.Included {
			continue
		}
		g, err := corpus.LoadGolden(filepath.Join(dir, e.Golden))
		if err != nil {
			t.Fatal(err)
		}
		runner := pcre2testgo.New(richLib{})
		for _, c := range g.Cases {
			if c.Kind == corpus.KindError {
				continue
			}
			if !c.Kind.Counted() {
				runner.Run([]byte(c.Input))
				continue
			}
			if c.Excluded != "" || matchLine.MatchString(c.Expected) {
				continue
			}
			total++
			var out string
			func() {
				defer func() {
					if p := recover(); p != nil {
						out = fmt.Sprint("panic: ", p)
					}
				}()
				res := runner.Run([]byte(c.Input))
				runner.DiscardOpenPattern()
				out = string(res.Output)
			}()
			if out == c.Expected {
				pass++
				continue
			}
			failing = append(failing, c.ID)
			if verbose {
				t.Logf("%s differs:\n%s", c.ID, c.Input)
			}
			if !known[c.ID] && !update {
				t.Errorf("%s: compile output differs from the reference (not in COMPILE_KNOWN_FAIL.txt)\ninput:\n%s\ngot:\n%s\nwant:\n%s",
					c.ID, trunc(c.Input), trunc(out), trunc(c.Expected))
			}
		}
	}
	t.Logf("compile-only golden cases: %d / %d pass (%.1f%%)", pass, total, 100*float64(pass)/float64(max(total, 1)))
	if update {
		sort.Strings(failing)
		body := "# Compile-only golden cases that still differ (see compile_golden_test.go).\n" + strings.Join(failing, "\n") + "\n"
		if err := os.WriteFile(knownPath, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func trunc(s string) string {
	if len(s) > 1500 {
		return s[:1500] + "..."
	}
	return s
}
