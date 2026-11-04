package pcre2testgo

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-regexp/pcre2/internal/pcre2testgo/corpus"
)

// TestRunnerSmoke feeds every committed case to the runner with the literal
// fake library: it must neither panic nor hang. It also checks the "** ..."
// diagnostics that pcre2test prints for bad modifiers, which do not depend on
// the library.
func TestRunnerSmoke(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "golden")
	m, err := corpus.LoadManifest(filepath.Join(dir, "MANIFEST.json"))
	if err != nil {
		t.Skipf("no corpus: %v", err)
	}
	var cases, diag, diagOK int
	var bad []string
	for _, e := range m.Entries {
		if !e.Included {
			continue
		}
		g, err := corpus.LoadGolden(filepath.Join(dir, e.Golden))
		if err != nil {
			t.Fatal(err)
		}
		r := New(fakeLib{})
		for _, c := range g.Cases {
			if c.Kind == corpus.KindError {
				continue
			}
			func() {
				defer func() {
					if p := recover(); p != nil {
						bad = append(bad, fmt.Sprintf("%s: panic: %v", c.ID, p))
					}
				}()
				res := r.Run([]byte(c.Input))
				r.DiscardOpenPattern()
				cases++
				// A modifier diagnostic is printed right after the pattern
				// echo, before any library involvement.
				want := firstDiag(c.Expected)
				if want != "" && len(res.Unsupported) == 0 {
					diag++
					if firstDiag(string(res.Output)) == want {
						diagOK++
					} else {
						t.Logf("%s: want %q got %q", c.ID, want, firstDiag(string(res.Output)))
					}
				}
			}()
		}
	}
	if len(bad) > 0 {
		t.Fatalf("%d panics, first: %v", len(bad), bad[0])
	}
	t.Logf("ran %d cases without panic; modifier diagnostics reproduced: %d/%d", cases, diagOK, diag)
	if diagOK != diag {
		t.Errorf("only %d of %d modifier diagnostics reproduced", diagOK, diag)
	}
}

// firstDiag returns the first "** ..." line of s that directly follows a
// pattern line (a line starting with a delimiter), or "".
func firstDiag(s string) string {
	lines := strings.Split(s, "\n")
	for i := 1; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "** ") && !strings.HasPrefix(lines[i-1], "    ") && lines[i-1] != "" {
			switch lines[i-1][0] {
			case '/', '!', '"', '\'', '`', '%', '&', '-', '=', '_', ':', ';', ',', '@', '~':
				return lines[i]
			}
		}
	}
	return ""
}
