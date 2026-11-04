package pcre2_test

// TestCompileOracle compares, for every pattern line of the golden corpus, the
// compile-time output of this library (pattern echo, /B bytecode dump with and
// without offsets, /I info, or the compile error) with the output of the real
// pcre2test of the oracle build. It is skipped unless PCRE2TEST names the
// oracle binary:
//
//	PCRE2TEST=$HOME/Documents/VCS/GIT/localhost/_bibliography/pcre2-10.44/build/pcre2test \
//	  go test -run TestCompileOracle -v .
//
// PCRE2_ORACLE_MUTATIONS=n adds n random one-character mutations of each
// pattern (deterministic seed), which exercises the error paths;
// PCRE2_ORACLE_OUT=file writes every difference to file.

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/go-regexp/pcre2/internal/pcre2testgo"
	"github.com/go-regexp/pcre2/internal/pcre2testgo/corpus"
)

// patternLine returns the first pattern line of a case input with the B and I
// modifiers added, or "" when the case has no single-line /pattern/ form.
func patternLine(input string) string {
	for _, l := range strings.Split(input, "\n") {
		t := strings.TrimSpace(l)
		if t == "" || t[0] == '#' {
			continue
		}
		d := t[0]
		if strings.IndexByte("/'\"!%&*+,-.:;=?@^_`|~", d) < 0 {
			return ""
		}
		last := strings.LastIndexByte(t, d)
		if last == 0 {
			return ""
		}
		mods := t[last+1:]
		for _, bad := range []string{"push", "pop", "convert", "posix", "null_pattern", "stackguard",
			"tables", "hex", "use_length", "expand", "mark", "\\=", "locale", "substitute", "dfa", "jit", "memory"} {
			if strings.Contains(mods, bad) {
				return ""
			}
		}
		if mods == "" {
			return t + "B,I"
		}
		return t + ",B,I"
	}
	return ""
}

// mutate changes one character of the pattern body of line (the part between
// the delimiters) into a syntax character, deletes it or inserts one.
func mutate(line string, rng *rand.Rand) string {
	d := line[0]
	last := strings.LastIndexByte(line, d)
	if last < 2 {
		return line
	}
	body := []byte(line[1:last])
	i := rng.Intn(len(body))
	const syn = "()[]{}|*+?^$.\\-:<>=!#,0123456789abcdxpPkgRQEN"
	if rng.Intn(4) == 0 {
		body = append(body[:i], body[i+1:]...)
	} else {
		c := syn[rng.Intn(len(syn))]
		if c == d {
			c = 'a'
		}
		if rng.Intn(2) == 0 {
			body[i] = c
		} else {
			body = append(body[:i], append([]byte{c}, body[i:]...)...)
		}
	}
	return string(line[0]) + string(body) + line[last:]
}

func TestCompileOracle(t *testing.T) {
	bin := os.Getenv("PCRE2TEST")
	if bin == "" {
		t.Skip("PCRE2TEST not set")
	}
	mutations, _ := strconv.Atoi(os.Getenv("PCRE2_ORACLE_MUTATIONS"))
	rng := rand.New(rand.NewSource(1))
	dir := filepath.Join("testdata", "golden")
	man, err := corpus.LoadManifest(filepath.Join(dir, "MANIFEST.json"))
	if err != nil {
		t.Fatal(err)
	}
	var diffs strings.Builder
	total, same := 0, 0
	for _, e := range man.Entries {
		if !e.Included {
			continue
		}
		g, err := corpus.LoadGolden(filepath.Join(dir, e.Golden))
		if err != nil {
			t.Fatal(err)
		}
		state := pcre2testgo.New(richLib{})
		for _, c := range g.Cases {
			if !c.Kind.Counted() {
				state.Run([]byte(c.Input))
				continue
			}
			line := patternLine(c.Input)
			if line == "" {
				continue
			}
			ins := []string{line + "\n", strings.Replace(line, ",B,I", ",fullbincode,I", 1) + "\n"}
			for k := 0; k < mutations; k++ {
				ins = append(ins, mutate(line, rng)+"\n")
			}
			for _, in := range ins {
				total++
				var got string
				func() {
					defer func() {
						if p := recover(); p != nil {
							got = fmt.Sprint("panic: ", p)
						}
					}()
					got = string(pcre2testgo.New(richLib{}).Run([]byte(in)).Output)
				}()
				cmd := exec.Command(bin, "-q")
				cmd.Stdin = strings.NewReader(in)
				var out bytes.Buffer
				cmd.Stdout = &out
				cmd.Stderr = &out
				_ = cmd.Run()
				if got == out.String() {
					same++
					continue
				}
				fmt.Fprintf(&diffs, "=== %s\n%s\n--- got\n%s\n--- oracle\n%s\n", c.ID, in, got, out.String())
			}
		}
	}
	t.Logf("oracle comparison: %d / %d identical", same, total)
	if p := os.Getenv("PCRE2_ORACLE_OUT"); p != "" {
		if err := os.WriteFile(p, []byte(diffs.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if same != total {
		t.Errorf("%d of %d outputs differ from the oracle", total-same, total)
	}
}
