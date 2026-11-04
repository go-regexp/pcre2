package pcre2_test

// TestConformance runs every golden case of testdata/golden (the testinput
// files of PCRE2 10.44 that apply to an 8-bit, non-JIT build, with the output
// of the reference pcre2test) through this library and compares the output
// byte for byte.
//
//	go test -run TestConformance -v .
//	go test -run 'TestConformance/testinput1/1:0042' -v .      one case
//	go test -run 'TestConformance/testinput4$' -v .            one file
//
// Environment:
//
//	PCRE2_CONFORMANCE_JSON=path               write the summary as JSON
//	PCRE2_CONFORMANCE_TIMEOUT=30s             per-case time limit (default 30s)
//	PCRE2_CONFORMANCE_UPDATE_KNOWN_FAIL=1     rewrite testdata/golden/KNOWN_FAIL.txt
//	                                          with the cases that fail now (full run only)
//	PCRE2_CONFORMANCE_STRICT=1                also fail when a KNOWN_FAIL case now passes
//
// A case that is listed in KNOWN_FAIL.txt and fails is reported as skipped
// ("known failure"); a case that is not listed and fails is a regression and
// fails the test. The test skips when pcre2.Compile is not implemented yet.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-regexp/pcre2"
	"github.com/go-regexp/pcre2/internal/pcre2testgo"
	"github.com/go-regexp/pcre2/internal/pcre2testgo/corpus"
	"github.com/go-regexp/pcre2/internal/pcre2testgo/libpcre2"
)

// richLib wraps the public-API adapter and supplies the internals that only a
// test inside the module can reach.
type richLib struct{ libpcre2.Lib }

func (r richLib) Compile(p []byte, o uint32, cs pcre2testgo.CompileSettings) (pcre2testgo.Code, int, uint64) {
	c, ec, off := r.Lib.Compile(p, o, cs)
	if c == nil {
		return nil, ec, off
	}
	return &richCode{c.(*libpcre2.Code)}, ec, off
}

type richCode struct{ *libpcre2.Code }

func (c *richCode) Extra() pcre2testgo.CodeExtra {
	e := c.Code.Extra()
	e.Known = true
	e.FirstCaseless, e.LastCaseless, e.NLSet, e.BSRSet, e.HasBkPorX = pcre2.HarnessCodeFlags(c.C)
	return e
}

func (c *richCode) NewMatchData(n uint32) pcre2testgo.MatchData {
	return &richMD{c.Code.NewMatchData(n).(*libpcre2.MatchData)}
}

func (c *richCode) Match(s []byte, start uint64, o uint32, md pcre2testgo.MatchData, ms pcre2testgo.MatchSettings) int {
	return c.Code.Match(s, start, o, md.(*richMD).MatchData, ms)
}

type richMD struct{ *libpcre2.MatchData }

func (m *richMD) UsedChars() (uint64, uint64, bool) {
	l, r := pcre2.HarnessUsedChars(m.M)
	return l, r, true
}

// libAvailable reports whether the library can compile anything yet.
func libAvailable() (ok bool, why string) {
	defer func() {
		if p := recover(); p != nil {
			ok, why = false, fmt.Sprint("pcre2.Compile panics: ", p)
		}
	}()
	code, ec, _ := pcre2.Compile([]byte("a"), 0, nil)
	if code == nil {
		return false, fmt.Sprintf("pcre2.Compile is not implemented yet (error %d for /a/)", ec)
	}
	code.Free()
	return true, ""
}

type outcome int

const (
	outPass outcome = iota
	outFail
	outUnsupported
)

type caseResult struct {
	ID      string
	Outcome outcome
	Detail  string
}

type fileSummary struct {
	File        string  `json:"file"`
	Total       int     `json:"total"`
	Pass        int     `json:"pass"`
	Fail        int     `json:"fail"`
	Unsupported int     `json:"unsupported"`
	Excluded    int     `json:"excluded"`
	Share       float64 `json:"share"`
	Regressions int     `json:"regressions"`
	NowPassing  int     `json:"now_passing_but_listed"`
}

type summary struct {
	Files       []fileSummary `json:"files"`
	Total       int           `json:"total"`
	Pass        int           `json:"pass"`
	Fail        int           `json:"fail"`
	Unsupported int           `json:"unsupported"`
	Excluded    int           `json:"excluded"`
	Share       float64       `json:"share"`
	Failing     []string      `json:"failing"`
}

func loadKnownFail(t *testing.T, path string) map[string]bool {
	known := map[string]bool{}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return known
		}
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if i := strings.IndexByte(l, '#'); i >= 0 {
			l = l[:i]
		}
		if l = strings.TrimSpace(l); l != "" {
			known[l] = true
		}
	}
	return known
}

// execute runs one case with a time limit and recovery from panics.
func execute(r *pcre2testgo.Runner, input string, limit time.Duration) (res pcre2testgo.Result, panicked any, timedOut bool) {
	type ret struct {
		res pcre2testgo.Result
		p   any
	}
	ch := make(chan ret, 1)
	go func() {
		var rr ret
		defer func() {
			if p := recover(); p != nil {
				rr.p = p
			}
			ch <- rr
		}()
		rr.res = r.Run([]byte(input))
		r.DiscardOpenPattern()
	}()
	select {
	case rr := <-ch:
		return rr.res, rr.p, false
	case <-time.After(limit):
		return pcre2testgo.Result{}, nil, true
	}
}

// firstDiff describes where got and want first differ.
func firstDiff(got, want string) string {
	g, w := strings.Split(got, "\n"), strings.Split(want, "\n")
	i := 0
	for i < len(g) && i < len(w) && g[i] == w[i] {
		i++
	}
	cut := func(s string) string {
		if len(s) > 200 {
			return s[:200] + "..."
		}
		return s
	}
	var gl, wl string
	if i < len(g) {
		gl = g[i]
	} else {
		gl = "<end of output>"
	}
	if i < len(w) {
		wl = w[i]
	} else {
		wl = "<end of output>"
	}
	return fmt.Sprintf("line %d:\n  got:  %q\n  want: %q", i+1, cut(gl), cut(wl))
}

func TestConformance(t *testing.T) {
	if ok, why := libAvailable(); !ok {
		t.Skip(why)
	}
	dir := filepath.Join("testdata", "golden")
	man, err := corpus.LoadManifest(filepath.Join(dir, "MANIFEST.json"))
	if err != nil {
		t.Fatal(err)
	}
	knownPath := filepath.Join(dir, "KNOWN_FAIL.txt")
	known := loadKnownFail(t, knownPath)
	limit := 30 * time.Second
	if s := os.Getenv("PCRE2_CONFORMANCE_TIMEOUT"); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			t.Fatalf("PCRE2_CONFORMANCE_TIMEOUT: %v", err)
		}
		limit = d
	}
	strict := os.Getenv("PCRE2_CONFORMANCE_STRICT") != ""

	var sum summary
	executed, countedTotal := 0, 0
	var failing []string
	var stale []string

	for _, e := range man.Entries {
		if !e.Included {
			continue
		}
		e := e
		g, err := corpus.LoadGolden(filepath.Join(dir, e.Golden))
		if err != nil {
			t.Fatal(err)
		}
		fs := fileSummary{File: e.TestInput}
		var prelude []string
		runner := pcre2testgo.New(richLib{})
		t.Run(e.TestInput, func(t *testing.T) {
			for _, c := range g.Cases {
				c := c
				if c.Kind.Counted() {
					if c.Excluded != "" {
						fs.Excluded++
						continue
					}
					countedTotal++
				}
				if c.Kind == corpus.KindError {
					// The "pcre2test -error ..." tail of testoutput2.
					t.Run(c.ID, func(t *testing.T) {
						executed++
						list := strings.TrimSpace(strings.TrimPrefix(c.Input, "-error"))
						got, err := pcre2testgo.ErrorMessages(richLib{}, list)
						record(t, &fs, &failing, &stale, known, strict, c, got == c.Expected && err == nil,
							false, func() string { return firstDiff(got, c.Expected) })
					})
					continue
				}
				if !c.Kind.Counted() {
					// State-setting #commands always run, whatever the filter.
					res, p, to := execute(runner, c.Input, limit)
					if p != nil || to {
						t.Errorf("%s: command did not run cleanly (panic %v, timeout %v)", c.ID, p, to)
					}
					_ = res
					prelude = append(prelude, c.Input)
					continue
				}
				t.Run(c.ID, func(t *testing.T) {
					executed++
					res, p, to := execute(runner, c.Input, limit)
					switch {
					case p != nil:
						record(t, &fs, &failing, &stale, known, strict, c, false, false, func() string { return fmt.Sprint("panic: ", p) })
					case to:
						// The abandoned goroutine still owns the runner: start over
						// and replay the state-setting commands.
						runner = pcre2testgo.New(richLib{})
						for _, in := range prelude {
							runner.Run([]byte(in))
						}
						record(t, &fs, &failing, &stale, known, strict, c, false, false, func() string { return "timeout after " + limit.String() })
					default:
						got := string(res.Output)
						record(t, &fs, &failing, &stale, known, strict, c, got == c.Expected,
							len(res.Unsupported) > 0, func() string {
								d := firstDiff(got, c.Expected)
								if len(res.Unsupported) > 0 {
									d += "\n  unsupported: " + strings.Join(res.Unsupported, "; ")
								}
								return d
							})
					}
				})
			}
		})
		fs.Total = fs.Pass + fs.Fail + fs.Unsupported
		if fs.Total > 0 {
			fs.Share = float64(fs.Pass) / float64(fs.Total)
		}
		sum.Files = append(sum.Files, fs)
	}

	// Summary.
	for _, fs := range sum.Files {
		sum.Total += fs.Total
		sum.Pass += fs.Pass
		sum.Fail += fs.Fail
		sum.Unsupported += fs.Unsupported
		sum.Excluded += fs.Excluded
	}
	if sum.Total > 0 {
		sum.Share = float64(sum.Pass) / float64(sum.Total)
	}
	sort.Strings(failing)
	sum.Failing = failing
	var b strings.Builder
	fmt.Fprintf(&b, "\nconformance by file (cases run: pass / total; unsupported = needs a feature the library lacks)\n")
	for _, fs := range sum.Files {
		fmt.Fprintf(&b, "  %-12s %5d / %-5d %6.1f%%   fail %-5d unsupported %-5d excluded %-3d regressions %d\n",
			fs.File, fs.Pass, fs.Total, 100*fs.Share, fs.Fail, fs.Unsupported, fs.Excluded, fs.Regressions)
	}
	fmt.Fprintf(&b, "  %-12s %5d / %-5d %6.1f%%   fail %-5d unsupported %-5d excluded %-3d\n",
		"TOTAL", sum.Pass, sum.Total, 100*sum.Share, sum.Fail, sum.Unsupported, sum.Excluded)
	t.Log(b.String())
	if len(stale) > 0 {
		sort.Strings(stale)
		t.Logf("%d case(s) pass now but are still listed in KNOWN_FAIL.txt (remove them): %s", len(stale), strings.Join(stale, " "))
		if strict {
			t.Errorf("PCRE2_CONFORMANCE_STRICT: stale KNOWN_FAIL entries")
		}
	}
	if p := os.Getenv("PCRE2_CONFORMANCE_JSON"); p != "" {
		jb, err := json.MarshalIndent(&sum, "", " ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, append(jb, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if os.Getenv("PCRE2_CONFORMANCE_UPDATE_KNOWN_FAIL") != "" {
		if executed != countedTotal {
			t.Fatalf("refusing to rewrite %s after a partial run (%d of %d cases ran)", knownPath, executed, countedTotal)
		}
		var kb strings.Builder
		kb.WriteString("# Cases of the golden corpus that do not pass yet (one id per line).\n")
		kb.WriteString("# A listed case that fails is reported as skipped; a case that is not listed and\n")
		kb.WriteString("# fails is a regression. Regenerate with:\n")
		kb.WriteString("#   PCRE2_CONFORMANCE_UPDATE_KNOWN_FAIL=1 go test -run TestConformance .\n")
		for _, id := range failing {
			kb.WriteString(id + "\n")
		}
		if err := os.WriteFile(knownPath, []byte(kb.String()), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %d ids to %s", len(failing), knownPath)
	}
}

// record classifies one case and reports it to t.
func record(t *testing.T, fs *fileSummary, failing, stale *[]string, known map[string]bool, strict bool,
	c corpus.Case, pass, unsupported bool, detail func() string) {
	t.Helper()
	switch {
	case pass:
		fs.Pass++
		if known[c.ID] {
			*stale = append(*stale, c.ID)
			fs.NowPassing++
		}
	default:
		if unsupported {
			fs.Unsupported++
		} else {
			fs.Fail++
		}
		*failing = append(*failing, c.ID)
		if known[c.ID] {
			t.Skipf("known failure: %s", detail())
		}
		fs.Regressions++
		t.Errorf("%s (input line %d) does not match the reference output; not in KNOWN_FAIL.txt\ninput:\n%s%s",
			c.ID, c.Line, indent(c.Input), detail())
	}
}

func indent(s string) string {
	if len(s) > 800 {
		s = s[:800] + "...\n"
	}
	return "    " + strings.ReplaceAll(strings.TrimSuffix(s, "\n"), "\n", "\n    ") + "\n"
}
