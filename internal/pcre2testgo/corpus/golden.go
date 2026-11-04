package corpus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/go-regexp/pcre2/internal/pcre2testgo/mods"
)

// SchemaVersion is the version of the golden file layout.
const SchemaVersion = 1

// Golden is the content of one testdata/golden/testinputN.json file.
type Golden struct {
	Schema     int          `json:"schema"`
	PCRE2      string       `json:"pcre2_version"`
	TestInput  string       `json:"testinput"`
	TestOutput string       `json:"testoutput"`
	Oracle     OracleReport `json:"oracle"`
	Cases      []Case       `json:"cases"`
}

// OracleReport records the cross-check against the real pcre2test.
type OracleReport struct {
	Checked bool `json:"checked"`
	// Identical is true when the oracle's output for the whole file equals
	// the shipped testoutput byte for byte.
	Identical bool `json:"identical"`
	// Differing lists the ids of the cases whose output differs.
	Differing []string `json:"differing,omitempty"`
}

// ManifestEntry describes one testinput file.
type ManifestEntry struct {
	Number     int    `json:"number"`
	TestInput  string `json:"testinput"`
	TestOutput string `json:"testoutput,omitempty"`
	Included   bool   `json:"included"`
	Reason     string `json:"reason"`
	Golden     string `json:"golden,omitempty"`
	Cases      int    `json:"cases,omitempty"`
	Counted    int    `json:"counted,omitempty"`
	Excluded   int    `json:"excluded,omitempty"`
	// Features lists pcre2test features beyond plain compile/match that
	// the file exercises (informational).
	Features []string `json:"features,omitempty"`
	// ExtraArgs are additional pcre2test invocations whose output RunTest
	// appends to the file's expected output.
	ExtraArgs [][]string `json:"extra_args,omitempty"`
}

// Manifest is testdata/golden/MANIFEST.json.
type Manifest struct {
	Schema  int             `json:"schema"`
	PCRE2   string          `json:"pcre2_version"`
	Mode    string          `json:"mode"`
	Source  string          `json:"source"`
	Entries []ManifestEntry `json:"entries"`
}

// Plan returns the test selection for an 8-bit, non-JIT, UTF/UCP, link size 2
// build, derived from RunTest in the PCRE2 10.44 distribution.
func Plan() []ManifestEntry {
	inc := func(n int, out, why string, feats ...string) ManifestEntry {
		return ManifestEntry{Number: n, TestInput: fmt.Sprintf("testinput%d", n), TestOutput: out, Included: true, Reason: why, Features: feats}
	}
	skip := func(n int, why string) ManifestEntry {
		return ManifestEntry{Number: n, TestInput: fmt.Sprintf("testinput%d", n), Reason: why}
	}
	p := []ManifestEntry{
		inc(1, "testoutput1", "RunTest test 1: main non-UTF functionality, always run"),
		inc(2, "testoutput2", "RunTest test 2: API, errors, internals, always run; RunTest appends 'pcre2test -error' output", "serialize-none"),
		skip(3, "RunTest test 3 needs a French locale (fr_FR, french, fr or fr_CA) and accepts one of three alternative outputs (testoutput3, 3A, 3B); outputs depend on the host's locale tables, so it is not a stable oracle"),
		inc(4, "testoutput4", "RunTest test 4: UTF and Unicode property support (Unicode build)"),
		inc(5, "testoutput5", "RunTest test 5: API and internals for UTF/UCP (Unicode build)"),
		inc(6, "testoutput6", "RunTest test 6: DFA matching main functionality, always run", "dfa"),
		inc(7, "testoutput7", "RunTest test 7: DFA matching with UTF/UCP (Unicode build)", "dfa"),
		inc(8, "testoutput8-8-2", "RunTest test 8: internal offsets and code size, 8-bit, link size 2", "bincode"),
		inc(9, "testoutput9", "RunTest test 9: specials for the basic 8-bit library"),
		inc(10, "testoutput10", "RunTest test 10: specials for the 8-bit library with UTF-8 and UCP"),
		skip(11, "RunTest test 11 runs only with the 16-bit and 32-bit libraries ('Skipped when running 8-bit tests')"),
		skip(12, "RunTest test 12 runs only with the 16-bit and 32-bit libraries ('Skipped when running 8-bit tests')"),
		skip(13, "RunTest test 13 runs only with the 16-bit and 32-bit libraries ('Skipped when running 8-bit tests')"),
		inc(14, "testoutput14-8", "RunTest test 14: DFA UTF and UCP features, 8-bit output", "dfa"),
		inc(15, "testoutput15", "RunTest test 15: non-JIT match and depth limits, run when JIT is not available"),
		inc(16, "testoutput16", "RunTest test 16: JIT-specific features when JIT is not available (this oracle build has no JIT)"),
		skip(17, "RunTest test 17 runs only when JIT is available and not disabled; the oracle build has no JIT and this port has none"),
		inc(18, "testoutput18", "RunTest test 18: POSIX interface without UTF/UCP, 8-bit only", "posix"),
		inc(19, "testoutput19", "RunTest test 19: POSIX interface with UTF/UCP, 8-bit only", "posix"),
		inc(20, "testoutput20", "RunTest test 20: serialization and code copy tests", "serialize"),
		inc(21, "testoutput21", "RunTest test 21: \\C tests without UTF (\\C is supported by the oracle build); RunTest also runs it with -dfa, which this golden does not cover"),
		inc(22, "testoutput22-8", "RunTest test 22: \\C tests with UTF, 8-bit output"),
		skip(23, "RunTest test 23 runs only when \\C is disabled at build time (NEVER_BACKSLASH_C); the oracle build supports \\C"),
		inc(24, "testoutput24", "RunTest test 24: non-UTF pattern conversion tests", "convert"),
		inc(25, "testoutput25", "RunTest test 25: UTF pattern conversion tests", "convert"),
		inc(26, "testoutput26", "RunTest test 26: auto-generated Unicode property tests"),
	}
	for i := range p {
		if p[i].Number == 2 {
			p[i].ExtraArgs = [][]string{{"-error", "-70,-62,-2,-1,0,100,101,191,300"}}
		}
	}
	return p
}

// Oracle runs the real pcre2test.
type Oracle struct {
	Bin     string // path to pcre2test
	WorkDir string // working directory for the runs (testbtables is copied here)
	Timeout time.Duration
}

// RunFile runs "pcre2test -q file" and returns its standard output. A non-zero
// exit status is an error, as in RunTest, but the output is still returned.
func (o Oracle) RunFile(file string) ([]byte, error) {
	return o.run("-q", file)
}

// RunArgs runs pcre2test with args (e.g. -error list).
func (o Oracle) RunArgs(args ...string) ([]byte, error) {
	return o.run(append([]string{"-q"}, args...)...)
}

func (o Oracle) run(args ...string) ([]byte, error) {
	to := o.Timeout
	if to == 0 {
		to = 20 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), to)
	defer cancel()
	cmd := exec.CommandContext(ctx, o.Bin, args...)
	cmd.Dir = o.WorkDir
	cmd.Stdin = nil
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	if err != nil {
		return out.Bytes(), fmt.Errorf("%s %v: %w (stderr: %s)", o.Bin, args, err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

// Source describes where the distribution lives.
type Source struct {
	TestData string // .../pcre2-10.44/testdata
	Oracle   Oracle
}

// Build builds the golden for one planned file. The returned Golden has
// cases excluded wherever the oracle disagrees with the shipped output.
func (s Source) Build(e ManifestEntry) (*Golden, error) {
	inPath := filepath.Join(s.TestData, e.TestInput)
	input, err := os.ReadFile(inPath)
	if err != nil {
		return nil, err
	}
	shipped, err := os.ReadFile(filepath.Join(s.TestData, e.TestOutput))
	if err != nil {
		return nil, err
	}
	g := &Golden{Schema: SchemaVersion, PCRE2: "10.44", TestInput: e.TestInput, TestOutput: e.TestOutput}
	num := fmt.Sprint(e.Number)

	// RunTest copies testbtables to the working directory for test 2.
	if err := os.MkdirAll(s.Oracle.WorkDir, 0o755); err != nil {
		return nil, err
	}
	if tb, err := os.ReadFile(filepath.Join(s.TestData, "testbtables")); err == nil {
		if err := os.WriteFile(filepath.Join(s.Oracle.WorkDir, "testbtables"), tb, 0o644); err != nil {
			return nil, err
		}
	}

	// Separate the output of the extra invocations from the main output.
	head := shipped
	var extras []Case
	for k := len(e.ExtraArgs) - 1; k >= 0; k-- {
		args := e.ExtraArgs[k]
		eo, err := s.Oracle.RunArgs(args...)
		if err != nil {
			return nil, fmt.Errorf("%s extra %v: %w", e.TestInput, args, err)
		}
		if !bytes.HasSuffix(head, eo) {
			return nil, fmt.Errorf("%s: shipped output does not end with the output of pcre2test %v", e.TestOutput, args)
		}
		head = head[:len(head)-len(eo)]
		extras = append([]Case{{Kind: KindError, Input: strings.Join(args, " "), Expected: string(eo)}}, extras...)
	}

	cases, err := Split(num, input, head)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", e.TestInput, err)
	}

	oo, runErr := s.Oracle.RunFile(inPath)
	g.Oracle.Checked = true
	if runErr != nil {
		// Partial output is still compared; the error is reported.
		g.Oracle.Identical = false
	}
	if bytes.Equal(oo, head) && runErr == nil {
		g.Oracle.Identical = true
	} else {
		ocases, err := Split(num, input, oo)
		if err != nil || len(ocases) != len(cases) {
			// Alignment impossible: exclude every case.
			for i := range cases {
				cases[i].Excluded = "oracle output could not be aligned with the input"
				g.Oracle.Differing = append(g.Oracle.Differing, fmt.Sprintf("%s:%04d", num, i+1))
			}
		} else {
			for i := range cases {
				if cases[i].Input != ocases[i].Input || cases[i].Expected != ocases[i].Expected {
					cases[i].Excluded = "oracle pcre2test output differs from the shipped " + e.TestOutput + " (environment-dependent)"
				}
			}
		}
		if runErr != nil {
			return nil, fmt.Errorf("%s: oracle run failed (exit status): %w", e.TestInput, runErr)
		}
	}
	for i := range cases {
		if cases[i].Excluded != "" {
			g.Oracle.Differing = append(g.Oracle.Differing, cases[i].ID)
		}
	}
	for i := range extras {
		extras[i].ID = fmt.Sprintf("%s:error", num)
		if k := len(extras); k > 1 {
			extras[i].ID = fmt.Sprintf("%s:error%d", num, i+1)
		}
		extras[i].Line = 0
		// The extras were run by the oracle by construction; they match.
	}
	g.Cases = append(cases, extras...)
	return g, nil
}

// MarshalGolden encodes a golden file (stable, indented, trailing newline).
func MarshalGolden(g *Golden) ([]byte, error) {
	b, err := encodeNoHTML(g, " ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// LoadGolden reads a golden file.
func LoadGolden(path string) (*Golden, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var g Golden
	if err := json.Unmarshal(b, &g); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if g.Schema != SchemaVersion {
		return nil, fmt.Errorf("%s: schema %d, want %d", path, g.Schema, SchemaVersion)
	}
	return &g, nil
}

// LoadManifest reads MANIFEST.json.
func LoadManifest(path string) (*Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &m, nil
}

// Stats fills Cases/Counted/Excluded of a manifest entry from a golden.
func (e *ManifestEntry) Stats(g *Golden) {
	e.Cases, e.Counted, e.Excluded = len(g.Cases), 0, 0
	for _, c := range g.Cases {
		if !c.Kind.Counted() {
			continue
		}
		if c.Excluded != "" {
			e.Excluded++
			continue
		}
		e.Counted++
	}
}

// Frequency counts how many patterns use each modifier (long names, the
// single-letter abbreviations are expanded) across the given goldens, and
// how many data lines use each "\=" data modifier.
type Frequency struct {
	Pattern map[string]int `json:"pattern"`
	Data    map[string]int `json:"data"`
}

// CountFrequency scans cases (pattern lines and data lines) for modifiers.
func CountFrequency(cases []Case) Frequency {
	f := Frequency{Pattern: map[string]int{}, Data: map[string]int{}}
	for _, c := range cases {
		lines := SplitLines([]byte(c.Input))
		i := 0
		for i < len(lines) && (blank(lines[i]) || lines[i][0] == '#' && (len(lines[i]) < 2 || isSpace(lines[i][1]) || lines[i][1] == '!')) {
			i++
		}
		if i >= len(lines) {
			continue
		}
		switch c.Kind {
		case KindPattern:
			var text []byte
			delim := lines[i][0]
			pos := 1
			found := false
			for ; i < len(lines) && !found; i++ {
				text = append(text, lines[i]...)
				for pos < len(text) {
					if text[pos] == '\\' && pos+1 < len(text) {
						pos += 2
						continue
					}
					if text[pos] == delim {
						found = true
						break
					}
					pos++
				}
			}
			if !found {
				continue
			}
			rest := string(text[pos+1:])
			names := ModifierNames(rest)
			for k, n := range names {
				if _, ok := mods.Lookup(n); !ok && k == 0 {
					for j := 0; j < len(n); j++ {
						if long, ok := mods.Expand(n[j]); ok {
							f.Pattern[long]++
						}
					}
					continue
				}
				f.Pattern[n]++
			}
		}
		// data lines: everything after the pattern, up to the blank line
		for ; i < len(lines); i++ {
			l := string(lines[i])
			if k := strings.Index(l, "\\="); k >= 0 && k+2 < len(l) && l[k+2] != ' ' && l[k+2] != '\n' {
				for _, n := range ModifierNames(l[k+2:]) {
					f.Data[n]++
				}
			}
		}
	}
	return f
}

// Ranked returns the keys of m sorted by decreasing count then name.
func Ranked(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	return keys
}

// ErrNoOracle is returned when no oracle binary is configured.
var ErrNoOracle = errors.New("no oracle pcre2test binary configured (use -oracle or $PCRE2TEST_ORACLE)")
