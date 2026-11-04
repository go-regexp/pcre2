// Command goldengen builds the golden corpus of the conformance harness from
// the PCRE2 10.44 distribution and an oracle pcre2test binary.
//
// For every testinput file that applies to an 8-bit, non-JIT, UTF/UCP build
// (see corpus.Plan, derived from RunTest) it splits the file into cases,
// aligns each case with the shipped testoutput, runs the oracle on the whole
// file, and writes testdata/golden/testinputN.json plus MANIFEST.json. Cases
// where the oracle disagrees with the shipped output are listed and marked
// excluded.
//
// See README.md in this directory.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/go-regexp/pcre2/internal/pcre2testgo/corpus"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("goldengen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	testdata := fs.String("testdata", os.Getenv("PCRE2_TESTDATA"), "directory with the PCRE2 10.44 testinput*/testoutput* files (env PCRE2_TESTDATA)")
	oracle := fs.String("oracle", os.Getenv("PCRE2TEST_ORACLE"), "path of the oracle pcre2test binary (env PCRE2TEST_ORACLE)")
	out := fs.String("out", filepath.Join("testdata", "golden"), "output directory")
	work := fs.String("workdir", "", "working directory for oracle runs (default: <user cache dir>/go-regexp-pcre2/goldengen)")
	check := fs.Bool("check", false, "do not write: regenerate and fail if the files in -out differ")
	freq := fs.Bool("freq", false, "print the modifier frequency table of the existing goldens and exit")
	only := fs.Int("only", 0, "build only testinput N")
	verify := fs.Bool("verify", false, "also replay every case stand-alone through the oracle to validate the case splitter (slow)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *freq {
		return printFreq(*out, stdout, stderr)
	}
	if *testdata == "" {
		fmt.Fprintln(stderr, "goldengen: -testdata (or $PCRE2_TESTDATA) is required")
		return 2
	}
	if *oracle == "" {
		fmt.Fprintln(stderr, "goldengen:", corpus.ErrNoOracle)
		return 2
	}
	if *work == "" {
		d, err := os.UserCacheDir()
		if err != nil {
			fmt.Fprintln(stderr, "goldengen:", err)
			return 1
		}
		*work = filepath.Join(d, "go-regexp-pcre2", "goldengen")
	}
	src := corpus.Source{TestData: *testdata, Oracle: corpus.Oracle{Bin: *oracle, WorkDir: *work}}

	man := corpus.Manifest{Schema: corpus.SchemaVersion, PCRE2: "10.44", Mode: "8-bit, no JIT, UTF/UCP (Unicode 15.0.0), link size 2",
		Source: "PCRE2 10.44 testdata, RunTest selection"}
	files := map[string][]byte{}
	status := 0
	var diffs []string
	for _, e := range corpus.Plan() {
		if *only != 0 && e.Number != *only {
			continue
		}
		if !e.Included {
			man.Entries = append(man.Entries, e)
			continue
		}
		g, err := src.Build(e)
		if err != nil {
			fmt.Fprintf(stderr, "goldengen: testinput%d: %v\n", e.Number, err)
			status = 1
			continue
		}
		if *verify {
			bad, err := corpus.Replay(g, src.Oracle)
			if err != nil {
				fmt.Fprintf(stderr, "goldengen: testinput%d: replay: %v\n", e.Number, err)
				status = 1
			}
			fmt.Fprintf(stdout, "replay testinput%d: %d case(s) differ when run stand-alone: %v\n", e.Number, len(bad), bad)
		}
		e.Golden = fmt.Sprintf("testinput%d.json", e.Number)
		e.Stats(g)
		b, err := corpus.MarshalGolden(g)
		if err != nil {
			fmt.Fprintln(stderr, "goldengen:", err)
			return 1
		}
		files[e.Golden] = b
		man.Entries = append(man.Entries, e)
		fmt.Fprintf(stdout, "testinput%-3d %-16s cases=%-5d counted=%-5d excluded=%-3d oracle-identical=%v\n",
			e.Number, e.TestOutput, e.Cases, e.Counted, e.Excluded, g.Oracle.Identical)
		for _, c := range g.Cases {
			if c.Excluded != "" {
				diffs = append(diffs, fmt.Sprintf("%s (input line %d): %s", c.ID, c.Line, c.Excluded))
			}
		}
	}
	sort.Strings(diffs)
	for _, d := range diffs {
		fmt.Fprintln(stdout, "excluded:", d)
	}
	mb, err := json.MarshalIndent(&man, "", " ")
	if err != nil {
		fmt.Fprintln(stderr, "goldengen:", err)
		return 1
	}
	files["MANIFEST.json"] = append(mb, '\n')
	if *only != 0 {
		// A partial run never touches MANIFEST.json.
		delete(files, "MANIFEST.json")
	}

	if *check {
		for name, want := range files {
			got, err := os.ReadFile(filepath.Join(*out, name))
			if err != nil || string(got) != string(want) {
				fmt.Fprintf(stderr, "goldengen: %s is out of date\n", name)
				status = 1
			}
		}
		return status
	}
	if status != 0 {
		return status
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(stderr, "goldengen:", err)
		return 1
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(*out, name), b, 0o644); err != nil {
			fmt.Fprintln(stderr, "goldengen:", err)
			return 1
		}
	}
	return 0
}

func printFreq(dir string, stdout, stderr *os.File) int {
	m, err := corpus.LoadManifest(filepath.Join(dir, "MANIFEST.json"))
	if err != nil {
		fmt.Fprintln(stderr, "goldengen:", err)
		return 1
	}
	pat, dat := map[string]int{}, map[string]int{}
	for _, e := range m.Entries {
		if !e.Included {
			continue
		}
		g, err := corpus.LoadGolden(filepath.Join(dir, e.Golden))
		if err != nil {
			fmt.Fprintln(stderr, "goldengen:", err)
			return 1
		}
		f := corpus.CountFrequency(g.Cases)
		for k, v := range f.Pattern {
			pat[k] += v
		}
		for k, v := range f.Data {
			dat[k] += v
		}
	}
	fmt.Fprintln(stdout, "# pattern modifiers (patterns using each)")
	for _, k := range corpus.Ranked(pat) {
		fmt.Fprintf(stdout, "%6d %s\n", pat[k], k)
	}
	fmt.Fprintln(stdout, "# data modifiers (data lines using each, after \\=)")
	for _, k := range corpus.Ranked(dat) {
		fmt.Fprintf(stdout, "%6d %s\n", dat[k], k)
	}
	return 0
}
