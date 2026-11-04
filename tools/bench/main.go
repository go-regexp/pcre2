// Command bench compares the Go library with the oracle "pcre2test -t" on a
// handful of representative patterns, single core, in interleaved rounds.
//
// For every benchmark it builds a pcre2test input file (pattern, one subject
// line using the replication syntax \[unit]{n}), runs
// "pcre2test -q -t <iterations>" and reads the "Compile time" and "Match time"
// lines; then it does the same work through the library and reports the
// median of the rounds. Oracle and Go runs alternate within each round, so
// slow drifts of the machine hit both. Nothing is measured when the 1-minute
// load average is above -maxload (default 8): the run is refused and says so.
//
// See README.md in this directory.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-regexp/pcre2/internal/pcre2testgo"
	"github.com/go-regexp/pcre2/internal/pcre2testgo/libpcre2"
)

// bench is one measurement.
type bench struct {
	Name    string
	Pattern string // pattern text, without delimiters
	Flags   string // pcre2test pattern modifiers
	// Subject = Prefix + Unit*Count + Suffix
	Prefix, Unit, Suffix string
	Count                int
	Match                bool // the subject must match
	Iterations           int  // timing repetitions (-t n)
}

func (b bench) subject() []byte {
	return []byte(b.Prefix + strings.Repeat(b.Unit, b.Count) + b.Suffix)
}

// esc writes s as a pcre2test data line fragment: alphanumerics and space are
// literal, every other byte is \xhh (which, in UTF mode, copies the byte).
func esc(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == ' ' {
			sb.WriteByte(c)
		} else {
			fmt.Fprintf(&sb, "\\x%02x", c)
		}
	}
	return sb.String()
}

func (b bench) testinput() string {
	var line strings.Builder
	line.WriteString("    " + esc(b.Prefix))
	if b.Count > 0 && b.Unit != "" {
		fmt.Fprintf(&line, "\\[%s]{%d}", esc(b.Unit), b.Count)
	}
	line.WriteString(esc(b.Suffix))
	return "/" + b.Pattern + "/" + b.Flags + "\n" + line.String() + "\n\n"
}

func benches() []bench {
	words := make([]string, 200)
	for i := range words {
		words[i] = "word" + strconv.Itoa(i*7919%100003)
	}
	return []bench{
		{"literal-at-end", "needle", "", "", "a", 100000, "needle", true, 2000},
		{"alternation", "(foo|bar|baz)qux", "", "", "abc ", 20000, "bazqux", true, 1000},
		{"digits", `\d+`, "", "", "abc ", 20000, "12345", true, 2000},
		{"star-class-backtrack", "(a|b)*c", "", "", "ab", 5000, "c", true, 500},
		{"caseless-phrase", "(?i)hello world", "", "", "lorem ipsum ", 8000, "HeLLo WoRLD", true, 1000},
		{"anchored-fail", "^abc", "", "x", "y", 100000, "", false, 20000},
		{"unicode-props", `\p{Lu}\p{Ll}+`, "utf", "", "\xc3\xa9\xc3\xa8 1 ", 5000, "\xc3\x89t\xc3\xa9", true, 500},
		{"lookahead", `\w+(?=:)`, "", "", "some words here ", 5000, "key: value", true, 1000},
		{"backreference", `(\w+) \1`, "", "", "ab cd ef ", 5000, "gh gh", true, 500},
		{"email", `[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}`, "i", "", "no address in this text ", 3000, "me@example.org", true, 500},
		{"compile-big-alternation", "(?:" + strings.Join(words, "|") + ")x", "", "", "", 0, "word0x", true, 200},
		{"dotstar-capture", `^(.*?),(.*?),(.*)$`, "", "", "ab,", 3000, "", true, 1000},
	}
}

type measure struct {
	Compile, Match float64 // microseconds per operation
}

type row struct {
	Name          string  `json:"name"`
	Iterations    int     `json:"iterations"`
	OracleCompile float64 `json:"oracle_compile_us"`
	GoCompile     float64 `json:"go_compile_us"`
	OracleMatch   float64 `json:"oracle_match_us"`
	GoMatch       float64 `json:"go_match_us"`
	CompileRatio  float64 `json:"compile_ratio"`
	MatchRatio    float64 `json:"match_ratio"`
	Slower        bool    `json:"slower"`
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("bench", flag.ContinueOnError)
	fs.SetOutput(stderr)
	oracle := fs.String("oracle", os.Getenv("PCRE2TEST_ORACLE"), "path of the oracle pcre2test (env PCRE2TEST_ORACLE)")
	rounds := fs.Int("rounds", 7, "interleaved rounds; the median is reported")
	maxload := fs.Float64("maxload", 8, "refuse to measure when the 1-minute load average is above this")
	only := fs.String("only", "", "only the benchmarks whose name contains this")
	jsonOut := fs.String("json", "", "also write the table as JSON to this file")
	work := fs.String("workdir", "", "directory for the generated testinput files (default: user cache dir)")
	list := fs.Bool("list", false, "list the benchmarks and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	bs := benches()
	if *list {
		for _, b := range bs {
			fmt.Fprintf(stdout, "%-24s /%.40s/%s  subject %d bytes  x%d\n", b.Name, b.Pattern, b.Flags, len(b.subject()), b.Iterations)
		}
		return 0
	}
	if *oracle == "" {
		fmt.Fprintln(stderr, "bench: -oracle (or $PCRE2TEST_ORACLE) is required")
		return 2
	}
	if load, err := loadavg1(); err != nil {
		fmt.Fprintf(stderr, "bench: cannot read the load average (%v); refusing to measure\n", err)
		return 1
	} else if load > *maxload {
		fmt.Fprintf(stderr, "bench: 1-minute load average %.2f is above %.2f; deferred, nothing measured\n", load, *maxload)
		return 1
	}
	dir := *work
	if dir == "" {
		d, err := os.UserCacheDir()
		if err != nil {
			fmt.Fprintln(stderr, "bench:", err)
			return 1
		}
		dir = filepath.Join(d, "go-regexp-pcre2", "bench")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintln(stderr, "bench:", err)
		return 1
	}
	runtime.GOMAXPROCS(1)

	lib := libpcre2.New()
	var rows []row
	for _, b := range bs {
		if *only != "" && !strings.Contains(b.Name, *only) {
			continue
		}
		in := filepath.Join(dir, b.Name+".txt")
		if err := os.WriteFile(in, []byte(b.testinput()), 0o644); err != nil {
			fmt.Fprintln(stderr, "bench:", err)
			return 1
		}
		var oc, om, gc, gm []float64
		for r := 0; r < *rounds; r++ {
			o, err := oracleRun(*oracle, in, b.Iterations)
			if err != nil {
				fmt.Fprintf(stderr, "bench: %s: oracle: %v\n", b.Name, err)
				return 1
			}
			g, err := goRun(lib, b)
			if err != nil {
				fmt.Fprintf(stderr, "bench: %s: library: %v\n", b.Name, err)
				return 1
			}
			oc, om = append(oc, o.Compile), append(om, o.Match)
			gc, gm = append(gc, g.Compile), append(gm, g.Match)
		}
		rw := row{Name: b.Name, Iterations: b.Iterations,
			OracleCompile: median(oc), GoCompile: median(gc), OracleMatch: median(om), GoMatch: median(gm)}
		rw.CompileRatio = rw.GoCompile / rw.OracleCompile
		rw.MatchRatio = rw.GoMatch / rw.OracleMatch
		rw.Slower = rw.CompileRatio > 1 || rw.MatchRatio > 1
		rows = append(rows, rw)
	}
	fmt.Fprintf(stdout, "%-24s %12s %12s %7s %12s %12s %7s\n", "benchmark", "C compile", "Go compile", "ratio", "C match", "Go match", "ratio")
	for _, r := range rows {
		mark := ""
		if r.Slower {
			mark = "  <- slower than the reference"
		}
		fmt.Fprintf(stdout, "%-24s %10.3fus %10.3fus %7.2f %10.3fus %10.3fus %7.2f%s\n",
			r.Name, r.OracleCompile, r.GoCompile, r.CompileRatio, r.OracleMatch, r.GoMatch, r.MatchRatio, mark)
	}
	if *jsonOut != "" {
		b, _ := json.MarshalIndent(rows, "", " ")
		if err := os.WriteFile(*jsonOut, append(b, '\n'), 0o644); err != nil {
			fmt.Fprintln(stderr, "bench:", err)
			return 1
		}
	}
	return 0
}

// oracleRun runs pcre2test -q -t n on the file and parses the timings.
func oracleRun(bin, file string, n int) (measure, error) {
	out, err := exec.Command(bin, "-q", "-t", strconv.Itoa(n), file).Output()
	if err != nil {
		return measure{}, err
	}
	var m measure
	var gotC, gotM bool
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		// "Compile time %8.4f microseconds" / "Match time %7.4f microseconds"
		if len(f) == 4 && f[0] == "Compile" && f[1] == "time" {
			v, err := strconv.ParseFloat(f[2], 64)
			if err != nil {
				return m, err
			}
			m.Compile, gotC = v, true
		}
		if len(f) == 4 && f[0] == "Match" && f[1] == "time" {
			v, err := strconv.ParseFloat(f[2], 64)
			if err != nil {
				return m, err
			}
			m.Match, gotM = v, true
		}
	}
	if !gotC || !gotM {
		return m, fmt.Errorf("no timing lines in the output:\n%s", out)
	}
	return m, nil
}

// goRun does the same work as pcre2test -t n through the library.
func goRun(lib pcre2testgo.Lib, b bench) (measure, error) {
	var m measure
	pat := []byte(b.Pattern)
	var opts uint32
	for _, f := range strings.Split(b.Flags, ",") {
		switch f {
		case "utf":
			opts |= 0x00080000
		case "i":
			opts |= 0x00000008
		}
	}
	cs := pcre2testgo.CompileSettings{}
	start := time.Now()
	var code pcre2testgo.Code
	for i := 0; i < b.Iterations; i++ {
		c, ec, off := lib.Compile(pat, opts, cs)
		if c == nil {
			return m, fmt.Errorf("compile failed: error %d at offset %d", ec, off)
		}
		if i == b.Iterations-1 {
			code = c
		} else {
			c.Free()
		}
	}
	m.Compile = float64(time.Since(start).Microseconds()) / float64(b.Iterations)
	if m.Compile == 0 {
		m.Compile = float64(time.Since(start).Nanoseconds()) / 1000 / float64(b.Iterations)
	}
	subj := b.subject()
	md := code.NewMatchData(0)
	ms := pcre2testgo.MatchSettings{}
	start = time.Now()
	var rc int
	for i := 0; i < b.Iterations; i++ {
		rc = code.Match(subj, 0, 0, md, ms)
	}
	m.Match = float64(time.Since(start).Nanoseconds()) / 1000 / float64(b.Iterations)
	if b.Match != (rc >= 0) {
		return m, fmt.Errorf("match result %d, expected match=%v", rc, b.Match)
	}
	code.Free()
	return m, nil
}

func median(v []float64) float64 {
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// loadavg1 returns the 1-minute load average.
func loadavg1() (float64, error) {
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		f := strings.Fields(string(b))
		if len(f) > 0 {
			return strconv.ParseFloat(f[0], 64)
		}
	}
	out, err := exec.Command("sysctl", "-n", "vm.loadavg").Output()
	if err != nil {
		return 0, err
	}
	f := strings.Fields(strings.Trim(strings.TrimSpace(string(out)), "{}"))
	if len(f) == 0 {
		return 0, fmt.Errorf("unexpected sysctl output %q", out)
	}
	return strconv.ParseFloat(f[0], 64)
}
