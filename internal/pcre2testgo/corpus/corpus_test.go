package corpus

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The blank-looking line after "\=ovector=3" holds two spaces on purpose:
// whitespace-only lines end a data block.
const sampleIn = "# a comment\n" +
	"#forbid_utf\n" +
	"/abc/i,info,push\n" +
	"/a\nb/\n" +
	"    xyz\n" +
	"    \\=ovector=3\n" +
	"  \n" +
	"/(?<n>x)/I\n" +
	"    x\n" +
	"\n" +
	"/foo/\n" +
	"    bar\n" +
	"    foo\n" +
	"\n" +
	"#pattern push\n" +
	"/q/\n" +
	"#pattern -push\n" +
	"/r/g\n" +
	"    rr\n"

const sampleOut = "# a comment\n" +
	"#forbid_utf\n" +
	"/abc/i,info,push\n" +
	"Capture group count = 0\n" +
	"/a\nb/\n" +
	"    xyz\n" +
	"No match\n" +
	"    \\=ovector=3\n" +
	"No match\n" +
	"  \n" +
	"/(?<n>x)/I\n" +
	"Capture group count = 1\n" +
	"Named capture groups:\n" +
	"  n   1\n" +
	"    x\n" +
	" 0: x\n" +
	"\n" +
	"/foo/\n" +
	"    bar\n" +
	"No match\n" +
	"    foo\n" +
	" 0: foo\n" +
	"\n" +
	"#pattern push\n" +
	"/q/\n" +
	"#pattern -push\n" +
	"/r/g\n" +
	"    rr\n" +
	" 0: r\n" +
	" 0: r\n"

func TestSplit(t *testing.T) {
	cs, err := Split("9", []byte(sampleIn), []byte(sampleOut))
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		kind Kind
		in1  string
	}{
		{KindCommand, "# a comment\n#forbid_utf\n"},
		{KindPattern, "/abc/i,info,push\n"}, // push: no data
		{KindPattern, "/a\nb/\n"},
		{KindPattern, "/(?<n>x)/I\n"},
		{KindPattern, "/foo/\n"},
		{KindCommand, "#pattern push\n"},
		{KindPattern, "/q/\n"}, // default push: no data
		{KindCommand, "#pattern -push\n"},
		{KindPattern, "/r/g\n"},
	}
	if len(cs) != len(want) {
		for _, c := range cs {
			t.Logf("%s %s %q", c.ID, c.Kind, c.Input)
		}
		t.Fatalf("got %d cases, want %d", len(cs), len(want))
	}
	var in, out strings.Builder
	for i, c := range cs {
		if c.Kind != want[i].kind || !strings.HasPrefix(c.Input, want[i].in1) {
			t.Errorf("case %d: kind %s input %q, want %s %q...", i, c.Kind, c.Input, want[i].kind, want[i].in1)
		}
		in.WriteString(c.Input)
		out.WriteString(c.Expected)
	}
	if in.String() != sampleIn || out.String() != sampleOut {
		t.Error("cases do not concatenate to the original input/output")
	}
	if got := cs[2].Expected; !strings.Contains(got, "No match") {
		t.Errorf("case 2 expected output = %q", got)
	}
	if cs[2].ID != "9:0003" {
		t.Errorf("id = %s", cs[2].ID)
	}
}

func TestSplitMissingEcho(t *testing.T) {
	if _, err := Split("9", []byte("/a/\n    x\n\n"), []byte("/a/\n")); err == nil {
		t.Fatal("expected an alignment error")
	}
}

func TestPlanCoversAllTests(t *testing.T) {
	seen := map[int]bool{}
	for _, e := range Plan() {
		if seen[e.Number] {
			t.Errorf("duplicate entry %d", e.Number)
		}
		seen[e.Number] = true
		if !e.Included && e.Reason == "" {
			t.Errorf("skipped test %d has no reason", e.Number)
		}
		if e.Included && e.TestOutput == "" {
			t.Errorf("included test %d has no output file", e.Number)
		}
	}
	for n := 1; n <= 26; n++ {
		if !seen[n] {
			t.Errorf("test %d missing from the plan", n)
		}
	}
}

// TestCommittedGoldens checks the committed golden files for internal
// consistency (no oracle needed).
func TestCommittedGoldens(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "testdata", "golden")
	m, err := LoadManifest(filepath.Join(dir, "MANIFEST.json"))
	if err != nil {
		t.Skipf("no committed corpus: %v", err)
	}
	plan := Plan()
	if len(m.Entries) != len(plan) {
		t.Fatalf("manifest has %d entries, plan %d", len(m.Entries), len(plan))
	}
	ids := map[string]bool{}
	for _, e := range m.Entries {
		if !e.Included {
			continue
		}
		g, err := LoadGolden(filepath.Join(dir, e.Golden))
		if err != nil {
			t.Fatal(err)
		}
		cnt := ManifestEntry{}
		cnt.Stats(g)
		if cnt.Cases != e.Cases || cnt.Counted != e.Counted || cnt.Excluded != e.Excluded {
			t.Errorf("%s: manifest says %d/%d/%d, golden has %d/%d/%d", e.Golden, e.Cases, e.Counted, e.Excluded, cnt.Cases, cnt.Counted, cnt.Excluded)
		}
		for _, c := range g.Cases {
			if ids[c.ID] {
				t.Errorf("duplicate id %s", c.ID)
			}
			ids[c.ID] = true
			if c.Kind.Counted() && c.Kind != KindError && !strings.HasSuffix(c.Input, "\n") {
				t.Errorf("%s: input not newline-terminated", c.ID)
			}
		}
	}
}

// TestGoldensMatchDistribution regenerates the corpus from the distribution
// and the oracle and compares it with the committed files. It needs
// PCRE2_TESTDATA and PCRE2TEST_ORACLE.
func TestGoldensMatchDistribution(t *testing.T) {
	td, orc := os.Getenv("PCRE2_TESTDATA"), os.Getenv("PCRE2TEST_ORACLE")
	if td == "" || orc == "" {
		t.Skip("PCRE2_TESTDATA and PCRE2TEST_ORACLE not set")
	}
	dir := filepath.Join("..", "..", "..", "testdata", "golden")
	src := Source{TestData: td, Oracle: Oracle{Bin: orc, WorkDir: t.TempDir()}}
	for _, e := range Plan() {
		if !e.Included {
			continue
		}
		g, err := src.Build(e)
		if err != nil {
			t.Fatalf("testinput%d: %v", e.Number, err)
		}
		want, err := MarshalGolden(g)
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(dir, "testinput"+strconv.Itoa(e.Number)+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Errorf("testinput%d.json is out of date; run tools/goldengen", e.Number)
		}
	}
}
