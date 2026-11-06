package pcre2

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// graphemes splits s into extended grapheme clusters with extuni, the way the
// matcher does for repeated \X, and returns the clusters and the xcount of each.
func graphemes(s string, utf bool) (out []string, counts []int) {
	subj := []byte(s)
	for pos := 0; pos < len(subj); {
		c, next := xGETCHARINCTEST(utf, subj, pos)
		x := 0
		end := extuni(c, subj, next, 0, len(subj), utf, &x)
		out = append(out, string(subj[pos:end]))
		counts = append(counts, x)
		pos = end
	}
	return
}

var extuniCases = []struct {
	name string
	in   string
	want []string
}{
	{"ascii", "ab", []string{"a", "b"}},
	{"crlf", "\r\nx", []string{"\r\n", "x"}},
	{"lfcr", "\n\r", []string{"\n", "\r"}},
	{"control", "a\x01b", []string{"a", "\x01", "b"}},
	{"combining", "á̂b", []string{"á̂", "b"}},
	{"extend after cr", "\ŕ", []string{"\r", "́"}},
	{"spacing mark", "का", []string{"का"}},
	{"prepend", "؀a", []string{"؀a"}},
	{"zwj family", "\U0001F468‍\U0001F469‍\U0001F467x", []string{"\U0001F468‍\U0001F469‍\U0001F467", "x"}},
	{"zwj not after EP", "a‍\U0001F642", []string{"a‍", "\U0001F642"}},
	{"zwj first", "‍\U0001F642", []string{"‍", "\U0001F642"}},
	{"EP extend zwj EP", "\U0001F468́‍\U0001F469", []string{"\U0001F468́‍\U0001F469"}},
	{"EP vs16", "☺️x", []string{"☺️", "x"}},
	{"regional pair", "\U0001F1EB\U0001F1F7\U0001F1E9\U0001F1EA", []string{"\U0001F1EB\U0001F1F7", "\U0001F1E9\U0001F1EA"}},
	{"regional odd", "\U0001F1EB\U0001F1F7\U0001F1E9", []string{"\U0001F1EB\U0001F1F7", "\U0001F1E9"}},
	{"regional after letter", "x\U0001F1EB\U0001F1F7", []string{"x", "\U0001F1EB\U0001F1F7"}},
	{"hangul jamo LVT", "한", []string{"한"}},
	{"hangul LV T", "각", []string{"각"}},
	{"hangul LVT V", "각ᅡ", []string{"각", "ᅡ"}},
	{"hangul L L", "ᄀᄀ가", []string{"ᄀᄀ가"}},
	{"two syllables", "한글", []string{"한", "글"}},
}

func xTestExtuni(t *testing.T) {
	for _, c := range extuniCases {
		got, counts := graphemes(c.in, true)
		if fmt.Sprintf("%q", got) != fmt.Sprintf("%q", c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
		// xcount counts the additional characters of each cluster.
		for i, g := range got {
			if want := len([]rune(g)) - 1; counts[i] != want {
				t.Errorf("%s: cluster %q xcount %d, want %d", c.name, g, counts[i], want)
			}
		}
	}
}

func xTestExtuniNonUTF(t *testing.T) {
	// One byte per character: CR LF is one cluster, a plus a byte 0x85 (not a
	// grapheme extender in Latin-1) is two.
	got, _ := graphemes("\r\nab", false)
	if fmt.Sprintf("%q", got) != `["\r\n" "a" "b"]` {
		t.Errorf("got %q", got)
	}
	got, _ = graphemes("a\xe9", false)
	if len(got) != 2 {
		t.Errorf("got %q", got)
	}
	// Regional indicators are above 255, so they never occur in non-UTF mode.
}

func xTestExtuniNilXcountAndBounds(t *testing.T) {
	subj := []byte("á̂b")
	// Limited by end_subject: stops after the first combining mark.
	end := extuni('a', subj, 1, 0, 3, true, nil)
	if end != 3 {
		t.Errorf("end = %d, want 3", end)
	}
	// Nothing to scan.
	if end := extuni('a', subj, 1, 0, 1, true, nil); end != 1 {
		t.Errorf("end = %d, want 1", end)
	}
	// Regional indicators: the count of preceding indicators is taken from
	// start_subject, so starting in the middle of a run changes the pairing.
	ri := []byte("\U0001F1EB\U0001F1F7\U0001F1E9\U0001F1EA")
	// Second indicator first (offset 4); the sequence starting there pairs with
	// the next one only if an even number precede it: one precedes, so a break.
	if end := extuni(0x1F1F7, ri, 8, 0, len(ri), true, nil); end != 8 {
		t.Errorf("odd preceding RI: end = %d, want 8", end)
	}
	if end := extuni(0x1F1E9, ri, 12, 0, len(ri), true, nil); end != 16 {
		t.Errorf("even preceding RI: end = %d, want 16", end)
	}
}

// ucdOracle runs pcre2test of the oracle build on one pattern line and data
// lines (separated by pcre2test's own syntax) and returns its output. It skips
// the test when the oracle is not available.
func ucdOracle(t *testing.T, input string) string {
	t.Helper()
	src := os.Getenv("PCRE2_SRC")
	if src == "" {
		t.Skip("PCRE2_SRC not set")
	}
	exe := filepath.Join(src, "..", "..", "build", "pcre2test")
	if _, err := os.Stat(exe); err != nil {
		t.Skipf("oracle not built: %v", err)
	}
	var out bytes.Buffer
	cmd := exec.Command(exe)
	cmd.Stdin = strings.NewReader(input)
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("pcre2test: %v\n%s", err, out.String())
	}
	return out.String()
}

// ucdUnescape decodes the \x{h} and \xhh escapes of a pcre2test output line.
func ucdUnescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if strings.HasPrefix(s[i:], "\\x{") {
			j := strings.IndexByte(s[i:], '}')
			var r rune
			fmt.Sscanf(s[i+3:i+j], "%x", &r)
			b.WriteRune(r)
			i += j + 1
		} else if strings.HasPrefix(s[i:], "\\x") && i+4 <= len(s) {
			var r rune
			fmt.Sscanf(s[i+2:i+4], "%x", &r)
			b.WriteRune(r)
			i += 4
		} else {
			b.WriteByte(s[i])
			i++
		}
	}
	return b.String()
}

// ucdData writes s as a pcre2test data line made of \x{} escapes.
func ucdData(s string) string {
	var b strings.Builder
	for _, r := range s {
		fmt.Fprintf(&b, "\\x{%x}", r)
	}
	return b.String()
}

// TestExtuniOracle compares the cluster splitting with pcre2test's \X.
func xTestExtuniOracle(t *testing.T) {
	for _, c := range extuniCases {
		out := ucdOracle(t, "/\\X/g,utf\n"+ucdData(c.in)+"\n\n")
		var got []string
		for _, line := range strings.Split(out, "\n") {
			if rest, ok := strings.CutPrefix(line, " 0: "); ok {
				got = append(got, ucdUnescape(rest))
			}
		}
		if fmt.Sprintf("%q", got) != fmt.Sprintf("%q", c.want) {
			t.Errorf("%s: pcre2test %q, ours %q\n%s", c.name, got, c.want, out)
		}
	}
}
