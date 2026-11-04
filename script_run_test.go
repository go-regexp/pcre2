package pcre2

import (
	"strings"
	"testing"
)

var scriptRunCases = []struct {
	name string
	in   string
	want bool
}{
	{"empty", "", true},
	{"one char", "a", true},
	{"one unknown", "͸", true},
	{"latin", "hello world", true},
	{"latin cyrillic", "aб", false},
	{"cyrillic latin", "бa", false},
	{"greek cyrillic", "αа", false},
	{"common then latin", "1 + a", true},
	{"latin digits", "abc123", true},
	{"inherited", "á", true},
	{"inherited first", "́a", true},
	{"unknown mixed", "a͸", false},
	{"han", "漢字", true},
	{"han hiragana katakana", "漢あア", true},
	{"hiragana han katakana", "あ漢ア", true},
	{"han bopomofo", "ㄅ漢", true},
	{"han hangul", "漢한", true},
	{"hangul han", "한漢", true},
	{"katakana hangul", "ア한", false},
	{"hiragana bopomofo", "あㄅ", false},
	{"han bopomofo hiragana", "漢ㄅあ", false},
	{"han latin", "漢a", false},
	{"latin han", "a漢", false},
	{"han hangul latin", "漢한a", false},
	{"prolonged sound mark", "あー", true},
	{"prolonged sound latin", "aー", false},
	{"han prolonged", "漢ー", true},
	{"ideographic comma latin", "a、", false},
	{"ideographic comma han", "漢、", true},
	{"ascii digits", "123", true},
	{"arabic digits", "١٢", true},
	{"ascii and arabic digit", "1٢", false},
	{"arabic digit and ascii", "٢1", false},
	{"two arabic sets", "١۱", false},
	{"arabic letters digits", "ا١", true},
	{"devanagari digit latin letter", "a१", false},
	{"fullwidth digits", "１２", true},
	{"mathematical digits sets", "\U0001d7ce\U0001d7d8", false},
	{"mathematical digits same", "\U0001d7ce\U0001d7cf", true},
	{"greek with common", "αβ, γ", true},
}

func TestScriptRun(t *testing.T) {
	for _, c := range scriptRunCases {
		s := []byte(c.in)
		if got := script_run(s, 0, len(s), true); got != c.want {
			t.Errorf("%s: script_run(%q) = %v, want %v", c.name, c.in, got, c.want)
		}
	}
}

func TestScriptRunBoundsAndNonUTF(t *testing.T) {
	s := []byte("aбc")
	if !script_run(s, 0, 1, true) {
		t.Error("a single character is a script run")
	}
	if script_run(s, 0, 3, true) {
		t.Error("a + cyrillic is not")
	}
	if !script_run(s, 3, len(s), true) {
		t.Error("the tail is c")
	}
	// Non-UTF: one byte per character; U+00E9 is Latin, U+00B5 is Common.
	if !script_run([]byte("a\xe9\xb5"), 0, 3, false) {
		t.Error("Latin-1 letters are Latin")
	}
	// U+00B5 first, then a Greek letter coded as a byte? None exists below 256
	// (U+00B5 is Common), so mixing is only possible with Latin: \xaa is Latin.
	if !script_run([]byte("\xaa\xe9"), 0, 2, false) {
		t.Error("Latin ordinal and e-acute")
	}
}

// TestScriptRunOracle compares with pcre2test's (*script_run:...).
func TestScriptRunOracle(t *testing.T) {
	for _, c := range scriptRunCases {
		if c.in == "" {
			continue // an empty data line ends the pcre2test input
		}
		out := ucdOracle(t, "/^(*sr:.+)$/utf\n"+ucdData(c.in)+"\n\n")
		got := strings.Contains(out, "\n 0: ")
		if !got && !strings.Contains(out, "No match") {
			t.Fatalf("%s: unexpected pcre2test output:\n%s", c.name, out)
		}
		if got != c.want {
			t.Errorf("%s: pcre2test says %v, expected %v", c.name, got, c.want)
		}
	}
}
