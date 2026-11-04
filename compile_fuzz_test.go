package pcre2

import (
	"testing"
)

// FuzzCompile feeds arbitrary patterns and option bits to Compile: it must
// never panic or hang, and a pattern that compiles must have a coherent
// header. Resource bounds keep every iteration cheap: short patterns, a small
// limit on the compiled size and on the nesting depth.
func xFuzzCompile(f *testing.F) {
	for _, s := range []string{
		"a+b", "(a|b)*c", "(?<n>x)\\k<n>", "[a-z]\\d{2,5}", "(?<=ab)c", "(a(b(?2)c)){0,2}",
		"(?(DEFINE)(?<A>a))(?&A)", "(*UTF)\\x{100}+", "\\p{Greek}+", "(?i:[[:alpha:]]+)",
		"(*MARK:x)(*SKIP:x)a", "((?'a'x)|(?'a'y))", "\\Qab\\E+", "(?x) a b # c\n d",
		"(?C1)a(?C'text')", "(?<!a|bc)d", "a{2,3}+b*?", "^\\R\\X$", "\\N{U+100}", "[\\d-z]",
	} {
		f.Add([]byte(s), uint32(0))
		f.Add([]byte(s), uint32(PCRE2_UTF|PCRE2_UCP|PCRE2_CASELESS))
	}
	f.Fuzz(func(t *testing.T, pat []byte, opts uint32) {
		if len(pat) > 512 {
			return
		}
		cc := NewCompileContext()
		cc.SetMaxPatternCompiledLength(1 << 20)
		cc.SetParensNestLimit(40)
		re, ec, _ := Compile(pat, opts, cc)
		if re == nil {
			if ec == 0 {
				t.Fatalf("nil code with error code 0 for %q", pat)
			}
			if ec == PCRE2_ERROR_INTERNAL {
				t.Fatalf("internal error (recovered panic) for %q opts %#x", pat, opts)
			}
			return
		}
		if re.blocksize == 0 || len(re.startCode()) == 0 {
			t.Fatalf("empty code for %q", pat)
		}
	})
}
