package pcre2

import "testing"

func TestDbg(t *testing.T) {
	compileDebugPanic = true
	for _, p := range []string{"a+b", "(a|b)*c", "(?<n>x)\\k<n>", "[a-z]\\d{2,5}", "(?<=ab)c"} {
		re, ec, off := Compile([]byte(p), 0, nil)
		t.Logf("%q -> %v ec=%d off=%d", p, re != nil, ec, off)
		if re != nil {
			t.Log(re.PrintInt(true))
		}
	}
}
