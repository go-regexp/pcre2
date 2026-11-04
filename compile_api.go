// Public entry points of pcre2_compile.c and pcre2_match.c. The bodies live in
// compile.go (compileImpl) and match.go (matchImpl); until those files exist,
// stub_compile.go and stub_match.go provide placeholders that return
// PCRE2_ERROR_INTERNAL. The porters of compile.go / match.go delete the stubs.
package pcre2

// Compile is pcre2_compile(): it compiles pattern (a code-unit slice; use the
// length of the slice, there is no zero-terminated form) with options and the
// compile context cc (nil means the defaults). On failure it returns a nil
// code, the PCRE2_ERROR_* compile error code (positive) and the offset in the
// pattern where the error was found.
func Compile(pattern []byte, options uint32, cc *CompileContext) (code *Code, errorcode int, erroroffset uint64) {
	if cc == nil {
		cc = NewCompileContext()
	}
	return compileImpl(pattern, options, cc)
}

// Match is pcre2_match(): it matches subject, starting at startoffset, against
// the compiled pattern, recording the groups in md. It returns the highest
// numbered group set plus one (0 if the ovector was too small), or a negative
// PCRE2_ERROR_* code (PCRE2_ERROR_NOMATCH when there is no match).
func Match(code *Code, subject []byte, startoffset uint64, options uint32, md *MatchData, mc *MatchContext) int {
	if mc == nil {
		m := defaultMatchContext()
		mc = &m
	}
	return matchImpl(code, subject, startoffset, options, md, mc)
}
