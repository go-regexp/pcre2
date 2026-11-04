// Interim stub: DELETE this file when compile.go (port of pcre2_compile.c)
// defines compileImpl.
package pcre2

// compileImpl is implemented by compile.go.
func compileImpl(pattern []byte, options uint32, cc *CompileContext) (*Code, int, uint64) {
	return nil, PCRE2_ERROR_INTERNAL, 0
}
