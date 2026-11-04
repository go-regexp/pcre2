package pcre2_test

// TestConformance runs every golden case of testdata/golden (the testinput
// files of PCRE2 10.44 that apply to an 8-bit, non-JIT build, with the output
// of the reference pcre2test) through this library and compares the output
// byte for byte.
//
//	go test -run TestConformance -v .
//	go test -run 'TestConformance/testinput1/1:0042' -v .      one case
//	go test -run 'TestConformance/testinput4$' -v .            one file
//
// Environment:
//
//	PCRE2_CONFORMANCE_JSON=path               write the summary as JSON
//	PCRE2_CONFORMANCE_TIMEOUT=30s             per-case time limit (default 30s)
//	PCRE2_CONFORMANCE_UPDATE_KNOWN_FAIL=1     rewrite testdata/golden/KNOWN_FAIL.txt
//	                                          with the cases that fail now (full run only)
//	PCRE2_CONFORMANCE_STRICT=1                also fail when a KNOWN_FAIL case now passes
//
// A case that is listed in KNOWN_FAIL.txt and fails is reported as skipped
// ("known failure"); a case that is not listed and fails is a regression and
// fails the test. The test skips when pcre2.Compile is not implemented yet.

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/go-regexp/pcre2"
	"github.com/go-regexp/pcre2/internal/pcre2testgo"
	"github.com/go-regexp/pcre2/internal/pcre2testgo/conformance"
	"github.com/go-regexp/pcre2/internal/pcre2testgo/libpcre2"
)

// richLib wraps the public-API adapter and supplies the internals that only a
// test inside the module can reach.
type richLib struct{ libpcre2.Lib }

func (r richLib) Compile(p []byte, o uint32, cs pcre2testgo.CompileSettings) (pcre2testgo.Code, int, uint64) {
	c, ec, off := r.Lib.Compile(p, o, cs)
	if c == nil {
		return nil, ec, off
	}
	return &richCode{c.(*libpcre2.Code)}, ec, off
}

type richCode struct{ *libpcre2.Code }

func (c *richCode) Extra() pcre2testgo.CodeExtra {
	e := c.Code.Extra()
	e.Known = true
	e.FirstCaseless, e.LastCaseless, e.NLSet, e.BSRSet, e.HasBkPorX = pcre2.HarnessCodeFlags(c.C)
	return e
}

func (c *richCode) NewMatchData(n uint32) pcre2testgo.MatchData {
	return &richMD{c.Code.NewMatchData(n).(*libpcre2.MatchData)}
}

func (c *richCode) Match(s []byte, start uint64, o uint32, md pcre2testgo.MatchData, ms pcre2testgo.MatchSettings) int {
	return c.Code.Match(s, start, o, md.(*richMD).MatchData, ms)
}

type richMD struct{ *libpcre2.MatchData }

func (m *richMD) UsedChars() (uint64, uint64, bool) {
	l, r := pcre2.HarnessUsedChars(m.M)
	return l, r, true
}

// libAvailable reports whether the library can compile anything yet.
func libAvailable() (ok bool, why string) {
	defer func() {
		if p := recover(); p != nil {
			ok, why = false, fmt.Sprint("pcre2.Compile panics: ", p)
		}
	}()
	code, ec, _ := pcre2.Compile([]byte("a"), 0, nil)
	if code == nil {
		return false, fmt.Sprintf("pcre2.Compile is not implemented yet (error %d for /a/)", ec)
	}
	code.Free()
	return true, ""
}

// TestConformance runs the golden corpus through this library.
func TestConformance(t *testing.T) {
	if ok, why := libAvailable(); !ok {
		t.Skip(why)
	}
	conformance.Run(t, richLib{}, conformance.Options{GoldenDir: filepath.Join("testdata", "golden")})
}
