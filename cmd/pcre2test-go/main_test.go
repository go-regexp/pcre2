package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-regexp/pcre2/internal/pcre2testgo"
)

// litLib is a literal-string stand-in library.
type litLib struct{}
type litCode struct{ pat []byte }
type litMD struct{ ov []uint64 }

func (litLib) Compile(p []byte, o uint32, cs pcre2testgo.CompileSettings) (pcre2testgo.Code, int, uint64) {
	return &litCode{pat: p}, 0, 0
}
func (litLib) ErrorMessage(c int) (string, bool) {
	if c == -1 {
		return "no match", true
	}
	return "", false
}
func (c *litCode) Info(w uint32) (uint64, int) {
	if w == 25 || w == 14 || w == 21 {
		return 0, -55
	}
	return 0, 0
}
func (c *litCode) NameTable() ([]byte, uint32, uint32) { return nil, 0, 0 }
func (c *litCode) Extra() pcre2testgo.CodeExtra        { return pcre2testgo.CodeExtra{Known: true} }
func (c *litCode) NumberFromName(string) int           { return -49 }
func (c *litCode) Free()                               {}
func (c *litCode) NewMatchData(n uint32) pcre2testgo.MatchData {
	if n == 0 {
		n = 1
	}
	return &litMD{ov: make([]uint64, 2*n)}
}
func (c *litCode) Match(s []byte, st uint64, o uint32, md pcre2testgo.MatchData, ms pcre2testgo.MatchSettings) int {
	i := bytes.Index(s[st:], c.pat)
	if i < 0 {
		return -1
	}
	ov := md.Ovector()
	ov[0], ov[1] = st+uint64(i), st+uint64(i)+uint64(len(c.pat))
	return 1
}
func (m *litMD) Ovector() []uint64                      { return m.ov }
func (m *litMD) OvectorCount() uint32                   { return uint32(len(m.ov) / 2) }
func (m *litMD) Mark() []byte                           { return nil }
func (m *litMD) StartChar() uint64                      { return m.ov[0] }
func (m *litMD) UsedChars() (uint64, uint64, bool)      { return 0, 0, false }
func (m *litMD) CopyByNumber(uint32, int) ([]byte, int) { return nil, pcre2testgo.Unsupported }
func (m *litMD) LengthByNumber(uint32) (uint64, int)    { return 0, pcre2testgo.Unsupported }
func (m *litMD) CopyByName(string, int) ([]byte, int)   { return nil, pcre2testgo.Unsupported }
func (m *litMD) LengthByName(string) (uint64, int)      { return 0, pcre2testgo.Unsupported }
func (m *litMD) GetByNumber(uint32) ([]byte, int)       { return nil, pcre2testgo.Unsupported }
func (m *litMD) GetByName(string) ([]byte, int)         { return nil, pcre2testgo.Unsupported }
func (m *litMD) ListGet() ([][]byte, int)               { return nil, pcre2testgo.Unsupported }

func exec(t *testing.T, stdin string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	newLib = func() pcre2testgo.Lib { return litLib{} }
	var gotCode int
	osExit = func(c int) { gotCode = c }
	cmd := RootCmd()
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetArgs(args)
	if err := cmd.Execute(); err != nil {
		if ee, ok := err.(exitError); ok {
			gotCode = ee.code
		} else { // a usage error: main() would exit 1
			gotCode = 1
			errb.WriteString(err.Error())
		}
	}
	return out.String(), errb.String(), gotCode
}

func TestStdinQuiet(t *testing.T) {
	out, _, code := exec(t, "/ab/\n    xaby\n\n", "-q")
	if code != 0 || out != "/ab/\n    xaby\n 0: ab\n\n" {
		t.Fatalf("code %d out %q", code, out)
	}
}

func TestVersionHeaderWithoutQuiet(t *testing.T) {
	out, _, _ := exec(t, "")
	if out != pcre2testgo.VersionLine {
		t.Fatalf("out %q", out)
	}
}

func TestFileArguments(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in")
	outp := filepath.Join(dir, "out")
	if err := os.WriteFile(in, []byte("/a/\n    ba\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, code := exec(t, "", "-q", in, outp); code != 0 {
		t.Fatalf("code %d", code)
	}
	b, _ := os.ReadFile(outp)
	if string(b) != "/a/\n    ba\n 0: a\n\n" {
		t.Fatalf("out %q", b)
	}
}

func TestMissingFile(t *testing.T) {
	out, _, code := exec(t, "", "-q", filepath.Join(t.TempDir(), "nope"))
	if code != 1 || !strings.HasPrefix(out, "** Failed to open ") {
		t.Fatalf("code %d out %q", code, out)
	}
}

func TestErrorOption(t *testing.T) {
	out, _, code := exec(t, "", "--error", "-1,7")
	if code != 0 || out != "Error -1: no match\nError 7: PCRE2_ERROR_BADDATA (unknown error number)\n" {
		t.Fatalf("code %d out %q", code, out)
	}
}

func TestUnsupportedExitStatus(t *testing.T) {
	_, errOut, code := exec(t, "/a/\n    a\\=dfa\n\n", "-q")
	if code != pcre2testgo.ExitUnsupported || !strings.Contains(errOut, "DFA") {
		t.Fatalf("code %d stderr %q", code, errOut)
	}
}

func TestDefaultModifiers(t *testing.T) {
	out, _, _ := exec(t, "/a/\n    aa\n\n", "-q", "--subject", "global")
	if out != "/a/\n    aa\n 0: a\n 0: a\n\n" {
		t.Fatalf("out %q", out)
	}
}

func TestBadDefaultModifier(t *testing.T) {
	_, errOut, code := exec(t, "", "-q", "--pattern", "bogus")
	if code != 1 || !strings.Contains(errOut, "Unrecognized modifier") {
		t.Fatalf("code %d stderr %q", code, errOut)
	}
}

func TestTooManyArgs(t *testing.T) {
	if _, _, code := exec(t, "", "a", "b", "c"); code == 0 {
		t.Fatal("expected failure")
	}
}
