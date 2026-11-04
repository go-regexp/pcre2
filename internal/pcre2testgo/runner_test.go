package pcre2testgo

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// fakeLib is a stand-in library for testing the runner's formatting: patterns
// are literal strings, "(" is a syntax error.
type fakeLib struct{}

type fakeCode struct{ pat []byte }

type fakeMD struct{ ov []uint64 }

func (fakeLib) Compile(p []byte, opts uint32, cs CompileSettings) (Code, int, uint64) {
	if bytes.HasPrefix(p, []byte("(")) {
		return nil, 114, 1
	}
	return &fakeCode{pat: p}, 0, 0
}

func (fakeLib) ErrorMessage(code int) (string, bool) {
	switch code {
	case 114:
		return "missing closing parenthesis", true
	case -1:
		return "no match", true
	case -33:
		return "bad offset value", true
	}
	return "", false
}

func (c *fakeCode) Info(what uint32) (uint64, int) {
	switch what {
	case infoFirstCodeType:
		return 1, 0
	case infoFirstCodeUnit:
		return uint64(c.pat[0]), 0
	case infoHeapLimit, infoMatchLimit, infoDepthLimit:
		return 0, errUnset
	case infoMinLength:
		return uint64(len(c.pat)), 0
	case infoNewline:
		return 2, 0
	}
	return 0, 0
}
func (c *fakeCode) NameTable() ([]byte, uint32, uint32) { return nil, 0, 0 }
func (c *fakeCode) Extra() CodeExtra                    { return CodeExtra{Known: true} }
func (c *fakeCode) NumberFromName(string) int           { return -49 }
func (c *fakeCode) Free()                               {}
func (c *fakeCode) NewMatchData(n uint32) MatchData {
	if n == 0 {
		n = 1
	}
	return &fakeMD{ov: make([]uint64, 2*n)}
}
func (c *fakeCode) Match(subject []byte, start uint64, opts uint32, md MatchData, ms MatchSettings) int {
	if start > uint64(len(subject)) {
		return -33
	}
	i := bytes.Index(subject[start:], c.pat)
	if i < 0 {
		return -1
	}
	ov := md.Ovector()
	ov[0] = start + uint64(i)
	ov[1] = ov[0] + uint64(len(c.pat))
	return 1
}

func (m *fakeMD) Ovector() []uint64                      { return m.ov }
func (m *fakeMD) OvectorCount() uint32                   { return uint32(len(m.ov) / 2) }
func (m *fakeMD) Mark() []byte                           { return nil }
func (m *fakeMD) StartChar() uint64                      { return m.ov[0] }
func (m *fakeMD) UsedChars() (l, r uint64, ok bool)      { return 0, 0, false }
func (m *fakeMD) CopyByNumber(uint32, int) ([]byte, int) { return nil, Unsupported }
func (m *fakeMD) LengthByNumber(uint32) (uint64, int)    { return 0, Unsupported }
func (m *fakeMD) CopyByName(string, int) ([]byte, int)   { return nil, Unsupported }
func (m *fakeMD) LengthByName(string) (uint64, int)      { return 0, Unsupported }
func (m *fakeMD) GetByNumber(uint32) ([]byte, int)       { return nil, Unsupported }
func (m *fakeMD) GetByName(string) ([]byte, int)         { return nil, Unsupported }
func (m *fakeMD) ListGet() ([][]byte, int)               { return nil, Unsupported }

func run(t *testing.T, in string) Result {
	t.Helper()
	return New(fakeLib{}).Run([]byte(in))
}

func TestRunBasic(t *testing.T) {
	in := "/abc/\n    xabcx\n    zzz\n\n"
	want := "/abc/\n    xabcx\n 0: abc\n    zzz\nNo match\n\n"
	if got := run(t, in); string(got.Output) != want {
		t.Fatalf("got %q want %q", got.Output, want)
	}
}

func TestRunEscapes(t *testing.T) {
	// \x41 is 'A'; \x{263a} does not fit a byte without UTF.
	in := "/A/\n    \\x41\\n\\x{263a}\n\n"
	want := "/A/\n    \\x41\\n\\x{263a}\n" +
		"** Character \\x{263a} is greater than 255 and UTF-8 mode is not enabled.\n" +
		"** Truncation will probably give the wrong result.\n" +
		" 0: A\n\n"
	if got := run(t, in); string(got.Output) != want {
		t.Fatalf("got %q want %q", got.Output, want)
	}
}

func TestRunNonPrintable(t *testing.T) {
	in := "/a/\n    \\x01a\\xff\n\n"
	want := "/a/\n    \\x01a\\xff\n 0: a\n\n"
	got := run(t, in)
	if string(got.Output) != want {
		t.Fatalf("got %q want %q", got.Output, want)
	}
	in = "/\\x01/\n    \\x01\n\n" // pattern text is literal here; the fake does not decode it
	got = run(t, in)
	if !strings.Contains(string(got.Output), "No match") {
		t.Fatalf("got %q", got.Output)
	}
}

func TestRunGlobalAndAfterText(t *testing.T) {
	in := "/a/g,aftertext\n    xaya\n\n"
	want := "/a/g,aftertext\n    xaya\n 0: a\n 0+ ya\n 0: a\n 0+ \n\n"
	if got := run(t, in); string(got.Output) != want {
		t.Fatalf("got %q want %q", got.Output, want)
	}
}

func TestRunDataModifiers(t *testing.T) {
	in := "/a/\n    banana\\=offset=3\n    banana\\=offset=99\n\n"
	want := "/a/\n    banana\\=offset=3\n 0: a\n    banana\\=offset=99\nFailed: error -33: bad offset value\n\n"
	if got := run(t, in); string(got.Output) != want {
		t.Fatalf("got %q want %q", got.Output, want)
	}
}

func TestRunCompileFailureSkipsData(t *testing.T) {
	in := "/(/\n    x\n\n/x/\n    x\n\n"
	want := "/(/\nFailed: error 114 at offset 1: missing closing parenthesis\n    x\n\n/x/\n    x\n 0: x\n\n"
	if got := run(t, in); string(got.Output) != want {
		t.Fatalf("got %q want %q", got.Output, want)
	}
}

func TestRunModifierErrors(t *testing.T) {
	in := "/a/bogus\n    a\n\n"
	got := run(t, in)
	want := "/a/bogus\n** Unrecognized modifier 'bogus'\n    a\n\n"
	// "bogus" starts with the single-letter route: 'b' is unknown there.
	want = "/a/bogus\n** Unrecognized modifier 'b' in 'bogus'\n    a\n\n"
	if string(got.Output) != want {
		t.Fatalf("got %q want %q", got.Output, want)
	}
}

func TestRunInfo(t *testing.T) {
	in := "/abc/I\n"
	want := "/abc/I\nCapture group count = 0\nFirst code unit = 'a'\nSubject length lower bound = 3\n"
	if got := run(t, in); string(got.Output) != want {
		t.Fatalf("got %q want %q", got.Output, want)
	}
}

func TestRunUnsupportedIsReported(t *testing.T) {
	got := run(t, "/a/\n    a\\=dfa\n\n")
	if len(got.Unsupported) != 1 || !strings.Contains(got.Unsupported[0], "DFA") {
		t.Fatalf("unsupported = %v", got.Unsupported)
	}
}

func TestRunStatePersistsAcrossRuns(t *testing.T) {
	r := New(fakeLib{})
	// "global" is not valid for a default pattern ("#pattern"), but is for
	// default subjects.
	if g := r.Run([]byte("#pattern global\n")); string(g.Output) != "#pattern global\n** 'global' is not valid here\n" {
		t.Fatalf("got %q", g.Output)
	}
	r.Run([]byte("#subject global\n"))
	got := r.Run([]byte("/a/\n    aa\n\n"))
	want := "/a/\n    aa\n 0: a\n 0: a\n\n"
	if string(got.Output) != want {
		t.Fatalf("got %q want %q", got.Output, want)
	}
}

func TestErrorMessages(t *testing.T) {
	s, err := ErrorMessages(fakeLib{}, "114,7")
	if err != nil {
		t.Fatal(err)
	}
	want := "Error 114: missing closing parenthesis\nError 7: PCRE2_ERROR_BADDATA (unknown error number)\n"
	if s != want {
		t.Fatalf("got %q", s)
	}
	if _, err := ErrorMessages(fakeLib{}, "x"); err == nil {
		t.Fatal("expected error")
	}
}

func TestUTF8Helpers(t *testing.T) {
	for _, c := range []uint32{0x41, 0xe9, 0x263a, 0x1f600, 0x10ffff, 0x7fffffff} {
		b := ord2utf8(c)
		v, n := utf82ord(b)
		if v != c || n != len(b) {
			t.Errorf("%x: %v %d %d", c, b, v, n)
		}
	}
	if _, n := utf82ord([]byte{0xc0, 0x80}); n > 0 {
		t.Error("overlong sequence accepted")
	}
	var b bytes.Buffer
	pchars([]byte("a\xc3\xa9\x01"), true, &b)
	if b.String() != "a\\x{e9}\\x{01}" {
		t.Errorf("pchars = %q", b.String())
	}
	_ = fmt.Sprint()
}
