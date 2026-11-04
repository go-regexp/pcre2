package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sample = `
#define LINK_SIZE 2
#define IMM2_SIZE 2
#define A_OPT   0x80000000u  /* option */
#define B_ERR   (-5)
#define C_REF   (B_ERR - 1)
#define CH      ((unsigned char)'\x85')
#define OCT     '\011'
#define S       "string"
#define F(x)    (x+1)
#define PCRE_SHIFT (1 << 16)
enum { E_ONE = 1, E_TWO, E_THREE };
enum { E_ZERO, E_NEXT };
#define L \
  1, 2+IMM2_SIZE, /* c */ \
  1+(32/sizeof(PCRE2_UCHAR))
`

func gen(t *testing.T, args ...string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "x.h")
	if err := os.WriteFile(src, []byte(sample), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.go")
	full := append([]string{"-out", out, "-header", "test"}, args...)
	for i, a := range full {
		full[i] = strings.ReplaceAll(a, "SRC", src)
	}
	var so, se bytes.Buffer
	if rc := run(full, &so, &se); rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, se.String())
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	// gofmt aligns columns: compare with white space collapsed.
	return strings.Join(strings.Fields(string(b)), " "), so.String()
}

func TestConstants(t *testing.T) {
	got, msg := gen(t, "-src", "SRC")
	for _, want := range []string{
		"A_OPT uint32 = 0x80000000", "B_ERR = -5", "C_REF = -6", "CH = 133", "OCT = 9",
		"PCRE_SHIFT = 65536", "E_ONE = 1", "E_TWO = 2", "E_THREE = 3", "E_ZERO = 0", "E_NEXT = 1",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	for _, bad := range []string{"S =", "F ="} {
		if strings.Contains(got, "\t"+bad) {
			t.Errorf("must not emit %q", bad)
		}
	}
	if !strings.Contains(msg, "2 not evaluable") {
		t.Errorf("expected exactly the string constant skipped, got %q", msg)
	}
}

func TestConditionals(t *testing.T) {
	src := "#ifndef SUPPORT_UNICODE\n#define CHAR_X 1\n#else\n#define CHAR_X 2\n#endif\n" +
		"#if PCRE2_CODE_UNIT_WIDTH == 8\n#define W 8\n#elif PCRE2_CODE_UNIT_WIDTH == 16\n#define W 16\n#endif\n"
	got := preprocess(src, nil)
	if strings.Contains(got, "CHAR_X 1") || !strings.Contains(got, "CHAR_X 2") || !strings.Contains(got, "W 8") || strings.Contains(got, "W 16") {
		t.Errorf("preprocess wrong:\n%s", got)
	}
}

func TestPrefixFilter(t *testing.T) {
	got, _ := gen(t, "-src", "SRC:E_")
	if strings.Contains(got, "B_ERR") || !strings.Contains(got, "E_TWO = 2") {
		t.Errorf("filter wrong:\n%s", got)
	}
}

func TestTable(t *testing.T) {
	got, _ := gen(t, "-src", "SRC:ZZ", "-table", "SRC:L=lens")
	if !strings.Contains(got, "var lens = [...]uint8{ 1, 4, 33, }") {
		t.Errorf("table wrong:\n%s", got)
	}
}

func TestUsage(t *testing.T) {
	var so, se bytes.Buffer
	if rc := run(nil, &so, &se); rc != 2 {
		t.Fatalf("rc=%d", rc)
	}
}
