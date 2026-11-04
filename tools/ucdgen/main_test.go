package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const smallUCD = `
#ifndef SUPPORT_UNICODE
const ucd_record PRIV(ucd_records)[] = {{0,0,0,0,0,0,0}};
const uint16_t PRIV(ucd_stage1)[] = {0};
#else
const char *PRIV(unicode_version) = "15.0.0";
const uint32_t PRIV(ucd_caseless_sets)[] = {
  NOTACHAR,
  0x0053,  0x0073,  0x017f,  NOTACHAR, /* a comment, with {braces} */
};
const uint32_t PRIV(ucd_digit_sets)[] = {
  2,  /* Number of subsequent values */
  0x00039, 0x00669,
};
const uint32_t PRIV(ucd_script_sets)[] = {
 0x00000000u, 0x00000080u, 0x00000000u,
};
const uint32_t PRIV(ucd_boolprop_sets)[] = {
 0x00800001u, 0x00020040u,
};
const ucd_record PRIV(ucd_records)[] = { /* 24 bytes */
  {    69,      0,      2,      0,      0,   6144,      2, }, /*   0 */
  {    25,      9,      3,      1,    -32,  43008,      4, }, /*   1 */
};
const uint16_t PRIV(ucd_stage1)[] = { /* x */
  0,  1, /* U+0000 */
};
const uint16_t PRIV(ucd_stage2)[] = {
/* block 0 */
  0,  1,  1,  0,
};
#endif
`

const smallH = "#define ucd_boolprop_sets_item_size 2\n#define ucd_script_sets_item_size 3\n"

const smallUPT = `
#define STRING_adlam0 STR_a STR_d STR_l STR_a STR_m "\0"
#define STRING_l_AMPERSAND0 STR_l STR_AMPERSAND "\0"
const char PRIV(utt_names)[] =
  STRING_adlam0
  STRING_l_AMPERSAND0;

const ucp_type_table PRIV(utt)[] = {
  {   0, PT_SCX, ucp_Adlam },
  {   6, PT_GC, ucp_L },
};

const size_t PRIV(utt_size) = sizeof(PRIV(utt)) / sizeof(ucp_type_table);
`

func TestGenUCDSmall(t *testing.T) {
	got, err := genUCD(smallUCD, smallH)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`const unicode_version = "15.0.0"`,
		"ucd_script_sets_item_size   = 3",
		"NOTACHAR, 0x0053, 0x0073, 0x017f, NOTACHAR,", // stub / comment braces ignored
		"{69, 0, 2, 0, 0, 6144, 2},",
		"{25, 9, 3, 1, -32, 43008, 4}, // 1",
		"var ucd_stage2 = []uint16{",
		"0x00000080,", // u suffix dropped
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "ucd_records = []ucdRecord{\n\t{0, 0, 0, 0, 0, 0, 0}") {
		t.Error("the SUPPORT_UNICODE stub was used instead of the real table")
	}
}

func TestGenUCDErrors(t *testing.T) {
	if _, err := genUCD(strings.Replace(smallUCD, "15.0.0", "", 1), smallH); err != nil {
		t.Fatal(err) // empty version is still a version
	}
	if _, err := genUCD(strings.Replace(smallUCD, `PRIV(unicode_version) = "15.0.0"`, "", 1), smallH); err == nil {
		t.Error("missing unicode_version accepted")
	}
	if _, err := genUCD(strings.Replace(smallUCD, "0x017f", "ucp_x", 1), smallH); err == nil {
		t.Error("symbolic token accepted")
	}
	if _, err := genUCD(strings.Replace(smallUCD, "69,      0,      2,      0,      0,", "69, 0, 2, 0,", 1), smallH); err == nil {
		t.Error("short record accepted")
	}
	if _, err := genUCD(smallUCD, ""); err == nil {
		t.Error("missing item sizes accepted")
	}
}

func TestGenUTTSmall(t *testing.T) {
	got, err := genUTT(smallUPT)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"adlam\x00"`, `"l&\x00"`, "{0, PT_SCX, ucp_Adlam},", "{6, PT_GC, ucp_L},", "var utt_size = len(utt)"} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
	if _, err := genUTT(strings.Replace(smallUPT, "STR_d", "STR_dd", 1)); err == nil {
		t.Error("bad STR_ token accepted")
	}
	if _, err := genUTT(strings.Replace(smallUPT, "  STRING_l_AMPERSAND0;", "  STRING_nope0;", 1)); err == nil {
		t.Error("undefined name accepted")
	}
}

func TestStripComments(t *testing.T) {
	if got := stripComments(`a /* x */ "/* y */" b`); got != `a   "/* y */" b` {
		t.Errorf("got %q", got)
	}
}

func TestRunErrors(t *testing.T) {
	var out, errb bytes.Buffer
	t.Setenv("PCRE2_SRC", "")
	if run(nil, &out, &errb) != 2 {
		t.Error("missing -src not refused")
	}
	if run([]string{"-src", t.TempDir()}, &out, &errb) != 1 {
		t.Error("missing files not refused")
	}
	if run([]string{"-bogus"}, &out, &errb) != 2 {
		t.Error("bad flag not refused")
	}
}

// TestRegenerate regenerates from the real C files and compares with the
// committed output (skipped when PCRE2_SRC is unset).
func TestRegenerate(t *testing.T) {
	src := os.Getenv("PCRE2_SRC")
	if src == "" {
		t.Skip("PCRE2_SRC not set")
	}
	dir := t.TempDir()
	var out, errb bytes.Buffer
	if rc := run([]string{"-src", src, "-out", dir}, &out, &errb); rc != 0 {
		t.Fatalf("rc=%d: %s", rc, errb.String())
	}
	for _, name := range []string{"ucd_tables.go", "ucptables.go"} {
		want, err := os.ReadFile(filepath.Join("..", "..", name))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s differs from the committed file; run go generate", name)
		}
	}
}
