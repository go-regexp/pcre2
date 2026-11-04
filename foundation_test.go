package pcre2

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// cSource returns the contents of a C source file of the reference tree, or
// skips the test when PCRE2_SRC is not set.
func cSource(t *testing.T, name string) string {
	t.Helper()
	dir := os.Getenv("PCRE2_SRC")
	if dir == "" {
		t.Skip("PCRE2_SRC not set")
	}
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// cStrings extracts the NUL separated texts of a C initialiser "name[] = ...;"
// made of adjacent string literals, expanding the XSTRING() inserts.
func cStrings(t *testing.T, src, name string) []string {
	t.Helper()
	i := strings.Index(src, name)
	if i < 0 {
		t.Fatalf("%s not found", name)
	}
	body := src[i:]
	body = body[strings.Index(body, "=")+1 : strings.Index(body, ";\n")]
	body = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(body, "")
	body = regexp.MustCompile(`(?m)^#.*$`).ReplaceAllString(body, "") // #ifndef EBCDIC etc: keep ASCII branch below
	body = strings.ReplaceAll(body, `XSTRING(PCRE2_CODE_UNIT_WIDTH)`, `"8"`)
	body = strings.ReplaceAll(body, `XSTRING(MAX_NAME_SIZE)`, `"`+strconv.Itoa(MAX_NAME_SIZE)+`"`)
	body = strings.ReplaceAll(body, `XSTRING(MAX_NAME_COUNT)`, `"`+strconv.Itoa(MAX_NAME_COUNT)+`"`)
	lit := regexp.MustCompile(`"(?:[^"\\]|\\.)*"`).FindAllString(body, -1)
	var sb strings.Builder
	for _, l := range lit {
		s, err := strconv.Unquote(l)
		if err != nil { // C escapes Go does not know: \0 only
			s, err = strconv.Unquote(strings.ReplaceAll(l, `\0`, `\x00`))
			if err != nil {
				t.Fatalf("unquote %s: %v", l, err)
			}
		}
		sb.WriteString(s)
	}
	return strings.Split(strings.TrimSuffix(sb.String(), "\x00"), "\x00")
}

func TestErrorMessagesAgainstCSource(t *testing.T) {
	src := cSource(t, "pcre2_error.c")
	// the EBCDIC alternative of message 68 follows the ASCII one in the C text
	// and is dropped by taking the first of the two adjacent candidates.
	comp := cStrings(t, src, "compile_error_texts[]")
	var cleaned []string
	for _, s := range comp {
		if strings.HasPrefix(s, `\c must be followed by a letter`) {
			continue
		}
		cleaned = append(cleaned, s)
	}
	for i, want := range cleaned {
		if got := GetErrorMessage(COMPILE_ERROR_BASE + i); got != want {
			t.Errorf("compile error %d: got %q want %q", COMPILE_ERROR_BASE+i, got, want)
		}
	}
	if got := GetErrorMessage(COMPILE_ERROR_BASE + len(cleaned)); got != "" {
		t.Errorf("one past the last compile error must have no message, got %q", got)
	}
	match := cStrings(t, src, "match_error_texts[]")
	// Error number 0 is "invalid" for C (only n < 0 selects the match texts),
	// so "no error" of that list is unreachable: BADDATA.
	if GetErrorMessage(0) != "" {
		t.Error("code 0 must have no message")
	}
	for i, want := range match {
		if i == 0 {
			continue
		}
		if got := GetErrorMessage(-i); got != want {
			t.Errorf("match error %d: got %q want %q", -i, got, want)
		}
	}
	if GetErrorMessage(-len(match)) != "" {
		t.Error("one past the last match error must have no message")
	}
}

func TestGetErrorMessageSemantics(t *testing.T) {
	cases := []struct {
		code int
		want string
	}{
		{PCRE2_ERROR_NOMATCH, "no match"},
		{PCRE2_ERROR_PARTIAL, "partial match"},
		{PCRE2_ERROR_BADDATA, "bad data value"},
		{PCRE2_ERROR_UTF8_ERR21, "UTF-8 error: illegal byte (0xfe or 0xff)"},
		{PCRE2_ERROR_END_BACKSLASH, `\ at end of pattern`},
		{PCRE2_ERROR_MISSING_CLOSING_PARENTHESIS, "missing closing parenthesis"},
		{PCRE2_ERROR_BADOFFSET, "bad offset value"},
		{PCRE2_ERROR_INTERNAL, "internal error - pattern overwritten?"},
		{PCRE2_ERROR_BADUTFOFFSET, "bad offset into UTF string"},
	}
	for _, c := range cases {
		if got := GetErrorMessage(c.code); got != c.want {
			t.Errorf("GetErrorMessage(%d) = %q, want %q", c.code, got, c.want)
		}
	}
	buf := make([]byte, 64)
	for _, bad := range []int{0, 1, 99, 5000, -1000} {
		if rc := GetErrorMessageBuf(bad, buf); rc != PCRE2_ERROR_BADDATA {
			t.Errorf("code %d: rc=%d, want PCRE2_ERROR_BADDATA", bad, rc)
		}
	}
	if rc := GetErrorMessageBuf(PCRE2_ERROR_NOMATCH, nil); rc != PCRE2_ERROR_NOMEMORY {
		t.Errorf("empty buffer: %d", rc)
	}
	small := make([]byte, 5)
	if rc := GetErrorMessageBuf(PCRE2_ERROR_NOMATCH, small); rc != PCRE2_ERROR_NOMEMORY || string(small) != "no m\x00" {
		t.Errorf("truncation: rc=%d buf=%q", rc, small)
	}
	if rc := GetErrorMessageBuf(PCRE2_ERROR_NOMATCH, buf); rc != 8 || string(buf[:9]) != "no match\x00" {
		t.Errorf("full: rc=%d buf=%q", rc, buf[:9])
	}
}

func TestValidUTF(t *testing.T) {
	cases := []struct {
		in   string
		rc   int
		off  uint64
		name string
	}{
		{"", 0, 0, "empty"},
		{"abc é €  😀", 0, 0, "valid"},
		{"a\x80", PCRE2_ERROR_UTF8_ERR20, 1, "isolated"},
		{"ab\xfe", PCRE2_ERROR_UTF8_ERR21, 2, "fe"},
		{"\xff", PCRE2_ERROR_UTF8_ERR21, 0, "ff"},
		{"a\xc3", PCRE2_ERROR_UTF8_ERR1, 1, "missing 1"},
		{"\xe2\x82", PCRE2_ERROR_UTF8_ERR1, 0, "missing 1 of 3"},
		{"\xe2", PCRE2_ERROR_UTF8_ERR2, 0, "missing 2"},
		{"\xf0\x9f", PCRE2_ERROR_UTF8_ERR2, 0, "missing 2 of 4"},
		{"\xf0", PCRE2_ERROR_UTF8_ERR3, 0, "missing 3"},
		{"\xf8", PCRE2_ERROR_UTF8_ERR4, 0, "missing 4"},
		{"\xfc", PCRE2_ERROR_UTF8_ERR5, 0, "missing 5"},
		{"\xc3\x28", PCRE2_ERROR_UTF8_ERR6, 0, "byte 2"},
		{"\xe2\x82\x28", PCRE2_ERROR_UTF8_ERR7, 0, "byte 3"},
		{"\xf0\x9f\x98\x28", PCRE2_ERROR_UTF8_ERR8, 0, "byte 4"},
		{"\xf8\x88\x80\x80\x28", PCRE2_ERROR_UTF8_ERR9, 0, "byte 5"},
		{"\xfc\x84\x80\x80\x80\x28", PCRE2_ERROR_UTF8_ERR10, 0, "byte 6"},
		{"\xf8\x88\x80\x80\x80", PCRE2_ERROR_UTF8_ERR11, 0, "5-byte char"},
		{"\xfc\x84\x80\x80\x80\x80", PCRE2_ERROR_UTF8_ERR12, 0, "6-byte char"},
		{"\xf4\x90\x80\x80", PCRE2_ERROR_UTF8_ERR13, 0, "> 0x10ffff"},
		{"\xf5\x80\x80\x80", PCRE2_ERROR_UTF8_ERR13, 0, "f5"},
		{"\xed\xa0\x80", PCRE2_ERROR_UTF8_ERR14, 0, "surrogate"},
		{"\xc0\x80", PCRE2_ERROR_UTF8_ERR15, 0, "overlong 2"},
		{"\xc1\xbf", PCRE2_ERROR_UTF8_ERR15, 0, "overlong 2 c1"},
		{"\xe0\x80\x80", PCRE2_ERROR_UTF8_ERR16, 0, "overlong 3"},
		{"\xf0\x80\x80\x80", PCRE2_ERROR_UTF8_ERR17, 0, "overlong 4"},
		{"\xf8\x80\x80\x80\x80", PCRE2_ERROR_UTF8_ERR18, 0, "overlong 5"},
		{"\xfc\x80\x80\x80\x80\x80", PCRE2_ERROR_UTF8_ERR19, 0, "overlong 6"},
		{"xy\xe0\x80\x80", PCRE2_ERROR_UTF8_ERR16, 2, "offset after prefix"},
	}
	for _, c := range cases {
		rc, off := ValidUTF([]byte(c.in))
		if rc != c.rc || off != c.off {
			t.Errorf("%s: rc=%d off=%d, want rc=%d off=%d", c.name, rc, off, c.rc, c.off)
		}
	}
}

// ValidUTF must agree with Go's validator on validity (both implement RFC
// 3629 for the lengths that can be valid) for every 1-4 byte prefix class.
func TestValidUTFAgreesWithGo(t *testing.T) {
	for _, r := range []rune{0, 0x7f, 0x80, 0x7ff, 0x800, 0xd7ff, 0xe000, 0xffff, 0x10000, 0x10ffff} {
		s := string(r)
		if rc, _ := ValidUTF([]byte(s)); rc != 0 {
			t.Errorf("%U rejected: %d", r, rc)
		}
	}
	for b := 0; b < 256; b++ {
		for c := 0; c < 256; c += 5 {
			s := []byte{byte(b), byte(c), 0x80, 0x80}
			rc, off := ValidUTF(s)
			if (rc == 0) != utf8.Valid(s) {
				t.Fatalf("% x: rc=%d, utf8.Valid=%v", s, rc, utf8.Valid(s))
			}
			if rc != 0 && off >= uint64(len(s)) {
				t.Fatalf("% x: offset %d out of range", s, off)
			}
		}
	}
}

func FuzzValidUTF(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add([]byte("\xe2\x82\xac"))
	f.Add([]byte("\xf8\x88\x80\x80\x80"))
	f.Fuzz(func(t *testing.T, s []byte) {
		rc, off := ValidUTF(s)
		if (rc == 0) != utf8.Valid(s) {
			t.Fatalf("% x: rc=%d but utf8.Valid=%v", s, rc, utf8.Valid(s))
		}
		if rc != 0 {
			if off >= uint64(len(s)) {
				t.Fatalf("offset %d beyond %d", off, len(s))
			}
			if rc > PCRE2_ERROR_UTF8_ERR1 || rc < PCRE2_ERROR_UTF8_ERR21 {
				t.Fatalf("rc %d not a UTF-8 error", rc)
			}
		}
	})
}

func TestOrd2UTF(t *testing.T) {
	buf := make([]byte, 8)
	for _, r := range []rune{0, 'a', 0x7f, 0x80, 0x7ff, 0x800, 0xffff, 0x10000, 0x10ffff} {
		n := ord2utf(uint32(r), buf)
		if string(buf[:n]) != string(r) {
			t.Errorf("%U: % x", r, buf[:n])
		}
	}
	for r := rune(0); r <= 0x10ffff; r += 97 {
		if r >= 0xd800 && r <= 0xdfff {
			continue
		}
		n := ord2utf(uint32(r), buf)
		if string(buf[:n]) != string(r) {
			t.Fatalf("%U", r)
		}
	}
	// beyond Unicode: the 5- and 6-byte forms PCRE2 still produces
	if n := ord2utf(0x200000, buf); n != 5 || buf[0] != 0xf8 {
		t.Errorf("0x200000: n=%d % x", n, buf[:n])
	}
	if n := ord2utf(0x7fffffff, buf); n != 6 || buf[0] != 0xfd {
		t.Errorf("0x7fffffff: n=%d % x", n, buf[:n])
	}
	// and the utf character macros decode what it wrote
	for _, r := range []uint32{'a', 0xe9, 0x20ac, 0x1f600, 0x10ffff} {
		clear(buf)
		n := ord2utf(r, buf)
		if c, i := GETCHARINC(buf, 0); c != r || i != int(n) {
			t.Errorf("GETCHARINC %U: %U %d", r, c, i)
		}
		if c, x := GETCHARLEN(buf, 0); c != r || x != int(n)-1 {
			t.Errorf("GETCHARLEN %U", r)
		}
		if BACKCHAR(buf, int(n)-1) != 0 || FORWARDCHAR(buf, 1) != int(n) && n > 1 {
			t.Errorf("BACKCHAR/FORWARDCHAR %U", r)
		}
	}
}

func TestPutGet(t *testing.T) {
	b := make([]byte, 4)
	PUT(b, 1, 0xabcd)
	if b[1] != 0xab || b[2] != 0xcd || GET(b, 1) != 0xabcd {
		t.Errorf("% x", b)
	}
	PUT2(b, 0, 0x1234)
	if GET2(b, 0) != 0x1234 || PUTINC(b, 0, 7) != 2 || PUT2INC(b, 2, 9) != 4 {
		t.Error("PUTINC")
	}
}

func TestChkdint(t *testing.T) {
	var r uint64
	if ckd_smul(&r, 1<<20, 1<<10) || r != 1<<30 {
		t.Error("1<<30")
	}
	if ckd_smul(&r, -1, 5) {
		// negative result overflows a PCRE2_SIZE
	} else {
		t.Error("negative product must overflow")
	}
	if ckd_smul(&r, 0x7fffffff, 0x7fffffff) || r != 0x7fffffff*0x7fffffff {
		t.Error("large product fits in 64 bits")
	}
}

func TestConstantsSpotChecks(t *testing.T) {
	var cases = []struct {
		name     string
		got, exp uint64
	}{
		{"PCRE2_CASELESS", uint64(PCRE2_CASELESS), 8},
		{"PCRE2_ANCHORED", uint64(PCRE2_ANCHORED), 0x80000000},
		{"PCRE2_MATCH_INVALID_UTF", uint64(PCRE2_MATCH_INVALID_UTF), 0x04000000},
		{"PCRE2_EXTRA_ASCII_DIGIT", uint64(PCRE2_EXTRA_ASCII_DIGIT), 0x1000},
		{"PCRE2_DISABLE_RECURSELOOP_CHECK", uint64(PCRE2_DISABLE_RECURSELOOP_CHECK), 0x40000},
		{"PCRE2_INFO_EXTRAOPTIONS", uint64(PCRE2_INFO_EXTRAOPTIONS), 26},
		{"PCRE2_CONFIG_TABLES_LENGTH", uint64(PCRE2_CONFIG_TABLES_LENGTH), 15},
		{"PCRE2_NEWLINE_NUL", uint64(PCRE2_NEWLINE_NUL), 6},
		{"OP_END", uint64(OP_END), 0},
		{"OP_TABLE_LENGTH", uint64(OP_TABLE_LENGTH), uint64(len(OP_lengths))},
		{"META_END", uint64(META_END), 0x80000000},
		{"ERR0", uint64(ERR0), 100},
		{"PCRE2_FIRSTSET", uint64(PCRE2_FIRSTSET), 0x10},
		{"TABLES_LENGTH", uint64(TABLES_LENGTH), 1088},
		{"MAGIC_NUMBER", uint64(MAGIC_NUMBER), 0x50435245},
		{"LINK_SIZE", uint64(LINK_SIZE), 2},
		{"IMM2_SIZE", uint64(IMM2_SIZE), 2},
	}
	for _, c := range cases {
		if c.got != c.exp {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.exp)
		}
	}
	if PCRE2_ERROR_NOMATCH != -1 || PCRE2_ERROR_DEPTHLIMIT != -53 || PCRE2_ERROR_INVALIDOFFSET != -67 {
		t.Error("error codes")
	}
	// spot values of the opcode length table that depend on LINK_SIZE/IMM2_SIZE
	if OP_lengths[OP_CBRA] != 1+LINK_SIZE+IMM2_SIZE || OP_lengths[OP_CLASS] != 33 ||
		OP_lengths[OP_EXACT] != 2+IMM2_SIZE || OP_lengths[OP_XCLASS] != 0 || OP_lengths[OP_CALLOUT] != 6 {
		t.Error("OP_lengths")
	}
}

// parseChartables extracts the table bytes of pcre2_chartables.c.dist.
func parseChartables(t *testing.T) []byte {
	src := cSource(t, "pcre2_chartables.c.dist")
	i := strings.Index(src, "pcre2_default_tables[] = {")
	if i < 0 {
		i = strings.Index(src, "default_tables")
	}
	body := src[i:]
	body = body[strings.Index(body, "{")+1:]
	body = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(body, "")
	var out []byte
	// the lower-casing and case-flipping tables are in decimal, the rest in hex
	for _, h := range regexp.MustCompile(`0x[0-9a-fA-F]{2}|\b[0-9]+\b`).FindAllString(body, -1) {
		v, err := strconv.ParseUint(h, 0, 8)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, byte(v))
	}
	return out
}

func TestMaketablesMatchesDefaultTables(t *testing.T) {
	want := parseChartables(t)
	if len(want) != TABLES_LENGTH {
		t.Fatalf("parsed %d bytes, want %d", len(want), TABLES_LENGTH)
	}
	got := Maketables()
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Maketables differs from pcre2_chartables.c.dist at %d: %#x vs %#x", i, got[i], want[i])
		}
		if default_tables[i] != want[i] {
			t.Fatalf("default_tables differs at %d", i)
		}
	}
}

func TestTablesSpot(t *testing.T) {
	tb := Maketables()
	if tb[lcc_offset+'A'] != 'a' || tb[fcc_offset+'a'] != 'A' || tb[fcc_offset+'1'] != '1' {
		t.Error("case tables")
	}
	if tb[ctypes_offset+'_'] != ctype_word || tb[ctypes_offset+'a'] != ctype_letter|ctype_lcletter|ctype_word ||
		tb[ctypes_offset+' '] != ctype_space || tb[ctypes_offset+'7'] != ctype_digit|ctype_word {
		t.Error("ctypes")
	}
	if tb[cbits_offset+cbit_digit+'0'/8]&(1<<('0'&7)) == 0 {
		t.Error("cbit_digit")
	}
}

func TestNewlineHelpers(t *testing.T) {
	s := []byte("a\r\nb\xc2\x85c\xe2\x80\xa8")
	if ok, n := is_newline(s, 1, NLTYPE_ANYCRLF, len(s), true); !ok || n != 2 {
		t.Errorf("CRLF: %v %d", ok, n)
	}
	if ok, n := is_newline(s, 4, NLTYPE_ANY, len(s), true); !ok || n != 2 {
		t.Errorf("NEL utf: %v %d", ok, n)
	}
	if ok, _ := is_newline(s, 4, NLTYPE_ANYCRLF, len(s), true); ok {
		t.Error("NEL is not ANYCRLF")
	}
	if ok, n := is_newline(s, 7, NLTYPE_ANY, len(s), true); !ok || n != 3 {
		t.Errorf("LS: %v %d", ok, n)
	}
	if ok, n := was_newline(s, 3, NLTYPE_ANYCRLF, 0, true); !ok || n != 2 {
		t.Errorf("was CRLF: %v %d", ok, n)
	}
	if ok, n := was_newline(s, 6, NLTYPE_ANY, 0, true); !ok || n != 2 {
		t.Errorf("was NEL: %v %d", ok, n)
	}
	if ok, n := was_newline(s, len(s), NLTYPE_ANY, 0, true); !ok || n != 3 {
		t.Errorf("was LS: %v %d", ok, n)
	}
	if ok, _ := was_newline(s, 1, NLTYPE_ANY, 0, true); ok {
		t.Error("'a' is no newline")
	}
}

func TestStringUtils(t *testing.T) {
	if strcmp([]byte("abc\x00zzz"), []byte("abc")) != 0 || strcmp([]byte("ab"), []byte("abc")) != -1 ||
		strcmp([]byte("b"), []byte("a")) != 1 {
		t.Error("strcmp")
	}
	if strncmp([]byte("abcX"), []byte("abcY"), 3) != 0 || strncmp([]byte("abcX"), []byte("abcY"), 4) != -1 {
		t.Error("strncmp")
	}
	if strcmp_c8([]byte("xy"), "xy") != 0 || strncmp_c8([]byte("xyz"), "xya", 2) != 0 || strlen([]byte("ab\x00c")) != 2 {
		t.Error("c8 variants")
	}
	buf := make([]byte, 8)
	if strcpy_c8(buf, "hey") != 3 || string(buf[:4]) != "hey\x00" {
		t.Error("strcpy_c8")
	}
}

// buildCode hand-builds a Code whose name table lists the given names (sorted,
// duplicates adjacent) with group numbers.
func buildCode(topBracket uint16, entries ...any) *Code {
	re := &Code{magicNumber: MAGIC_NUMBER, flags: PCRE2_MODE8, topBracket: topBracket, nameEntrySize: 8}
	for i := 0; i < len(entries); i += 2 {
		e := make([]byte, 8)
		PUT2(e, 0, entries[i+1].(int))
		copy(e[IMM2_SIZE:], entries[i].(string))
		re.code = append(re.code, e...)
		re.nameCount++
	}
	re.code = append(re.code, OP_END)
	return re
}

func TestSubstringFunctions(t *testing.T) {
	re := buildCode(3, "dup", 1, "dup", 3, "one", 2)
	md := NewMatchData(re)
	if md.OvectorCount() != 4 || len(md.Ovector()) != 8 {
		t.Fatalf("ovector sizing %d %d", md.OvectorCount(), len(md.Ovector()))
	}
	subject := []byte("hello world")
	md.code, md.subject, md.subjectLength, md.rc = re, subject, uint64(len(subject)), 4
	copy(md.ovector, []uint64{0, 11, PCRE2_UNSET, PCRE2_UNSET, 6, 11, 0, 5})

	if SubstringNumberFromName(re, "one") != 2 || SubstringNumberFromName(re, "none") != PCRE2_ERROR_NOSUBSTRING ||
		SubstringNumberFromName(re, "dup") != PCRE2_ERROR_NOUNIQUESUBSTRING {
		t.Error("number from name")
	}
	if entrysize, first, last := SubstringNametableScan(re, "dup"); entrysize != 8 || first != 0 || last != 8 {
		t.Errorf("scan: %d %d %d", entrysize, first, last)
	}
	if n, rc := SubstringLengthByNumber(md, 2); rc != 0 || n != 5 {
		t.Errorf("length: %d %d", n, rc)
	}
	if _, rc := SubstringLengthByNumber(md, 1); rc != PCRE2_ERROR_UNSET {
		t.Errorf("unset: %d", rc)
	}
	if _, rc := SubstringLengthByNumber(md, 4); rc != PCRE2_ERROR_NOSUBSTRING {
		t.Errorf("no such: %d", rc)
	}
	buf := make([]byte, 6)
	if n, rc := SubstringCopyByNumber(md, 2, buf); rc != 0 || n != 5 || string(buf) != "world\x00" {
		t.Errorf("copy: %d %d %q", n, rc, buf)
	}
	if _, rc := SubstringCopyByNumber(md, 2, buf[:5]); rc != PCRE2_ERROR_NOMEMORY {
		t.Errorf("small buffer: %d", rc)
	}
	// duplicate name: group 1 is unset, so the first set one (3) is used
	if s, rc := SubstringGetByName(md, "dup"); rc != 0 || string(s) != "hello" {
		t.Errorf("get by dup name: %q %d", s, rc)
	}
	if n, rc := SubstringLengthByName(md, "one"); rc != 0 || n != 5 {
		t.Errorf("length by name: %d %d", n, rc)
	}
	if n, rc := SubstringCopyByName(md, "one", make([]byte, 10)); rc != 0 || n != 5 {
		t.Errorf("copy by name: %d %d", n, rc)
	}
	list, lens, rc := SubstringListGet(md)
	if rc != 0 || len(list) != 4 || string(list[0]) != "hello world" || len(list[1]) != 0 || lens[2] != 5 {
		t.Errorf("list: %q %v %d", list, lens, rc)
	}
	// partial / failed matches
	md.rc = PCRE2_ERROR_NOMATCH
	if _, rc := SubstringLengthByNumber(md, 0); rc != PCRE2_ERROR_NOMATCH {
		t.Error("failed match")
	}
	md.rc = PCRE2_ERROR_PARTIAL
	if _, rc := SubstringLengthByNumber(md, 1); rc != PCRE2_ERROR_PARTIAL {
		t.Error("partial, group 1")
	}
	// DFA-matched data refuses by-name access
	md.rc, md.matchedby = 1, PCRE2_MATCHEDBY_DFA_INTERPRETER
	if _, rc := SubstringGetByName(md, "one"); rc != PCRE2_ERROR_DFA_UFUNC {
		t.Error("dfa by name")
	}
	// start beyond end (\K in an assertion) gives length zero
	md.matchedby = PCRE2_MATCHEDBY_INTERPRETER
	md.rc = 1
	md.ovector[0], md.ovector[1] = 8, 3
	if n, rc := SubstringLengthByNumber(md, 0); rc != 0 || n != 0 {
		t.Errorf("start>end: %d %d", n, rc)
	}
	md.ovector[0] = 99
	if _, rc := SubstringLengthByNumber(md, 0); rc != PCRE2_ERROR_INVALIDOFFSET {
		t.Error("invalid offset")
	}
}

func TestMatchDataSizing(t *testing.T) {
	if NewMatchDataSize(0).OvectorCount() != 1 || NewMatchDataSize(1<<20).OvectorCount() != 0xffff {
		t.Error("clamping")
	}
	md := NewMatchDataSize(3)
	if md.GetMatchDataSize() != 104+2*3*8 {
		t.Errorf("size %d", md.GetMatchDataSize())
	}
	md.Free()
}

func TestContexts(t *testing.T) {
	cc := NewCompileContext()
	if cc.SetNewline(99) != PCRE2_ERROR_BADDATA || cc.SetNewline(PCRE2_NEWLINE_ANYCRLF) != 0 ||
		cc.SetBSR(7) != PCRE2_ERROR_BADDATA || cc.SetBSR(PCRE2_BSR_ANYCRLF) != 0 {
		t.Error("compile context validation")
	}
	if cc.newlineConvention != PCRE2_NEWLINE_ANYCRLF || NewCompileContext().newlineConvention != NEWLINE_DEFAULT ||
		cc.parensNestLimit != 250 || cc.maxVarlookbehind != 255 || cc.maxPatternLength != PCRE2_UNSET {
		t.Error("compile context defaults")
	}
	cp := cc.Copy()
	cp.SetParensNestLimit(5)
	if cc.parensNestLimit == 5 {
		t.Error("copy is shared")
	}
	mc := NewMatchContext()
	if mc.matchLimit != 10000000 || mc.heapLimit != 20000000 || mc.depthLimit != 10000000 || mc.offsetLimit != PCRE2_UNSET {
		t.Error("match context defaults")
	}
	called := 0
	mc.SetCallout(func(*CalloutBlock, any) int { called++; return 0 }, nil)
	mc.callout(nil, nil)
	if called != 1 {
		t.Error("callout")
	}
	cv := NewConvertContext()
	if cv.SetGlobSeparator('x') != PCRE2_ERROR_BADDATA || cv.SetGlobEscape('a') != PCRE2_ERROR_BADDATA ||
		cv.SetGlobEscape('`') != 0 || cv.SetGlobEscape(0) != 0 {
		t.Error("convert context")
	}
	if js := JITStackCreate(1, 0); js != nil {
		t.Error("jit stack with max 0")
	}
	if js := JITStackCreate(32<<10, 64<<10); js == nil {
		t.Error("jit stack")
	} else {
		mc.JITStackAssign(js)
		JITStackFree(js)
	}
}

func TestPatternInfoAndConfig(t *testing.T) {
	re := buildCode(2, "n", 1)
	re.flags |= PCRE2_FIRSTSET | PCRE2_HASCRORLF
	re.firstCodeunit = 'x'
	re.limitMatch = 0xffffffff
	re.limitDepth = 77
	re.overallOptions = PCRE2_UTF
	re.blocksize = 500
	checks := []struct {
		what uint32
		val  uint64
		rc   int
	}{
		{PCRE2_INFO_CAPTURECOUNT, 2, 0}, {PCRE2_INFO_FIRSTCODETYPE, 1, 0}, {PCRE2_INFO_FIRSTCODEUNIT, 'x', 0},
		{PCRE2_INFO_LASTCODETYPE, 0, 0}, {PCRE2_INFO_HASCRORLF, 1, 0}, {PCRE2_INFO_MATCHEMPTY, 0, 0},
		{PCRE2_INFO_MATCHLIMIT, 0xffffffff, PCRE2_ERROR_UNSET}, {PCRE2_INFO_DEPTHLIMIT, 77, 0},
		{PCRE2_INFO_NAMECOUNT, 1, 0}, {PCRE2_INFO_NAMEENTRYSIZE, 8, 0}, {PCRE2_INFO_SIZE, 500, 0},
		{PCRE2_INFO_ALLOPTIONS, uint64(PCRE2_UTF), 0}, {PCRE2_INFO_JITSIZE, 0, 0},
		{PCRE2_INFO_FRAMESIZE, 136 + 2*2*8, 0}, {1000, 0, PCRE2_ERROR_BADOPTION},
	}
	for _, c := range checks {
		if v, rc := re.PatternInfo(c.what); v != c.val || rc != c.rc {
			t.Errorf("info %d: (%d, %d), want (%d, %d)", c.what, v, rc, c.val, c.rc)
		}
	}
	tab, n, sz := re.NameTable()
	if n != 1 || sz != 8 || len(tab) != 8 || tab[1] != 1 || tab[2] != 'n' {
		t.Errorf("name table %v %d %d", tab, n, sz)
	}
	if re.FirstBitmap() != nil {
		t.Error("no bitmap")
	}
	bad := &Code{}
	if _, rc := bad.PatternInfo(PCRE2_INFO_SIZE); rc != PCRE2_ERROR_BADMAGIC {
		t.Error("bad magic")
	}
	if _, rc := (*Code)(nil).PatternInfo(PCRE2_INFO_SIZE); rc != PCRE2_ERROR_NULL {
		t.Error("null")
	}
	if re.JITCompile(PCRE2_JIT_COMPLETE) != PCRE2_ERROR_JIT_BADOPTION {
		t.Error("jit")
	}

	if v, _, rc := Config(PCRE2_CONFIG_LINKSIZE); v != 2 || rc != 0 {
		t.Error("linksize")
	}
	if _, s, rc := Config(PCRE2_CONFIG_VERSION); s != "10.44 2024-06-07" || rc != 17 {
		t.Errorf("version %q %d", s, rc)
	}
	if _, s, _ := Config(PCRE2_CONFIG_UNICODE_VERSION); s != "15.0.0" {
		t.Errorf("unicode version %q", s)
	}
	if v, _, _ := Config(PCRE2_CONFIG_UNICODE); v != 1 {
		t.Error("unicode")
	}
	if _, _, rc := Config(PCRE2_CONFIG_JITTARGET); rc != PCRE2_ERROR_BADOPTION {
		t.Error("jit target")
	}
	if _, _, rc := Config(999); rc != PCRE2_ERROR_BADOPTION {
		t.Error("unknown")
	}
	if v, _, _ := Config(PCRE2_CONFIG_TABLES_LENGTH); v != 1088 {
		t.Error("tables length")
	}
}

func TestCalloutEnumerate(t *testing.T) {
	re := buildCode(0)
	re.nameCount, re.nameEntrySize, re.code = 0, 0, nil
	co := make([]byte, 1+3*LINK_SIZE-LINK_SIZE+1) // OP_CALLOUT, pos, len, number
	co[0] = OP_CALLOUT
	PUT(co, 1, 3)
	PUT(co, 1+LINK_SIZE, 4)
	co[1+2*LINK_SIZE] = 42
	re.code = append(append(co, 'x'), OP_END)
	// 'x' is not an opcode of interest but OP_lengths[x] must exist: use OP_NOT_DIGIT instead
	re.code[len(re.code)-2] = OP_NOT_DIGIT
	var got []string
	rc := re.CalloutEnumerate(func(b *CalloutEnumerateBlock, _ any) int {
		got = append(got, fmt.Sprintf("%d/%d/%d", b.PatternPosition, b.NextItemLength, b.CalloutNumber))
		return 0
	}, nil)
	if rc != 0 || len(got) != 1 || got[0] != "3/4/42" {
		t.Errorf("rc=%d got=%v", rc, got)
	}
}

func TestFindBracket(t *testing.T) {
	// OP_BRA, link, OP_CBRA link n=1 ... OP_KET .. OP_CBRA n=2
	var c []byte
	c = append(c, OP_CBRA, 0, 9, 0, 1) // CBRA 1 (len 1+2+2 = 5)
	c = append(c, OP_NOT_DIGIT, OP_KET, 0, 4)
	off2 := len(c)
	c = append(c, OP_CBRA, 0, 9, 0, 2, OP_KET, 0, 4, OP_END)
	if find_bracket(c, 0, false, 1) != 0 || find_bracket(c, 0, false, 2) != off2 || find_bracket(c, 0, false, 3) != -1 {
		t.Error("find_bracket")
	}
}

func TestStubs(t *testing.T) {
	// until compile.go / match.go replace them, the stubs report an internal error
	if _, rc, _ := Compile([]byte("a"), 0, nil); rc != PCRE2_ERROR_INTERNAL && rc <= 0 {
		t.Errorf("unexpected compile rc %d", rc)
	}
}
