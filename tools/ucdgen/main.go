// Command ucdgen turns the Unicode tables of PCRE2 10.44, which are C
// initialisers, into Go source, so that they are never retyped by hand.
//
// It reads pcre2_ucd.c (the two-stage UCD tables, the caseless, digit, script
// extension and boolean property sets), pcre2_ucptables.c (the property name
// table) and pcre2_ucp.h (the item sizes of the sets) from a PCRE2 "src"
// directory and writes two files into the output directory:
//
//	ucd_tables.go   unicode_version, ucd_caseless_sets, ucd_digit_sets,
//	                ucd_script_sets, ucd_boolprop_sets, ucd_records,
//	                ucd_stage1, ucd_stage2 and the *_item_size constants
//	ucptables.go    utt_names, utt, utt_size
//
// The C names are kept (without the PRIV() wrapper) so that diffs against the C
// text are easy. PRIV(dummy_ucd_record) exists only for the 32-bit library
// (#if PCRE2_CODE_UNIT_WIDTH == 32) and is therefore not generated: this port
// is 8-bit.
//
// Usage:
//
//	ucdgen -src $PCRE2_SRC -out .
//
// The module has no dependency, so the standard flag package is used; run is
// driven by tests.
package main

import (
	"flag"
	"fmt"
	"go/format"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ucdgen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	src := fs.String("src", os.Getenv("PCRE2_SRC"), "PCRE2 src directory (default $PCRE2_SRC)")
	out := fs.String("out", ".", "output directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *src == "" {
		fmt.Fprintln(stderr, "ucdgen: -src (or $PCRE2_SRC) is required")
		return 2
	}
	read := func(name string) (string, bool) {
		b, err := os.ReadFile(filepath.Join(*src, name))
		if err != nil {
			fmt.Fprintf(stderr, "ucdgen: %v\n", err)
			return "", false
		}
		return string(b), true
	}
	ucdC, ok1 := read("pcre2_ucd.c")
	uptC, ok2 := read("pcre2_ucptables.c")
	ucpH, ok3 := read("pcre2_ucp.h")
	if !ok1 || !ok2 || !ok3 {
		return 1
	}
	ucdGo, err := genUCD(ucdC, ucpH)
	if err != nil {
		fmt.Fprintf(stderr, "ucdgen: pcre2_ucd.c: %v\n", err)
		return 1
	}
	uptGo, err := genUTT(uptC)
	if err != nil {
		fmt.Fprintf(stderr, "ucdgen: pcre2_ucptables.c: %v\n", err)
		return 1
	}
	for name, text := range map[string]string{"ucd_tables.go": ucdGo, "ucptables.go": uptGo} {
		if err := os.WriteFile(filepath.Join(*out, name), []byte(text), 0o644); err != nil {
			fmt.Fprintf(stderr, "ucdgen: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "wrote %s\n", filepath.Join(*out, name))
	}
	return 0
}

// stripComments removes C comments, leaving string literals alone.
func stripComments(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		switch {
		case s[i] == '"':
			j := i + 1
			for j < len(s) && s[j] != '"' {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			if j < len(s) {
				j++
			}
			b.WriteString(s[i:j])
			i = j
		case strings.HasPrefix(s[i:], "/*"):
			j := strings.Index(s[i+2:], "*/")
			if j < 0 {
				i = len(s)
			} else {
				i += j + 4
			}
			b.WriteByte(' ')
		default:
			b.WriteByte(s[i])
			i++
		}
	}
	return b.String()
}

// initialiser returns the text between the braces of the C initialiser of the
// array named name, written as "PRIV(name)[] = {" (comments already removed).
// When the declaration occurs more than once (the #ifndef SUPPORT_UNICODE stub
// comes first) the longest body is taken.
func initialiser(src, name string) (string, error) {
	re := regexp.MustCompile(`(?:PRIV\(` + regexp.QuoteMeta(name) + `\)|\b` + regexp.QuoteMeta(name) + `\b)\s*\[\]\s*=\s*\{`)
	best := ""
	found := false
	for _, loc := range re.FindAllStringIndex(src, -1) {
		depth := 1
		i := loc[1]
		start := i
		for ; i < len(src) && depth > 0; i++ {
			switch src[i] {
			case '{':
				depth++
			case '}':
				depth--
			}
		}
		if depth != 0 {
			return "", fmt.Errorf("unterminated initialiser of %s", name)
		}
		body := src[start : i-1]
		if !found || len(body) > len(best) {
			best = body
		}
		found = true
	}
	if !found {
		return "", fmt.Errorf("array %s not found", name)
	}
	return best, nil
}

// token is a number of the C text, or the symbol NOTACHAR.
func token(t string) (string, error) {
	if t == "NOTACHAR" {
		return t, nil
	}
	n := strings.TrimRight(t, "uU")
	neg := strings.HasPrefix(n, "-")
	v, err := strconv.ParseUint(strings.TrimPrefix(n, "-"), 0, 64)
	if err != nil {
		return "", fmt.Errorf("unsupported token %q", t)
	}
	if neg {
		return "-" + strconv.FormatUint(v, 10), nil
	}
	if strings.HasPrefix(n, "0x") || strings.HasPrefix(n, "0X") {
		return "0x" + strings.ToLower(n[2:]), nil
	}
	return strconv.FormatUint(v, 10), nil
}

// tokens splits a flat initialiser into its tokens.
func tokens(body string) ([]string, error) {
	var out []string
	for _, f := range strings.FieldsFunc(body, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}) {
		t, err := token(f)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// records splits an initialiser of {a, b, ...} groups into groups of tokens.
func records(body string, fields int) ([][]string, error) {
	var out [][]string
	for {
		i := strings.IndexByte(body, '{')
		if i < 0 {
			break
		}
		j := strings.IndexByte(body[i:], '}')
		if j < 0 {
			return nil, fmt.Errorf("unterminated record")
		}
		toks, err := tokens(body[i+1 : i+j])
		if err != nil {
			return nil, err
		}
		if len(toks) != fields {
			return nil, fmt.Errorf("record %d has %d fields, want %d", len(out), len(toks), fields)
		}
		out = append(out, toks)
		body = body[i+j+1:]
	}
	if strings.TrimSpace(strings.Trim(body, ", \n\t")) != "" {
		return nil, fmt.Errorf("text after the last record: %q", body)
	}
	return out, nil
}

// emitList writes values perLine to a line.
func emitList(b *strings.Builder, vals []string, perLine int) {
	for i, v := range vals {
		if i%perLine == 0 {
			b.WriteString("\n\t")
		} else {
			b.WriteByte(' ')
		}
		b.WriteString(v)
		b.WriteByte(',')
	}
	b.WriteString("\n")
}

const hdr = "// Code generated by tools/ucdgen; DO NOT EDIT.\n// Source: %s (PCRE2 10.44)\n\npackage pcre2\n\n"

func genUCD(ucdC, ucpH string) (string, error) {
	m := regexp.MustCompile(`unicode_version\)\s*=\s*"([^"]*)"`).FindStringSubmatch(ucdC)
	if m == nil {
		return "", fmt.Errorf("unicode_version not found")
	}
	var b strings.Builder
	fmt.Fprintf(&b, hdr, "pcre2_ucd.c and pcre2_ucp.h")
	fmt.Fprintf(&b, "// unicode_version is PRIV(unicode_version) (pcre2_ucd.c).\nconst unicode_version = %q\n\n", m[1])

	// The item sizes of the bitset tables (pcre2_ucp.h).
	sizes := regexp.MustCompile(`(?m)^#define\s+(ucd_\w+_item_size)\s+(\d+)`).FindAllStringSubmatch(ucpH, -1)
	if len(sizes) != 2 {
		return "", fmt.Errorf("want 2 *_item_size defines in pcre2_ucp.h, found %d", len(sizes))
	}
	b.WriteString("// Number of 32-bit words of one bitset (pcre2_ucp.h).\nconst (\n")
	for _, s := range sizes {
		fmt.Fprintf(&b, "\t%s = %s\n", s[1], s[2])
	}
	b.WriteString(")\n\n")

	src := stripComments(ucdC)
	flat := []struct{ name, doc string }{
		{"ucd_caseless_sets", "lists of characters that are caseless sets of more than one character, each terminated by NOTACHAR."},
		{"ucd_digit_sets", "the code points of the '9' of each set of decimal digits; the first element is the number of following ones."},
		{"ucd_script_sets", "the Script Extension bitsets (ucd_script_sets_item_size words each)."},
		{"ucd_boolprop_sets", "the Boolean property bitsets (ucd_boolprop_sets_item_size words each)."},
	}
	for _, f := range flat {
		body, err := initialiser(src, f.name)
		if err != nil {
			return "", err
		}
		toks, err := tokens(body)
		if err != nil {
			return "", fmt.Errorf("%s: %w", f.name, err)
		}
		fmt.Fprintf(&b, "// %s holds %s\nvar %s = []uint32{", f.name, f.doc, f.name)
		emitList(&b, toks, 8)
		b.WriteString("}\n\n")
	}

	body, err := initialiser(src, "ucd_records")
	if err != nil {
		return "", err
	}
	recs, err := records(body, 7)
	if err != nil {
		return "", fmt.Errorf("ucd_records: %w", err)
	}
	b.WriteString("// ucd_records are the records of the two-stage table: script, chartype,\n// gbprop, caseset, other_case, scriptx_bidiclass, bprops.\nvar ucd_records = []ucdRecord{\n")
	for i, r := range recs {
		fmt.Fprintf(&b, "\t{%s}, // %d\n", strings.Join(r, ", "), i)
	}
	b.WriteString("}\n\n")

	for _, st := range []string{"ucd_stage1", "ucd_stage2"} {
		body, err := initialiser(src, st)
		if err != nil {
			return "", err
		}
		toks, err := tokens(body)
		if err != nil {
			return "", fmt.Errorf("%s: %w", st, err)
		}
		fmt.Fprintf(&b, "// %s is the %s index of the two-stage table.\nvar %s = []uint16{", st, strings.TrimPrefix(st, "ucd_"), st)
		emitList(&b, toks, 16)
		b.WriteString("}\n\n")
	}
	out, err := format.Source([]byte(b.String()))
	return string(out), err
}

var (
	reDefine = regexp.MustCompile(`(?m)^#define\s+(STRING_\w+)\s+(.*)$`)
	reUTT    = regexp.MustCompile(`\{\s*(\d+)\s*,\s*(PT_\w+)\s*,\s*(\w+)\s*\}`)
)

func genUTT(c string) (string, error) {
	defs := map[string]string{}
	for _, m := range reDefine.FindAllStringSubmatch(c, -1) {
		var name strings.Builder
		for _, f := range strings.Fields(m[2]) {
			switch {
			case f == `"\0"`:
				name.WriteByte(0)
			case f == "STR_AMPERSAND": // pcre2_internal.h:812
				name.WriteByte('&')
			case strings.HasPrefix(f, "STR_") && len(f) == 5:
				name.WriteByte(f[4])
			default:
				return "", fmt.Errorf("%s: unsupported token %q", m[1], f)
			}
		}
		defs[m[1]] = name.String()
	}
	i := strings.Index(c, "PRIV(utt_names)[] =")
	if i < 0 {
		return "", fmt.Errorf("utt_names not found")
	}
	j := strings.Index(c[i:], ";")
	var names []string
	for _, f := range strings.Fields(c[i+len("PRIV(utt_names)[] =") : i+j]) {
		s, ok := defs[f]
		if !ok {
			return "", fmt.Errorf("utt_names: undefined %s", f)
		}
		names = append(names, s)
	}
	k := strings.Index(c, "PRIV(utt)[] = {")
	if k < 0 {
		return "", fmt.Errorf("utt not found")
	}
	l := strings.Index(c[k:], "\n};")
	if l < 0 {
		return "", fmt.Errorf("utt unterminated")
	}
	rows := reUTT.FindAllStringSubmatch(c[k:k+l], -1)
	if len(rows) == 0 {
		return "", fmt.Errorf("utt has no rows")
	}
	var b strings.Builder
	fmt.Fprintf(&b, hdr, "pcre2_ucptables.c")
	b.WriteString("// utt_names is the table of lower cased property names, each followed by a\n// NUL (PRIV(utt_names)). utt holds offsets into it.\nconst utt_names = \"\" +\n")
	for n, s := range names {
		q := strconv.Quote(s)
		fmt.Fprintf(&b, "\t%s", q)
		if n < len(names)-1 {
			b.WriteString(" +")
		}
		b.WriteString("\n")
	}
	b.WriteString("\n// utt translates Unicode property names into type and code values; it is\n// searched by binary chop on the names (PRIV(utt)).\nvar utt = []ucpTypeTable{\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "\t{%s, %s, %s},\n", r[1], r[2], r[3])
	}
	b.WriteString("}\n\n// utt_size is the number of entries of utt (PRIV(utt_size)).\nvar utt_size = len(utt)\n")
	out, err := format.Source([]byte(b.String()))
	return string(out), err
}
