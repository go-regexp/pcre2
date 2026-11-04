package pcre2

import (
	"strings"
	"testing"
	"unicode"
)

func xTestUCDTableShape(t *testing.T) {
	if unicode_version != "15.0.0" {
		t.Errorf("unicode_version = %q", unicode_version)
	}
	if got, want := len(ucd_stage1), (xMAX_UTF_CODE_POINT+1)/xUCD_BLOCK_SIZE; got != want {
		t.Errorf("len(ucd_stage1) = %d, want %d", got, want)
	}
	if len(ucd_stage2)%xUCD_BLOCK_SIZE != 0 {
		t.Errorf("len(ucd_stage2) = %d is not a multiple of the block size", len(ucd_stage2))
	}
	for i, b := range ucd_stage1 {
		if int(b+1)*xUCD_BLOCK_SIZE > len(ucd_stage2) {
			t.Fatalf("stage1[%d] = %d points outside stage2", i, b)
		}
	}
	for i, r := range ucd_stage2 {
		if int(r) >= len(ucd_records) {
			t.Fatalf("stage2[%d] = %d points outside the records", i, r)
		}
	}
	if len(ucd_script_sets)%ucd_script_sets_item_size != 0 || len(ucd_boolprop_sets)%ucd_boolprop_sets_item_size != 0 {
		t.Error("bitset tables are not whole numbers of items")
	}
	if int(ucd_digit_sets[0]) != len(ucd_digit_sets)-1 {
		t.Errorf("ucd_digit_sets[0] = %d, %d values follow", ucd_digit_sets[0], len(ucd_digit_sets)-1)
	}
	if ucd_caseless_sets[0] != xNOTACHAR || ucd_caseless_sets[len(ucd_caseless_sets)-1] != xNOTACHAR {
		t.Error("ucd_caseless_sets is not NOTACHAR delimited")
	}
	for i, rec := range ucd_records {
		if int(rec.caseset) != 0 && int(rec.caseset) >= len(ucd_caseless_sets) {
			t.Fatalf("record %d: caseset %d out of range", i, rec.caseset)
		}
		if xUCD_SCRIPTX_PROP(&rec)+ucd_script_sets_item_size > uint32(len(ucd_script_sets)) {
			t.Fatalf("record %d: script extension offset out of range", i)
		}
		if xUCD_BPROPS_PROP(&rec)+ucd_boolprop_sets_item_size > uint32(len(ucd_boolprop_sets)) {
			t.Fatalf("record %d: bprops offset out of range", i)
		}
	}
}

func xTestUTT(t *testing.T) {
	if utt_size != len(utt) || utt_size == 0 {
		t.Fatalf("utt_size = %d, len(utt) = %d", utt_size, len(utt))
	}
	if !strings.HasSuffix(utt_names, "\x00") || strings.Count(utt_names, "\x00") != utt_size {
		t.Errorf("utt_names has %d names for %d entries", strings.Count(utt_names, "\x00"), utt_size)
	}
	nameAt := func(off uint16) string {
		s := utt_names[off:]
		return s[:strings.IndexByte(s, 0)]
	}
	prev := ""
	for i, e := range utt {
		if e.nameOffset > 0 && utt_names[e.nameOffset-1] != 0 {
			t.Fatalf("entry %d: offset %d is not the start of a name", i, e.nameOffset)
		}
		n := nameAt(e.nameOffset)
		if n <= prev { // "searched by binary chop, so must be in collating sequence"
			t.Errorf("entry %d: %q after %q", i, n, prev)
		}
		prev = n
	}
	if nameAt(utt[0].nameOffset) != "adlam" || utt[0].typ != xPT_SCX || utt[0].value != ucp_Adlam {
		t.Errorf("first entry: %+v", utt[0])
	}
	if !strings.Contains(utt_names, "l&\x00") {
		t.Error("the name l& is missing")
	}
}

// lookupUTT is the binary chop of the compiler on utt_names.
func lookupUTT(name string) (ucpTypeTable, bool) {
	lo, hi := 0, utt_size
	for lo < hi {
		mid := (lo + hi) / 2
		s := utt_names[utt[mid].nameOffset:]
		n := s[:strings.IndexByte(s, 0)]
		switch {
		case n == name:
			return utt[mid], true
		case n < name:
			lo = mid + 1
		default:
			hi = mid
		}
	}
	return ucpTypeTable{}, false
}

func xTestAccessorsKnownValues(t *testing.T) {
	if got := xUCD_CHARTYPE('A'); got != ucp_Lu {
		t.Errorf("chartype(A) = %d", got)
	}
	if xUCD_CATEGORY('A') != ucp_L || xUCD_SCRIPT('A') != ucp_Latin {
		t.Error("A is not a Latin letter")
	}
	if xUCD_OTHERCASE('A') != 'a' || xUCD_OTHERCASE('a') != 'A' {
		t.Errorf("othercase A/a = %c/%c", xUCD_OTHERCASE('A'), xUCD_OTHERCASE('a'))
	}
	if xUCD_CHARTYPE('a') != ucp_Ll || xUCD_OTHERCASE('1') != '1' {
		t.Error("a or 1")
	}
	if xUCD_CHARTYPE('1') != ucp_Nd || xUCD_CATEGORY('1') != ucp_N {
		t.Error("1")
	}

	// The caseless set of S: s and U+017F.
	set := func(ch uint32) []uint32 {
		off := xUCD_CASESET(ch)
		if off == 0 {
			return nil
		}
		var out []uint32
		for _, v := range ucd_caseless_sets[off:] {
			if v == xNOTACHAR {
				break
			}
			out = append(out, v)
		}
		return out
	}
	eq := func(a []uint32, b ...uint32) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}
	for ch, want := range map[uint32][]uint32{
		'S': {0x53, 0x73, 0x17f}, 's': {0x53, 0x73, 0x17f}, 0x17f: {0x53, 0x73, 0x17f},
		0x3a3: {0x3a3, 0x3c2, 0x3c3}, 0x3c2: {0x3a3, 0x3c2, 0x3c3}, 0x3c3: {0x3a3, 0x3c2, 0x3c3},
		'K': {0x4b, 0x6b, 0x212a}, 0x212a: {0x4b, 0x6b, 0x212a},
	} {
		if got := set(ch); !eq(got, want...) {
			t.Errorf("caseless set of U+%04X = %x, want %x", ch, got, want)
		}
	}
	if set('x') != nil || set(0xdf) != nil {
		t.Error("x and U+00DF have no multi-character caseless set")
	}
	// U+00DF and U+1E9E (capital sharp s) are each other's other case.
	if xUCD_OTHERCASE(0xdf) != 0x1e9e || xUCD_CHARTYPE(0xdf) != ucp_Ll {
		t.Errorf("U+00DF: other case %x", xUCD_OTHERCASE(0xdf))
	}
	if xUCD_OTHERCASE(0x1e9e) != 0xdf {
		t.Errorf("U+1E9E other case = %x", xUCD_OTHERCASE(0x1e9e))
	}

	// U+0660: Arabic-Indic digit zero, Script=Arabic with script extensions.
	if xUCD_CHARTYPE(0x660) != ucp_Nd || xUCD_SCRIPT(0x660) != ucp_Arabic || xUCD_SCRIPTX(0x660) == 0 {
		t.Errorf("U+0660: type %d script %d scx %d", xUCD_CHARTYPE(0x660), xUCD_SCRIPT(0x660), xUCD_SCRIPTX(0x660))
	}
	scx := ucd_script_sets[xUCD_SCRIPTX(0x660):]
	if !xMAPBIT(scx, ucp_Arabic) || !xMAPBIT(scx, ucp_Thaana) || !xMAPBIT(scx, ucp_Yezidi) || xMAPBIT(scx, ucp_Latin) {
		t.Error("script extensions of U+0660")
	}
	if xUCD_BIDICLASS(0x660) != ucp_bidiAN {
		t.Errorf("bidi class of U+0660 = %d", xUCD_BIDICLASS(0x660))
	}

	// U+1F600: Extended_Pictographic grapheme break, Emoji binary property.
	if xUCD_GRAPHBREAK(0x1f600) != ucp_gbExtended_Pictographic || xUCD_CHARTYPE(0x1f600) != ucp_So {
		t.Errorf("U+1F600: gb %d type %d", xUCD_GRAPHBREAK(0x1f600), xUCD_CHARTYPE(0x1f600))
	}
	bp := ucd_boolprop_sets[xUCD_BPROPS(0x1f600):]
	if !xMAPBIT(bp, ucp_Emoji) || !xMAPBIT(bp, ucp_Extended_Pictographic) || xMAPBIT(bp, ucp_Alphabetic) {
		t.Error("binary properties of U+1F600")
	}
	if !xMAPBIT(ucd_boolprop_sets[xUCD_BPROPS('a'):], ucp_Alphabetic) {
		t.Error("a is not Alphabetic")
	}

	if xUCD_SCRIPT(0x4e00) != ucp_Han || xUCD_SCRIPT(0x3b1) != ucp_Greek || xUCD_SCRIPT(0x430) != ucp_Cyrillic {
		t.Error("scripts of U+4E00, U+03B1, U+0430")
	}
	if xUCD_CHARTYPE(0x2028) != ucp_Zl || xUCD_CATEGORY(0x2028) != ucp_Z {
		t.Error("U+2028 is not Zl")
	}
	if xUCD_GRAPHBREAK('\r') != ucp_gbCR || xUCD_GRAPHBREAK('\n') != ucp_gbLF || xUCD_GRAPHBREAK(0x301) != ucp_gbExtend {
		t.Error("grapheme break of CR, LF, U+0301")
	}
}

func xTestGETUCDOutOfRange(t *testing.T) {
	for _, ch := range []uint32{xMAX_UTF_CODE_POINT + 1, 0x7fffffff, xNOTACHAR} {
		r := xGET_UCD(ch)
		if r.script != ucp_Unknown || r.chartype != ucp_Cn || r.gbprop != ucp_gbOther || xUCD_BIDICLASS_PROP(r) != ucp_bidiL {
			t.Errorf("GET_UCD(%#x) = %+v", ch, *r)
		}
	}
	if xGET_UCD(xMAX_UTF_CODE_POINT) == &dummy_ucd_record || xGET_UCD(xMAX_UTF_CODE_POINT) != xREAL_GET_UCD(xMAX_UTF_CODE_POINT) {
		t.Error("U+10FFFF must use the real table")
	}
}

// gcNames maps Go's general category names to PCRE2's ucp_ values.
var gcNames = map[string]uint8{
	"Cc": ucp_Cc, "Cf": ucp_Cf, "Co": ucp_Co, "Cs": ucp_Cs,
	"Ll": ucp_Ll, "Lm": ucp_Lm, "Lo": ucp_Lo, "Lt": ucp_Lt, "Lu": ucp_Lu,
	"Mc": ucp_Mc, "Me": ucp_Me, "Mn": ucp_Mn, "Nd": ucp_Nd, "Nl": ucp_Nl, "No": ucp_No,
	"Pc": ucp_Pc, "Pd": ucp_Pd, "Pe": ucp_Pe, "Pf": ucp_Pf, "Pi": ucp_Pi, "Po": ucp_Po, "Ps": ucp_Ps,
	"Sc": ucp_Sc, "Sk": ucp_Sk, "Sm": ucp_Sm, "So": ucp_So,
	"Zl": ucp_Zl, "Zp": ucp_Zp, "Zs": ucp_Zs,
}

// TestAgainstGoUnicode compares categories, scripts and simple case mappings
// with Go's unicode package. The Unicode versions may differ (PCRE2 10.44 has
// 15.0.0), so differences are counted and reported, not failed, except for a
// gross mismatch.
func xTestAgainstGoUnicode(t *testing.T) {
	type gcTable struct {
		code uint8
		tab  *unicode.RangeTable
	}
	var gcs []gcTable
	for name, code := range gcNames {
		gcs = append(gcs, gcTable{code, unicode.Categories[name]})
	}
	type scTable struct {
		code uint8
		tab  *unicode.RangeTable
		name string
	}
	var scs []scTable
	missing := 0
	for name, tab := range unicode.Scripts {
		e, ok := lookupUTT(strings.ToLower(strings.ReplaceAll(name, "_", "")))
		if !ok || (e.typ != xPT_SC && e.typ != xPT_SCX) {
			// A script newer than Unicode 15.0.0: none of its code points may be
			// assigned in the PCRE2 tables. Counted, not silently skipped.
			missing++
			for _, rg := range tab.R16 {
				for r := rune(rg.Lo); r <= rune(rg.Hi); r++ {
					if xUCD_CHARTYPE(uint32(r)) != ucp_Cn {
						t.Errorf("script %s is unknown to utt but U+%04X is assigned", name, r)
					}
				}
			}
			for _, rg := range tab.R32 {
				for r := rune(rg.Lo); r <= rune(rg.Hi); r++ {
					if xUCD_CHARTYPE(uint32(r)) != ucp_Cn {
						t.Errorf("script %s is unknown to utt but U+%04X is assigned", name, r)
					}
				}
			}
			continue
		}
		scs = append(scs, scTable{uint8(e.value), tab, name})
	}
	var catDiff, scrDiff, caseDiff, assigned, scripted, cased int
	var firstCat, firstScr, firstCase []string
	note := func(l *[]string, s string) {
		if len(*l) < 5 {
			*l = append(*l, s)
		}
	}
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= 0xd800 && r <= 0xdfff {
			if xUCD_CHARTYPE(uint32(r)) != ucp_Cs {
				t.Fatalf("U+%04X is not Cs", r)
			}
			continue
		}
		ch := uint32(r)
		gcode, found := uint8(ucp_Cn), false
		for _, g := range gcs {
			if unicode.Is(g.tab, r) {
				gcode, found = g.code, true
				break
			}
		}
		// Only code points assigned in both versions are compared.
		if found && xUCD_CHARTYPE(ch) != ucp_Cn {
			assigned++
			if xUCD_CHARTYPE(ch) != gcode {
				catDiff++
				note(&firstCat, "U+"+hex4(ch))
			}
		}
		for _, s := range scs {
			if unicode.Is(s.tab, r) && xUCD_SCRIPT(ch) != ucp_Unknown {
				scripted++
				if xUCD_SCRIPT(ch) != s.code {
					scrDiff++
					note(&firstScr, "U+"+hex4(ch)+" "+s.name)
				}
				break
			}
		}
		// Case: only simple, single-character pairs both Go and PCRE2 agree on.
		// The other case must lie in Go's simple fold orbit of the character.
		if o := xUCD_OTHERCASE(ch); o != ch {
			cased++
			inOrbit := false
			for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
				if rune(o) == f {
					inOrbit = true
				}
			}
			if !inOrbit {
				caseDiff++
				note(&firstCase, "U+"+hex4(ch))
			}
		}
	}
	t.Logf("%d Go scripts newer than PCRE2's (all unassigned there)", missing)
	t.Logf("Go unicode %s vs PCRE2 %s: category %d/%d differ %v; script %d/%d differ %v; other case %d/%d differ %v",
		unicode.Version, unicode_version, catDiff, assigned, firstCat, scrDiff, scripted, firstScr, caseDiff, cased, firstCase)
	if catDiff*100 > assigned || scrDiff*100 > scripted || caseDiff*100 > cased {
		t.Errorf("more than 1%% differences: category %d, script %d, case %d", catDiff, scrDiff, caseDiff)
	}
}

func hex4(ch uint32) string {
	const digits = "0123456789ABCDEF"
	s := ""
	for n := 0; n < 4 || ch != 0; n++ {
		s = string(digits[ch&15]) + s
		ch >>= 4
	}
	return s
}
