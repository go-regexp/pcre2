// Port of the UCD access macros of pcre2_internal.h:1862-1892 (REAL_GET_UCD,
// GET_UCD, UCD_SCRIPTX_PROP ... UCD_BIDICLASS). The tables themselves are in
// ucd_tables.go, generated from pcre2_ucd.c.
package pcre2

// dummy_ucd_record is PRIV(dummy_ucd_record) of pcre2_ucd.c:100-108, the record
// the C 32-bit library returns for code points above MAX_UTF_CODE_POINT. The
// 8-bit C library has no such record and indexes the stage tables out of range
// (undefined behaviour) for such values; they cannot occur there, because
// UTF-8 characters are at most 0x10ffff and non-UTF characters at most 0xff.
// This port returns the 32-bit dummy record rather than panicking, so every
// out of range value is "Unknown script, Cn, other grapheme break, bidi L".
var dummy_ucd_record = ucdRecord{
	script:           ucp_Unknown,
	chartype:         ucp_Cn,
	gbprop:           ucp_gbOther,
	caseset:          0,
	otherCase:        0,
	scriptxBidiclass: 0 | ucp_bidiL<<UCD_BIDICLASS_SHIFT,
	bprops:           0,
}

// REAL_GET_UCD returns the record of ch (pcre2_internal.h:1865). ch must not
// exceed MAX_UTF_CODE_POINT.
func REAL_GET_UCD(ch uint32) *ucdRecord {
	return &ucd_records[ucd_stage2[uint32(ucd_stage1[ch/UCD_BLOCK_SIZE])*UCD_BLOCK_SIZE+ch%UCD_BLOCK_SIZE]]
}

// GET_UCD returns the record of ch (pcre2_internal.h:1869-1874). In 8-bit mode
// the C macro is REAL_GET_UCD; values above MAX_UTF_CODE_POINT, which C does
// not define, get dummy_ucd_record (see there).
func GET_UCD(ch uint32) *ucdRecord {
	if ch > MAX_UTF_CODE_POINT {
		return &dummy_ucd_record
	}
	return REAL_GET_UCD(ch)
}

// UCD_SCRIPTX_PROP is the script extension offset of a record.
func UCD_SCRIPTX_PROP(prop *ucdRecord) uint32 {
	return uint32(prop.scriptxBidiclass) & UCD_SCRIPTX_MASK
}

// UCD_BIDICLASS_PROP is the bidi class of a record.
func UCD_BIDICLASS_PROP(prop *ucdRecord) uint32 {
	return uint32(prop.scriptxBidiclass) >> UCD_BIDICLASS_SHIFT
}

// UCD_BPROPS_PROP is the binary properties offset of a record.
func UCD_BPROPS_PROP(prop *ucdRecord) uint32 {
	return uint32(prop.bprops) & UCD_BPROPS_MASK
}

// UCD_CHARTYPE is the general category (ucp_Lu ...) of ch.
func UCD_CHARTYPE(ch uint32) uint8 { return GET_UCD(ch).chartype }

// UCD_SCRIPT is the script (ucp_Latin ...) of ch.
func UCD_SCRIPT(ch uint32) uint8 { return GET_UCD(ch).script }

// UCD_CATEGORY is the general category group (ucp_L ...) of ch.
func UCD_CATEGORY(ch uint32) uint32 { return ucp_gentype[UCD_CHARTYPE(ch)] }

// UCD_GRAPHBREAK is the grapheme break property of ch.
func UCD_GRAPHBREAK(ch uint32) uint8 { return GET_UCD(ch).gbprop }

// UCD_CASESET is the offset into ucd_caseless_sets of ch's multi-character
// case set, or zero.
func UCD_CASESET(ch uint32) uint8 { return GET_UCD(ch).caseset }

// UCD_OTHERCASE is the other case of ch (ch itself when there is none).
// C: (uint32_t)((int)ch + (int)(GET_UCD(ch)->other_case)).
func UCD_OTHERCASE(ch uint32) uint32 {
	return uint32(int32(ch) + GET_UCD(ch).otherCase)
}

// UCD_SCRIPTX is the script extension offset of ch.
func UCD_SCRIPTX(ch uint32) uint32 { return UCD_SCRIPTX_PROP(GET_UCD(ch)) }

// UCD_BPROPS is the binary properties offset of ch.
func UCD_BPROPS(ch uint32) uint32 { return UCD_BPROPS_PROP(GET_UCD(ch)) }

// UCD_BIDICLASS is the bidi class of ch.
func UCD_BIDICLASS(ch uint32) uint32 { return UCD_BIDICLASS_PROP(GET_UCD(ch)) }
