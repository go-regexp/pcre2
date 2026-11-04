// Port of pcre2_compile.c lines 1-930: code parameters, macros and static
// tables of the compiler (8-bit code units, LINK_SIZE 2, Unicode support).
//
// The META_* codes, ERR*, PSKIP_* and the other constants that tools/cdefs
// generates live in internal_gen.go; what is defined here is the rest of that
// C range.
package pcre2

// pcre2_compile.c:147-149.
const (
	xREPEAT_UNLIMITED = xMAX_REPEAT_COUNT + 1
)

// pcre2_compile.c:166-200. COMPILE_WORK_SIZE is in code units.
const (
	xCOMPILE_WORK_SIZE                  = 3000 * xLINK_SIZE
	xGROUPINFO_DEFAULT_SIZE             = 256
	xWORK_SIZE_SAFETY_MARGIN            = 100
	xNAMED_GROUP_LIST_SIZE              = 20
	xPARSED_PATTERN_DEFAULT_SIZE        = 1024
	xOFLOW_MAX                          = 0x7fffffff - 20 // INT_MAX - 20
	xSIZEOFFSET                         = 2               // PCRE2_SIZE_MAX > UINT32_MAX
	xESCAPES_FIRST                      = xCHAR_0         // pcre2_compile.c:507
	xESCAPES_LAST                       = xCHAR_z         // pcre2_compile.c:508
	xREQ_UNSET                   uint32 = 0xffffffff      // Not yet found anything
	xREQ_NONE                    uint32 = 0xfffffffe      // Found not fixed character
	xREQ_CASELESS                uint32 = 0x00000001      // Code unit in xxcu is caseless
	xREQ_VARY                    uint32 = 0x00000002      // Code unit is followed by non-literal
	xGI_SET_FIXED_LENGTH         uint32 = 0x80000000      // groupinfo flags
	xGI_NOT_FIXED_LENGTH         uint32 = 0x40000000
	xGI_FIXED_LENGTH_MASK        uint32 = 0x0000ffff
)

// Indices of POSIX classes that are needed specially (pcre2_compile.c:709-713).
const (
	xPC_DIGIT  = 7
	xPC_GRAPH  = 8
	xPC_PRINT  = 9
	xPC_PUNCT  = 10
	xPC_XDIGIT = 13
)

// META_CODE, META_DATA and META_DIFF (pcre2_compile.c:113-115).
func xMETA_CODE(x uint32) uint32    { return x & 0xffff0000 }
func xMETA_DATA(x uint32) uint32    { return x & 0x0000ffff }
func xMETA_DIFF(x, y uint32) uint32 { return (x - y) >> 16 }

// PUTOFFSET stores a PCRE2_SIZE in pp at index p and returns the new index
// (pcre2_compile.c:99).
func xPUTOFFSET(s uint64, pp []uint32, p int) int {
	pp[p] = uint32(s >> 32)
	pp[p+1] = uint32(s & 0xffffffff)
	return p + 2
}

// GETOFFSET reads a PCRE2_SIZE at pp[p] and returns it with the index after
// it (pcre2_compile.c:101).
func xGETOFFSET(pp []uint32, p int) (uint64, int) {
	return uint64(pp[p])<<32 | uint64(pp[p+1]), p + 2
}

// GETPLUSOFFSET reads the PCRE2_SIZE at pp[p+1] and returns it with p+2
// (pcre2_compile.c:103).
func xGETPLUSOFFSET(pp []uint32, p int) (uint64, int) {
	return uint64(pp[p+1])<<32 | uint64(pp[p+2]), p + 2
}

// READPLUSOFFSET reads the PCRE2_SIZE at pp[p+1] (pcre2_compile.c:105).
func xREADPLUSOFFSET(pp []uint32, p int) uint64 {
	return uint64(pp[p+1])<<32 | uint64(pp[p+2])
}

// SKIPOFFSET skips a PCRE2_SIZE (pcre2_compile.c:107).
func xSKIPOFFSET(p int) int { return p + 2 }

// SETBIT sets bit b of the class bitmap a (pcre2_compile.c:386).
func xSETBIT(a []byte, b uint32) { a[b/8] |= byte(1 << (b & 7)) }

// IS_DIGIT is the decimal digit test (pcre2_compile.c:408).
func xIS_DIGIT(x uint32) bool { return x >= xCHAR_0 && x <= xCHAR_9 }

// XDIGIT looks up the private hex digit table (pcre2_compile.c:74); 0xff for
// non-hex digits.
func xXDIGIT(c byte) uint32 { return uint32(xdigitab[c]) }

// meta_extra_lengths (pcre2_compile.c:306): extra parsed-pattern elements for
// each META code, indexed by META_DIFF(code, META_END)... that is code>>16 & 0x7fff.
var meta_extra_lengths = [...]uint8{
	0,               // META_END
	0,               // META_ALT
	0,               // META_ATOMIC
	0,               // META_BACKREF - more if group is >= 10
	1 + xSIZEOFFSET, // META_BACKREF_BYNAME
	1,               // META_BIGVALUE
	3,               // META_CALLOUT_NUMBER
	3 + xSIZEOFFSET, // META_CALLOUT_STRING
	0,               // META_CAPTURE
	0,               // META_CIRCUMFLEX
	0,               // META_CLASS
	0,               // META_CLASS_EMPTY
	0,               // META_CLASS_EMPTY_NOT
	0,               // META_CLASS_END
	0,               // META_CLASS_NOT
	0,               // META_COND_ASSERT
	xSIZEOFFSET,     // META_COND_DEFINE
	1 + xSIZEOFFSET, // META_COND_NAME
	1 + xSIZEOFFSET, // META_COND_NUMBER
	1 + xSIZEOFFSET, // META_COND_RNAME
	1 + xSIZEOFFSET, // META_COND_RNUMBER
	3,               // META_COND_VERSION
	0,               // META_DOLLAR
	0,               // META_DOT
	0,               // META_ESCAPE - more for ESC_P, ESC_p, ESC_g, ESC_k
	0,               // META_KET
	0,               // META_NOCAPTURE
	1,               // META_OPTIONS
	1,               // META_POSIX
	1,               // META_POSIX_NEG
	0,               // META_RANGE_ESCAPED
	0,               // META_RANGE_LITERAL
	xSIZEOFFSET,     // META_RECURSE
	1 + xSIZEOFFSET, // META_RECURSE_BYNAME
	0,               // META_SCRIPT_RUN
	0,               // META_LOOKAHEAD
	0,               // META_LOOKAHEADNOT
	xSIZEOFFSET,     // META_LOOKBEHIND
	xSIZEOFFSET,     // META_LOOKBEHINDNOT
	0,               // META_LOOKAHEAD_NA
	xSIZEOFFSET,     // META_LOOKBEHIND_NA
	1,               // META_MARK - plus the string length
	0,               // META_ACCEPT
	0,               // META_FAIL
	0,               // META_COMMIT
	1,               // META_COMMIT_ARG - plus the string length
	0,               // META_PRUNE
	1,               // META_PRUNE_ARG - plus the string length
	0,               // META_SKIP
	1,               // META_SKIP_ARG - plus the string length
	0,               // META_THEN
	1,               // META_THEN_ARG - plus the string length
	0,               // META_ASTERISK
	0,               // META_ASTERISK_PLUS
	0,               // META_ASTERISK_QUERY
	0,               // META_PLUS
	0,               // META_PLUS_PLUS
	0,               // META_PLUS_QUERY
	0,               // META_QUERY
	0,               // META_QUERY_PLUS
	0,               // META_QUERY_QUERY
	2,               // META_MINMAX
	2,               // META_MINMAX_PLUS
	2,               // META_MINMAX_QUERY
}

// xdigitab identifies hex digits (pcre2_compile.c:422, the ASCII table): the
// binary value, or 0xff for non-hex digits.
var xdigitab = func() (t [256]uint8) {
	for i := range t {
		t[i] = 0xff
	}
	for i := 0; i < 10; i++ {
		t['0'+i] = uint8(i)
	}
	for i := 0; i < 6; i++ {
		t['a'+i] = uint8(10 + i)
		t['A'+i] = uint8(10 + i)
	}
	return
}()

// UPPER_CASE for the ASCII \c handling (pcre2_compile.c:509).
func xUPPER_CASE(c uint32) uint32 { return c - 32 }

// escapes handles alphanumeric escaped characters (pcre2_compile.c:511); it
// runs from '0' to 'z'. Positive values are data, negative are -ESC_x, zero
// means more processing or invalid.
var escapes = [...]int16{
	0, 0,
	0, 0,
	0, 0,
	0, 0,
	0, 0,
	xCHAR_COLON, xCHAR_SEMICOLON,
	xCHAR_LESS_THAN_SIGN, xCHAR_EQUALS_SIGN,
	xCHAR_GREATER_THAN_SIGN, xCHAR_QUESTION_MARK,
	xCHAR_COMMERCIAL_AT, -xESC_A,
	-xESC_B, -xESC_C,
	-xESC_D, -xESC_E,
	0, -xESC_G,
	-xESC_H, 0,
	0, -xESC_K,
	0, 0,
	-xESC_N, 0,
	-xESC_P, -xESC_Q,
	-xESC_R, -xESC_S,
	0, 0,
	-xESC_V, -xESC_W,
	-xESC_X, 0,
	-xESC_Z, xCHAR_LEFT_SQUARE_BRACKET,
	xCHAR_BACKSLASH, xCHAR_RIGHT_SQUARE_BRACKET,
	xCHAR_CIRCUMFLEX_ACCENT, xCHAR_UNDERSCORE,
	xCHAR_GRAVE_ACCENT, xCHAR_BEL,
	-xESC_b, 0,
	-xESC_d, xCHAR_ESC,
	xCHAR_FF, 0,
	-xESC_h, 0,
	0, -xESC_k,
	0, 0,
	xCHAR_LF, 0,
	-xESC_p, 0,
	xCHAR_CR, -xESC_s,
	xCHAR_HT, 0,
	-xESC_v, -xESC_w,
	0, 0,
	-xESC_z,
}

// verbitem (pcre2_compile.c:602).
type verbitem struct {
	len     uint
	meta    uint32 // Base META_ code
	has_arg int    // Argument requirement
}

// verbnames (pcre2_compile.c:608); the names are NUL-separated.
const verbnames = "\x00" + "MARK\x00" + "ACCEPT\x00" + "F\x00" + "FAIL\x00" +
	"COMMIT\x00" + "PRUNE\x00" + "SKIP\x00" + "THEN"

// verbs (pcre2_compile.c:619).
var verbs = [...]verbitem{
	{0, xMETA_MARK, +1}, // > 0 => must have an argument
	{4, xMETA_MARK, +1},
	{6, xMETA_ACCEPT, -1}, // < 0 => Optional argument, convert to pre-MARK
	{1, xMETA_FAIL, -1},
	{4, xMETA_FAIL, -1},
	{6, xMETA_COMMIT, 0},
	{5, xMETA_PRUNE, 0}, // Optional argument; bump META code if found
	{4, xMETA_SKIP, 0},
	{4, xMETA_THEN, 0},
}

// verbcount (pcre2_compile.c:631).
const verbcount = len(verbs)

// verbops are the verb opcodes, indexed by their META code offset from
// META_MARK (pcre2_compile.c:635).
var verbops = [...]uint32{
	xOP_MARK, xOP_ACCEPT, xOP_FAIL, xOP_COMMIT, xOP_COMMIT_ARG, xOP_PRUNE,
	xOP_PRUNE_ARG, xOP_SKIP, xOP_SKIP_ARG, xOP_THEN, xOP_THEN_ARG,
}

// alasitem (pcre2_compile.c:641).
type alasitem struct {
	len  uint
	meta uint32 // Base META_ code
}

// alasnames is the table of "alpha assertion" names (pcre2_compile.c:646).
const alasnames = "pla\x00" + "plb\x00" + "napla\x00" + "naplb\x00" + "nla\x00" +
	"nlb\x00" + "positive_lookahead\x00" + "positive_lookbehind\x00" +
	"non_atomic_positive_lookahead\x00" + "non_atomic_positive_lookbehind\x00" +
	"negative_lookahead\x00" + "negative_lookbehind\x00" + "atomic\x00" +
	"sr\x00" + "asr\x00" + "script_run\x00" + "atomic_script_run"

// alasmeta (pcre2_compile.c:665).
var alasmeta = [...]alasitem{
	{3, xMETA_LOOKAHEAD},
	{3, xMETA_LOOKBEHIND},
	{5, xMETA_LOOKAHEAD_NA},
	{5, xMETA_LOOKBEHIND_NA},
	{3, xMETA_LOOKAHEADNOT},
	{3, xMETA_LOOKBEHINDNOT},
	{18, xMETA_LOOKAHEAD},
	{19, xMETA_LOOKBEHIND},
	{29, xMETA_LOOKAHEAD_NA},
	{30, xMETA_LOOKBEHIND_NA},
	{18, xMETA_LOOKAHEADNOT},
	{19, xMETA_LOOKBEHINDNOT},
	{6, xMETA_ATOMIC},
	{2, xMETA_SCRIPT_RUN},         // sr = script run
	{3, xMETA_ATOMIC_SCRIPT_RUN},  // asr = atomic script run
	{10, xMETA_SCRIPT_RUN},        // script run
	{17, xMETA_ATOMIC_SCRIPT_RUN}, // atomic script run
}

// alascount (pcre2_compile.c:685).
const alascount = len(alasmeta)

// chartypeoffset gives offsets from OP_STAR for case-independent and negative
// repeat opcodes (pcre2_compile.c:689).
var chartypeoffset = [...]uint32{
	xOP_STAR - xOP_STAR, xOP_STARI - xOP_STAR,
	xOP_NOTSTAR - xOP_STAR, xOP_NOTSTARI - xOP_STAR,
}

// posix_names holds the POSIX class names, NUL-separated (pcre2_compile.c:700).
const posix_names = "alpha\x00" + "lower\x00" + "upper\x00" + "alnum\x00" +
	"ascii\x00" + "blank\x00" + "cntrl\x00" + "digit\x00" +
	"graph\x00" + "print\x00" + "punct\x00" + "space\x00" +
	"word\x00" + "xdigit"

// posix_name_lengths ends with a zero entry (pcre2_compile.c:706).
var posix_name_lengths = [...]uint8{5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 4, 6, 0}

// posix_class_maps are triples: base map offset, second map offset or -1, and
// the add/remove/tweak value (pcre2_compile.c:725).
var posix_class_maps = [...]int{
	cbit_word, cbit_digit, -2, // alpha
	cbit_lower, -1, 0, // lower
	cbit_upper, -1, 0, // upper
	cbit_word, -1, 2, // alnum - word without underscore
	cbit_print, cbit_cntrl, 0, // ascii
	cbit_space, -1, 1, // blank - a GNU extension
	cbit_cntrl, -1, 0, // cntrl
	cbit_digit, -1, 0, // digit
	cbit_graph, -1, 0, // graph
	cbit_print, -1, 0, // print
	cbit_punct, -1, 0, // punct
	cbit_space, -1, 0, // space
	cbit_word, -1, 0, // word - a Perl extension
	cbit_xdigit, -1, 0, // xdigit
}

// posix_substitutes are the UCP-mode property substitutes, in the order of
// the POSIX class names (pcre2_compile.c:747).
var posix_substitutes = [...]int{
	xPT_GC, ucp_L, // alpha
	xPT_PC, ucp_Ll, // lower
	xPT_PC, ucp_Lu, // upper
	xPT_ALNUM, 0, // alnum
	-1, 0, // ascii, treat as non-UCP
	-1, 1, // blank, treat as \h
	xPT_PC, ucp_Cc, // cntrl
	xPT_PC, ucp_Nd, // digit
	xPT_PXGRAPH, 0, // graph
	xPT_PXPRINT, 0, // print
	xPT_PXPUNCT, 0, // punct
	xPT_PXSPACE, 0, // space
	xPT_WORD, 0, // word
	xPT_PXXDIGIT, 0, // xdigit
}

// POSIX_SUBSIZE (pcre2_compile.c:763).
const xPOSIX_SUBSIZE = len(posix_substitutes) / 2

// Masks for checking option settings (pcre2_compile.c:769-792).
const (
	xPUBLIC_LITERAL_COMPILE_OPTIONS = PCRE2_ANCHORED | PCRE2_AUTO_CALLOUT | PCRE2_CASELESS |
		PCRE2_ENDANCHORED | PCRE2_FIRSTLINE | PCRE2_LITERAL | PCRE2_MATCH_INVALID_UTF |
		PCRE2_NO_START_OPTIMIZE | PCRE2_NO_UTF_CHECK | PCRE2_USE_OFFSET_LIMIT | PCRE2_UTF

	xPUBLIC_COMPILE_OPTIONS = xPUBLIC_LITERAL_COMPILE_OPTIONS |
		PCRE2_ALLOW_EMPTY_CLASS | PCRE2_ALT_BSUX | PCRE2_ALT_CIRCUMFLEX |
		PCRE2_ALT_VERBNAMES | PCRE2_DOLLAR_ENDONLY | PCRE2_DOTALL | PCRE2_DUPNAMES |
		PCRE2_EXTENDED | PCRE2_EXTENDED_MORE | PCRE2_MATCH_UNSET_BACKREF |
		PCRE2_MULTILINE | PCRE2_NEVER_BACKSLASH_C | PCRE2_NEVER_UCP |
		PCRE2_NEVER_UTF | PCRE2_NO_AUTO_CAPTURE | PCRE2_NO_AUTO_POSSESS |
		PCRE2_NO_DOTSTAR_ANCHOR | PCRE2_UCP | PCRE2_UNGREEDY

	xPUBLIC_LITERAL_COMPILE_EXTRA_OPTIONS = PCRE2_EXTRA_MATCH_LINE | PCRE2_EXTRA_MATCH_WORD |
		PCRE2_EXTRA_CASELESS_RESTRICT

	xPUBLIC_COMPILE_EXTRA_OPTIONS = xPUBLIC_LITERAL_COMPILE_EXTRA_OPTIONS |
		PCRE2_EXTRA_ALLOW_SURROGATE_ESCAPES | PCRE2_EXTRA_BAD_ESCAPE_IS_LITERAL |
		PCRE2_EXTRA_ESCAPED_CR_IS_LF | PCRE2_EXTRA_ALT_BSUX |
		PCRE2_EXTRA_ALLOW_LOOKAROUND_BSK | PCRE2_EXTRA_ASCII_BSD |
		PCRE2_EXTRA_ASCII_BSS | PCRE2_EXTRA_ASCII_BSW | PCRE2_EXTRA_ASCII_POSIX |
		PCRE2_EXTRA_ASCII_DIGIT
)

// PSO_* are the types of start-of-pattern settings (pcre2_compile.c:819).
const (
	xPSO_OPT  = iota // Value is an option bit
	xPSO_FLG         // Value is a flag bit
	xPSO_NL          // Value is a newline type
	xPSO_BSR         // Value is a \R type
	xPSO_LIMH        // Read integer value for heap limit
	xPSO_LIMM        // Read integer value for match limit
	xPSO_LIMD        // Read integer value for depth limit
)

// pso is an entry of the table of start-of-pattern options (pcre2_compile.c:828).
type pso struct {
	name   string
	length uint16
	typ    uint16 // C: type
	value  uint32
}

// pso_list (pcre2_compile.c:837).
var pso_list = [...]pso{
	{"UTF8)", 5, xPSO_OPT, PCRE2_UTF}, // STRING_UTFn_RIGHTPAR contains the length
	{"UTF)", 4, xPSO_OPT, PCRE2_UTF},
	{"UCP)", 4, xPSO_OPT, PCRE2_UCP},
	{"NOTEMPTY)", 9, xPSO_FLG, PCRE2_NOTEMPTY_SET},
	{"NOTEMPTY_ATSTART)", 17, xPSO_FLG, PCRE2_NE_ATST_SET},
	{"NO_AUTO_POSSESS)", 16, xPSO_OPT, PCRE2_NO_AUTO_POSSESS},
	{"NO_DOTSTAR_ANCHOR)", 18, xPSO_OPT, PCRE2_NO_DOTSTAR_ANCHOR},
	{"NO_JIT)", 7, xPSO_FLG, PCRE2_NOJIT},
	{"NO_START_OPT)", 13, xPSO_OPT, PCRE2_NO_START_OPTIMIZE},
	{"LIMIT_HEAP=", 11, xPSO_LIMH, 0},
	{"LIMIT_MATCH=", 12, xPSO_LIMM, 0},
	{"LIMIT_DEPTH=", 12, xPSO_LIMD, 0},
	{"LIMIT_RECURSION=", 16, xPSO_LIMD, 0},
	{"CR)", 3, xPSO_NL, PCRE2_NEWLINE_CR},
	{"LF)", 3, xPSO_NL, PCRE2_NEWLINE_LF},
	{"CRLF)", 5, xPSO_NL, PCRE2_NEWLINE_CRLF},
	{"ANY)", 4, xPSO_NL, PCRE2_NEWLINE_ANY},
	{"NUL)", 4, xPSO_NL, PCRE2_NEWLINE_NUL},
	{"ANYCRLF)", 8, xPSO_NL, PCRE2_NEWLINE_ANYCRLF},
	{"BSR_ANYCRLF)", 12, xPSO_BSR, PCRE2_BSR_ANYCRLF},
	{"BSR_UNICODE)", 12, xPSO_BSR, PCRE2_BSR_UNICODE},
}

// opcode_possessify converts repeating opcodes into their possessified
// versions for explicit possessive quantifiers; zero means none, the item must
// be wrapped in ONCE brackets. Truncated at OP_CALLOUT (pcre2_compile.c:867).
var opcode_possessify = [...]uint8{
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0 - 15
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 16 - 31

	0,              // NOTI
	xOP_POSSTAR, 0, // STAR, MINSTAR
	xOP_POSPLUS, 0, // PLUS, MINPLUS
	xOP_POSQUERY, 0, // QUERY, MINQUERY
	xOP_POSUPTO, 0, // UPTO, MINUPTO
	0,          // EXACT
	0, 0, 0, 0, // POS{STAR,PLUS,QUERY,UPTO}

	xOP_POSSTARI, 0, // STARI, MINSTARI
	xOP_POSPLUSI, 0, // PLUSI, MINPLUSI
	xOP_POSQUERYI, 0, // QUERYI, MINQUERYI
	xOP_POSUPTOI, 0, // UPTOI, MINUPTOI
	0,          // EXACTI
	0, 0, 0, 0, // POS{STARI,PLUSI,QUERYI,UPTOI}

	xOP_NOTPOSSTAR, 0, // NOTSTAR, NOTMINSTAR
	xOP_NOTPOSPLUS, 0, // NOTPLUS, NOTMINPLUS
	xOP_NOTPOSQUERY, 0, // NOTQUERY, NOTMINQUERY
	xOP_NOTPOSUPTO, 0, // NOTUPTO, NOTMINUPTO
	0,          // NOTEXACT
	0, 0, 0, 0, // NOTPOS{STAR,PLUS,QUERY,UPTO}

	xOP_NOTPOSSTARI, 0, // NOTSTARI, NOTMINSTARI
	xOP_NOTPOSPLUSI, 0, // NOTPLUSI, NOTMINPLUSI
	xOP_NOTPOSQUERYI, 0, // NOTQUERYI, NOTMINQUERYI
	xOP_NOTPOSUPTOI, 0, // NOTUPTOI, NOTMINUPTOI
	0,          // NOTEXACTI
	0, 0, 0, 0, // NOTPOS{STARI,PLUSI,QUERYI,UPTOI}

	xOP_TYPEPOSSTAR, 0, // TYPESTAR, TYPEMINSTAR
	xOP_TYPEPOSPLUS, 0, // TYPEPLUS, TYPEMINPLUS
	xOP_TYPEPOSQUERY, 0, // TYPEQUERY, TYPEMINQUERY
	xOP_TYPEPOSUPTO, 0, // TYPEUPTO, TYPEMINUPTO
	0,          // TYPEEXACT
	0, 0, 0, 0, // TYPEPOS{STAR,PLUS,QUERY,UPTO}

	xOP_CRPOSSTAR, 0, // CRSTAR, CRMINSTAR
	xOP_CRPOSPLUS, 0, // CRPLUS, CRMINPLUS
	xOP_CRPOSQUERY, 0, // CRQUERY, CRMINQUERY
	xOP_CRPOSRANGE, 0, // CRRANGE, CRMINRANGE
	0, 0, 0, 0, // CRPOS{STAR,PLUS,QUERY,RANGE}

	0, 0, 0, // CLASS, NCLASS, XCLASS
	0, 0, // REF, REFI
	0, 0, // DNREF, DNREFI
	0, 0, // RECURSE, CALLOUT
}
