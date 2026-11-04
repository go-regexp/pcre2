// Port of pcre2_tables.c (fixed tables shared by several modules). The table
// of fixed opcode lengths, PRIV(OP_lengths), is generated into internal_gen.go
// as OP_lengths from the OP_LENGTHS macro; the Unicode tables that
// pcre2_tables.c pulls in with #include "pcre2_ucptables.c" live in
// ucptables.go; the default character tables (pcre2_chartables.c) are built by
// maketables.go.
package pcre2

// Tables of horizontal and vertical whitespace characters, suitable for adding
// to classes. (pcre2_tables.c:66-67; HSPACE_LIST, VSPACE_LIST of
// pcre2_internal.h:407-469, Unicode variant)
var (
	hspace_list = []uint32{
		CHAR_HT, CHAR_SPACE, CHAR_NBSP,
		0x1680, 0x180e, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005,
		0x2006, 0x2007, 0x2008, 0x2009, 0x200A, 0x202f, 0x205f, 0x3000,
		NOTACHAR,
	}
	vspace_list = []uint32{
		CHAR_LF, CHAR_VT, CHAR_FF, CHAR_CR, CHAR_NEL, 0x2028, 0x2029, NOTACHAR,
	}
)

// The pairs of delimiters that are valid for callout string arguments.
// (pcre2_tables.c:73-81)
var (
	callout_start_delims = []uint32{
		CHAR_GRAVE_ACCENT, CHAR_APOSTROPHE, CHAR_QUOTATION_MARK,
		CHAR_CIRCUMFLEX_ACCENT, CHAR_PERCENT_SIGN, CHAR_NUMBER_SIGN,
		CHAR_DOLLAR_SIGN, CHAR_LEFT_CURLY_BRACKET, 0,
	}
	callout_end_delims = []uint32{
		CHAR_GRAVE_ACCENT, CHAR_APOSTROPHE, CHAR_QUOTATION_MARK,
		CHAR_CIRCUMFLEX_ACCENT, CHAR_PERCENT_SIGN, CHAR_NUMBER_SIGN,
		CHAR_DOLLAR_SIGN, CHAR_RIGHT_CURLY_BRACKET, 0,
	}
)

// Tables for UTF-8 support. (pcre2_tables.c:100-118)

// utf8_table1 holds the breakpoints for different numbers of bytes in a UTF-8
// character.
var utf8_table1 = [...]int{0x7f, 0x7ff, 0xffff, 0x1fffff, 0x3ffffff, 0x7fffffff}

// utf8_table1_size is the number of entries of utf8_table1.
const utf8_table1_size = len(utf8_table1)

// utf8_table2 and utf8_table3 are the indicator bits and the mask for the data
// bits to set in the first byte of a character, indexed by the number of
// additional bytes.
var (
	utf8_table2 = [...]int{0, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc}
	utf8_table3 = [...]int{0xff, 0x1f, 0x0f, 0x07, 0x03, 0x01}
)

// utf8_table4 is the number of extra bytes, indexed by the first byte masked
// with 0x3f. The highest number for a valid UTF-8 first byte is in fact 0x3d.
var utf8_table4 = [...]uint8{
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5,
}

// ucp_gentype translates a particular type value (ucp_Cc ...) to the general
// value (ucp_C ...). (pcre2_tables.c:130-139)
var ucp_gentype = [...]uint32{
	ucp_C, ucp_C, ucp_C, ucp_C, ucp_C, // Cc, Cf, Cn, Co, Cs
	ucp_L, ucp_L, ucp_L, ucp_L, ucp_L, // Ll, Lu, Lm, Lo, Lt
	ucp_M, ucp_M, ucp_M, // Mc, Me, Mn
	ucp_N, ucp_N, ucp_N, // Nd, Nl, No
	ucp_P, ucp_P, ucp_P, ucp_P, ucp_P, // Pc, Pd, Pe, Pf, Pi
	ucp_P, ucp_P, // Ps, Po
	ucp_S, ucp_S, ucp_S, ucp_S, // Sc, Sk, Sm, So
	ucp_Z, ucp_Z, ucp_Z, // Zl, Zp, Zs
}

// ESZ of pcre2_tables.c:186.
const gbESZ = 1<<ucp_gbExtend | 1<<ucp_gbSpacingMark | 1<<ucp_gbZWJ

// ucp_gbtable encodes the rules for finding the end of an extended grapheme
// cluster; indexed by the left property, the bit is the right property:
// ucp_gbtable[left] & (1 << right) != 0 means no break. (pcre2_tables.c:188-208)
var ucp_gbtable = [...]uint32{
	1 << ucp_gbLF, //  0 CR
	0,             //  1 LF
	0,             //  2 Control
	gbESZ,         //  3 Extend
	gbESZ | 1<<ucp_gbPrepend | //  4 Prepend
		1<<ucp_gbL | 1<<ucp_gbV | 1<<ucp_gbT |
		1<<ucp_gbLV | 1<<ucp_gbLVT | 1<<ucp_gbOther |
		1<<ucp_gbRegional_Indicator,
	gbESZ, //  5 SpacingMark
	gbESZ | 1<<ucp_gbL | 1<<ucp_gbV | 1<<ucp_gbLV | //  6 L
		1<<ucp_gbLVT,
	gbESZ | 1<<ucp_gbV | 1<<ucp_gbT,        //  7 V
	gbESZ | 1<<ucp_gbT,                     //  8 T
	gbESZ | 1<<ucp_gbV | 1<<ucp_gbT,        //  9 LV
	gbESZ | 1<<ucp_gbT,                     // 10 LVT
	1 << ucp_gbRegional_Indicator,          // 11 Regional Indicator
	gbESZ,                                  // 12 Other
	gbESZ | 1<<ucp_gbExtended_Pictographic, // 13 ZWJ
	gbESZ,                                  // 14 Extended Pictographic
}
