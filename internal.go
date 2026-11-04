// Port of pcre2_internal.h and pcre2_intmodedep.h (PCRE2 10.44, 8-bit code
// units, LINK_SIZE 2, no JIT, Unicode support).
//
// The numeric constants (OP_*, META_*, ERR*, ESC_*, PT_*, XCL_*, PCRE2_MODE8,
// PCRE2_FIRSTSET ..., CHAR_*, cbit_*, ctype_*, lcc_offset ..., NLTYPE_*, the
// config.h limits) are generated into internal_gen.go by tools/cdefs from the
// C text; this file holds what cannot be generated: the byte-layout helpers
// (GET, PUT, GET2, PUT2, the UTF-8 character macros), the hidden structures of
// pcre2_intmodedep.h and the callout blocks of pcre2.h.
//
// Naming rules for every file of the package: C macros and enum members keep
// their C spelling; C functions are Go-cased (PRIV(ord2utf) -> ord2utf); the
// fields of the hidden structures are lowerCamelCase of the C field name
// (max_pattern_length -> maxPatternLength); PCRE2_SIZE is uint64 and a
// PCRE2_SPTR is a []byte plus an int offset.
package pcre2

// PCRE2_SIZE related values (pcre2.h:479-482).
const (
	PCRE2_SIZE_MAX        uint64 = ^uint64(0)
	PCRE2_ZERO_TERMINATED uint64 = ^uint64(0)
	PCRE2_UNSET           uint64 = ^uint64(0)
)

// Values pcre2_internal.h computes with sizeof or limits.h.
const (
	// MAX_NON_UTF_CHAR is 0xffffffffU >> (32 - PCRE2_CODE_UNIT_WIDTH).
	MAX_NON_UTF_CHAR = 0xff
	// LOOKBEHIND_MAX is UINT16_MAX (pcre2_intmodedep.h:618).
	LOOKBEHIND_MAX = 0xffff
	// PCRE2_VERSION_STRING is what pcre2_config(PCRE2_CONFIG_VERSION) gives.
	PCRE2_VERSION_STRING = "10.44 2024-06-07"
	// PCRE2_DATE of pcre2.h.
	PCRE2_DATE = "2024-06-07"
)

// ---------------------------------------------------------------------------
// Link and immediate values (pcre2_intmodedep.h:102-201, LINK_SIZE 2, 8 bit).

// GET reads a LINK_SIZE (2 byte, big endian) value at a[n]. (GET)
func GET(a []byte, n int) int { return int(a[n])<<8 | int(a[n+1]) }

// PUT stores a LINK_SIZE value at a[n]. (PUT)
func PUT(a []byte, n int, d int) { a[n] = byte(d >> 8); a[n+1] = byte(d) }

// GET2 reads an IMM2_SIZE value at a[n]. (GET2)
func GET2(a []byte, n int) int { return int(a[n])<<8 | int(a[n+1]) }

// PUT2 stores an IMM2_SIZE value at a[n]. (PUT2)
func PUT2(a []byte, n int, d int) { a[n] = byte(d >> 8); a[n+1] = byte(d) }

// PUTINC stores a link value at a[n] and returns n+LINK_SIZE. (PUTINC)
func PUTINC(a []byte, n int, d int) int { PUT(a, n, d); return n + LINK_SIZE }

// PUT2INC stores an IMM2 value at a[n] and returns n+IMM2_SIZE. (PUT2INC)
func PUT2INC(a []byte, n int, d int) int { PUT2(a, n, d); return n + IMM2_SIZE }

// ---------------------------------------------------------------------------
// UTF-8 character macros (pcre2_internal.h:272-340, pcre2_intmodedep.h:277-365).
// Every function takes the subject/pattern slice and an index and works on
// well formed UTF-8 (as the C macros do); the *TEST variants take the utf flag.

// MAX_UTF_SINGLE_CU is the largest code point held in a single code unit.
// (the generated constant of the same name is that value in UTF-8 mode)

// HASUTF8EXTRALEN reports whether a first byte needs extra bytes.
func HASUTF8EXTRALEN(c uint32) bool { return c >= 0xc0 }

// HAS_EXTRALEN (8-bit).
func HAS_EXTRALEN(c uint32) bool { return HASUTF8EXTRALEN(c) }

// GET_EXTRALEN is the number of extra bytes of a UTF-8 first byte.
func GET_EXTRALEN(c uint32) int { return int(utf8_table4[c&0x3f]) }

// NOT_FIRSTCU reports whether c is a UTF-8 continuation byte.
func NOT_FIRSTCU(c uint32) bool { return c&0xc0 == 0x80 }

// getUTF8 decodes the remaining bytes of the character whose first byte c is
// at s[i] (GETUTF8: the pointer is not advanced).
func getUTF8(c uint32, s []byte, i int) uint32 {
	switch {
	case c&0x20 == 0:
		return (c&0x1f)<<6 | uint32(s[i+1]&0x3f)
	case c&0x10 == 0:
		return (c&0x0f)<<12 | uint32(s[i+1]&0x3f)<<6 | uint32(s[i+2]&0x3f)
	case c&0x08 == 0:
		return (c&0x07)<<18 | uint32(s[i+1]&0x3f)<<12 | uint32(s[i+2]&0x3f)<<6 | uint32(s[i+3]&0x3f)
	case c&0x04 == 0:
		return (c&0x03)<<24 | uint32(s[i+1]&0x3f)<<18 | uint32(s[i+2]&0x3f)<<12 |
			uint32(s[i+3]&0x3f)<<6 | uint32(s[i+4]&0x3f)
	}
	return (c&0x01)<<30 | uint32(s[i+1]&0x3f)<<24 | uint32(s[i+2]&0x3f)<<18 |
		uint32(s[i+3]&0x3f)<<12 | uint32(s[i+4]&0x3f)<<6 | uint32(s[i+5]&0x3f)
}

// GETCHAR returns the character at s[i] without advancing. (GETCHAR)
func GETCHAR(s []byte, i int) uint32 {
	c := uint32(s[i])
	if c >= 0xc0 {
		c = getUTF8(c, s, i)
	}
	return c
}

// GETCHARTEST is GETCHAR that decodes only when utf is true.
func GETCHARTEST(utf bool, s []byte, i int) uint32 {
	if !utf {
		return uint32(s[i])
	}
	return GETCHAR(s, i)
}

// GETCHARINC returns the character at s[i] and the index after it. (GETCHARINC)
func GETCHARINC(s []byte, i int) (uint32, int) {
	c := uint32(s[i])
	i++
	if c >= 0xc0 {
		n := GET_EXTRALEN(c)
		c = getUTF8(c, s, i-1)
		i += n
	}
	return c, i
}

// GETCHARINCTEST is GETCHARINC that decodes only when utf is true.
func GETCHARINCTEST(utf bool, s []byte, i int) (uint32, int) {
	if !utf {
		return uint32(s[i]), i + 1
	}
	return GETCHARINC(s, i)
}

// GETCHARLEN returns the character at s[i] and its number of extra bytes.
func GETCHARLEN(s []byte, i int) (uint32, int) {
	c := uint32(s[i])
	n := 0
	if c >= 0xc0 {
		n = GET_EXTRALEN(c)
		c = getUTF8(c, s, i)
	}
	return c, n
}

// GETCHARLENTEST is GETCHARLEN that decodes only when utf is true.
func GETCHARLENTEST(utf bool, s []byte, i int) (uint32, int) {
	if !utf {
		return uint32(s[i]), 0
	}
	return GETCHARLEN(s, i)
}

// BACKCHAR moves i back to the first byte of the character. (BACKCHAR)
func BACKCHAR(s []byte, i int) int {
	for s[i]&0xc0 == 0x80 {
		i--
	}
	return i
}

// FORWARDCHAR moves i forward over continuation bytes. (FORWARDCHAR)
func FORWARDCHAR(s []byte, i int) int {
	for s[i]&0xc0 == 0x80 {
		i++
	}
	return i
}

// FORWARDCHARTEST is FORWARDCHAR bounded by end. (FORWARDCHARTEST)
func FORWARDCHARTEST(s []byte, i, end int) int {
	for i < end && s[i]&0xc0 == 0x80 {
		i++
	}
	return i
}

// PUTCHAR writes c at p[0:] (UTF-8 encoded when utf and c > 127) and returns
// the number of bytes written. (PUTCHAR)
func PUTCHAR(utf bool, c uint32, p []byte) int {
	if utf && c > MAX_UTF_SINGLE_CU {
		return int(ord2utf(c, p))
	}
	p[0] = byte(c)
	return 1
}

// MAPBIT and MAPSET test or set bit n of a vector of 32-bit words.
func MAPBIT(m []uint32, n uint32) bool { return m[n/32]&(1<<(n%32)) != 0 }

// MAPSET sets bit n.
func MAPSET(m []uint32, n uint32) { m[n/32] |= 1 << (n % 32) }

// ---------------------------------------------------------------------------
// Unicode character database record (pcre2_internal.h:1852-1891).

// ucdRecord is ucd_record. The tables of ucd_tables.go are arrays of it.
type ucdRecord struct {
	script           uint8  // ucp_Arabic, etc.
	chartype         uint8  // ucp_Cc, etc. (general categories)
	gbprop           uint8  // ucp_gbControl, etc. (grapheme break property)
	caseset          uint8  // offset to multichar other cases or zero
	otherCase        int32  // offset to other case, or zero if none
	scriptxBidiclass uint16 // script extension (11 bit) and bidi class (5 bit) values
	bprops           uint16 // binary properties offset
}

// ucpTypeTable is ucp_type_table (name_offset/type/value of one property name).
type ucpTypeTable struct {
	nameOffset uint16
	typ        uint16
	value      uint16
}

// UCD accessors: see ucd.go (GET_UCD, UCD_CHARTYPE, UCD_SCRIPT, ...).

// ---------------------------------------------------------------------------
// Hidden structures (pcre2_intmodedep.h:551-672). Memory control (memctl) is
// not modelled: Go's allocator is used throughout.

// GeneralContext is pcre2_real_general_context. It carries nothing, because
// the custom allocator hooks of C have no meaning in Go.
type GeneralContext struct{}

// CompileContext is pcre2_real_compile_context.
type CompileContext struct {
	stackGuard               func(depth uint32, data any) int
	stackGuardData           any
	tables                   []byte // nil means the default tables
	maxPatternLength         uint64
	maxPatternCompiledLength uint64
	bsrConvention            uint16
	newlineConvention        uint16
	parensNestLimit          uint32
	extraOptions             uint32
	maxVarlookbehind         uint32
}

// MatchContext is pcre2_real_match_context.
type MatchContext struct {
	jitCallback           func(data any) *JITStack
	jitCallbackData       any
	callout               func(cb *CalloutBlock, data any) int
	calloutData           any
	substituteCallout     func(cb *SubstituteCalloutBlock, data any) int
	substituteCalloutData any
	offsetLimit           uint64
	heapLimit             uint32
	matchLimit            uint32
	depthLimit            uint32
}

// ConvertContext is pcre2_real_convert_context.
type ConvertContext struct {
	globSeparator uint32
	globEscape    uint32
}

// JITStack is pcre2_real_jit_stack. This build has no JIT, so it only records
// the sizes it was created with.
type JITStack struct {
	start, max uint64
}

// Code is pcre2_real_code. The compiled pattern keeps PCRE2's real byte
// layout: after the header comes the name table (nameCount entries of
// nameEntrySize bytes, each a 2-byte group number then the NUL-terminated
// name) and immediately after it the compiled opcodes, exactly as the C block
// lays them out after the structure. They are kept in one slice, code:
//
//	code[0 : nameCount*nameEntrySize]   name table  (C: name_table)
//	code[nameCount*nameEntrySize : ]    opcodes     (C: start of code)
//
// Links (GET/PUT) are 2 bytes, big endian, relative as in C.
type Code struct {
	tables         []byte // nil: default tables (no PCRE2_DEREF_TABLES in Go)
	executableJIT  any    // always nil in this build
	startBitmap    [32]uint8
	blocksize      uint64 // size in bytes of the C block (header + code)
	magicNumber    uint32
	compileOptions uint32
	overallOptions uint32
	extraOptions   uint32
	flags          uint32
	limitHeap      uint32
	limitMatch     uint32
	limitDepth     uint32
	firstCodeunit  uint32
	lastCodeunit   uint32

	bsrConvention     uint16
	newlineConvention uint16
	maxLookbehind     uint16
	minlength         uint16
	topBracket        uint16
	topBackref        uint16
	nameEntrySize     uint16
	nameCount         uint16

	code []byte // name table followed by the opcodes
}

// pcre2RealCodeSize is sizeof(pcre2_real_code) on a 64-bit target with the
// memctl member (3 pointers), as built by the oracle. It is used to compute
// PCRE2_INFO_SIZE the way C does (blocksize).
// 24 (memctl) + 8 (tables) + 8 (jit) + 32 (bitmap) + 8 (blocksize) +
// 10*4 (uint32 fields) + 8*2 (uint16 fields) = 136.
const pcre2RealCodeSize = 136

// nameTable returns the name table bytes (C: re + sizeof(pcre2_real_code)).
func (re *Code) nameTable() []byte {
	return re.code[:int(re.nameCount)*int(re.nameEntrySize)]
}

// startCode returns the opcodes: the slice starting at the first opcode, which
// follows the name table (C: re + sizeof(pcre2_real_code) +
// name_count*name_entry_size). Offsets inside compiled code are relative to it.
func (re *Code) startCode() []byte {
	return re.code[int(re.nameCount)*int(re.nameEntrySize):]
}

// charTables returns the active tables (the default ones when none was set).
func (re *Code) charTables() []byte {
	if re.tables == nil {
		return default_tables[:]
	}
	return re.tables
}

// MatchData is pcre2_real_match_data. The subject is referenced, not copied,
// as in C (unless PCRE2_COPY_MATCHED_SUBJECT sets PCRE2_MD_COPIED_SUBJECT, in
// which case the match code stores a private copy in subject).
type MatchData struct {
	code          *Code
	subject       []byte
	mark          []byte // nil: no mark. Slice of the pattern's code or subject
	heapframes    any    // backtracking frames memory, owned by the matcher
	heapframesSz  uint64
	subjectLength uint64
	leftchar      uint64
	rightchar     uint64
	startchar     uint64
	matchedby     uint8
	flags         uint32 // PCRE2_MD_*
	oveccount     uint16
	rc            int
	ovector       []uint64 // 2*oveccount entries

	calloutBlock *CalloutBlock // reused by every match (pcre2_match.c:6950)
}

// CalloutBlock is pcre2_callout_block (versions 0, 1 and 2).
type CalloutBlock struct {
	Version             uint32
	CalloutNumber       uint32
	CaptureTop          uint32
	CaptureLast         uint32
	OffsetVector        []uint64
	Mark                []byte
	Subject             []byte
	SubjectLength       uint64
	StartMatch          uint64
	CurrentPosition     uint64
	PatternPosition     uint64
	NextItemLength      uint64
	CalloutStringOffset uint64
	CalloutStringLength uint64
	CalloutString       []byte
	CalloutFlags        uint32
}

// CalloutEnumerateBlock is pcre2_callout_enumerate_block.
type CalloutEnumerateBlock struct {
	Version             uint32
	PatternPosition     uint64
	NextItemLength      uint64
	CalloutNumber       uint32
	CalloutStringOffset uint64
	CalloutStringLength uint64
	CalloutString       []byte
}

// SubstituteCalloutBlock is pcre2_substitute_callout_block.
type SubstituteCalloutBlock struct {
	Version       uint32
	Input         []byte
	Output        []byte
	OutputOffsets [2]uint64
	Ovector       []uint64
	Oveccount     uint32
	Subscount     uint32
}

// open_capitem and recurse_check style private structures belong to the files
// that use them (compile.go, match.go).
