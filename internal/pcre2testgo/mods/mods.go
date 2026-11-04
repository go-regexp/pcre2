// Package mods is a Go port of the modifier tables and the modifier decoder of
// pcre2test.c (PCRE2 10.44): modlist, c1modlist, check_modifier() and
// decode_modifiers(). It has no dependency on the pcre2 library; the numeric
// values of options, controls and error numbers are those of pcre2.h and
// pcre2test.c.
package mods

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// Compile and match options (pcre2.h).
const (
	ANCHORED                = 0x80000000
	NO_UTF_CHECK            = 0x40000000
	ENDANCHORED             = 0x20000000
	ALLOW_EMPTY_CLASS       = 0x00000001
	ALT_BSUX                = 0x00000002
	AUTO_CALLOUT            = 0x00000004
	CASELESS                = 0x00000008
	DOLLAR_ENDONLY          = 0x00000010
	DOTALL                  = 0x00000020
	DUPNAMES                = 0x00000040
	EXTENDED                = 0x00000080
	FIRSTLINE               = 0x00000100
	MATCH_UNSET_BACKREF     = 0x00000200
	MULTILINE               = 0x00000400
	NEVER_UCP               = 0x00000800
	NEVER_UTF               = 0x00001000
	NO_AUTO_CAPTURE         = 0x00002000
	NO_AUTO_POSSESS         = 0x00004000
	NO_DOTSTAR_ANCHOR       = 0x00008000
	NO_START_OPTIMIZE       = 0x00010000
	UCP                     = 0x00020000
	UNGREEDY                = 0x00040000
	UTF                     = 0x00080000
	NEVER_BACKSLASH_C       = 0x00100000
	ALT_CIRCUMFLEX          = 0x00200000
	ALT_VERBNAMES           = 0x00400000
	USE_OFFSET_LIMIT        = 0x00800000
	EXTENDED_MORE           = 0x01000000
	LITERAL                 = 0x02000000
	MATCH_INVALID_UTF       = 0x04000000
	NOTBOL                  = 0x00000001
	NOTEOL                  = 0x00000002
	NOTEMPTY                = 0x00000004
	NOTEMPTY_ATSTART        = 0x00000008
	PARTIAL_SOFT            = 0x00000010
	PARTIAL_HARD            = 0x00000020
	DFA_RESTART             = 0x00000040
	DFA_SHORTEST            = 0x00000080
	NO_JIT                  = 0x00002000
	COPY_MATCHED_SUBJECT    = 0x00004000
	DISABLE_RECURSELOOP_CHK = 0x00040000

	EXTRA_ALLOW_SURROGATE_ESCAPES = 0x00000001
	EXTRA_BAD_ESCAPE_IS_LITERAL   = 0x00000002
	EXTRA_MATCH_WORD              = 0x00000004
	EXTRA_MATCH_LINE              = 0x00000008
	EXTRA_ESCAPED_CR_IS_LF        = 0x00000010
	EXTRA_ALT_BSUX                = 0x00000020
	EXTRA_ALLOW_LOOKAROUND_BSK    = 0x00000040
	EXTRA_CASELESS_RESTRICT       = 0x00000080
	EXTRA_ASCII_BSD               = 0x00000100
	EXTRA_ASCII_BSS               = 0x00000200
	EXTRA_ASCII_BSW               = 0x00000400
	EXTRA_ASCII_POSIX             = 0x00000800
	EXTRA_ASCII_DIGIT             = 0x00001000
	EXTRA_ASCII_ALL               = EXTRA_ASCII_BSD | EXTRA_ASCII_BSS | EXTRA_ASCII_BSW | EXTRA_ASCII_POSIX

	CONVERT_UTF                    = 0x00000001
	CONVERT_NO_UTF_CHECK           = 0x00000002
	CONVERT_POSIX_BASIC            = 0x00000004
	CONVERT_POSIX_EXTENDED         = 0x00000008
	CONVERT_GLOB                   = 0x00000010
	CONVERT_GLOB_NO_WILD_SEPARATOR = 0x00000030
	CONVERT_GLOB_NO_STARSTAR       = 0x00000050
	// ConvertUnset is CONVERT_UNSET of pcre2test.c.
	ConvertUnset = 0xffffffff

	NEWLINE_CR      = 1
	NEWLINE_LF      = 2
	NEWLINE_CRLF    = 3
	NEWLINE_ANY     = 4
	NEWLINE_ANYCRLF = 5
	NEWLINE_NUL     = 6
	BSR_UNICODE     = 1
	BSR_ANYCRLF     = 2
)

// Control bits (first word), from pcre2test.c.
const (
	CTL_AFTERTEXT         = 0x00000001
	CTL_ALLAFTERTEXT      = 0x00000002
	CTL_ALLCAPTURES       = 0x00000004
	CTL_ALLUSEDTEXT       = 0x00000008
	CTL_ALTGLOBAL         = 0x00000010
	CTL_BINCODE           = 0x00000020
	CTL_CALLOUT_CAPTURE   = 0x00000040
	CTL_CALLOUT_INFO      = 0x00000080
	CTL_CALLOUT_NONE      = 0x00000100
	CTL_DFA               = 0x00000200
	CTL_EXPAND            = 0x00000400
	CTL_FINDLIMITS        = 0x00000800
	CTL_FINDLIMITS_NOHEAP = 0x00001000
	CTL_FULLBINCODE       = 0x00002000
	CTL_GETALL            = 0x00004000
	CTL_GLOBAL            = 0x00008000
	CTL_HEXPAT            = 0x00010000
	CTL_INFO              = 0x00020000
	CTL_JITFAST           = 0x00040000
	CTL_JITVERIFY         = 0x00080000
	CTL_MARK              = 0x00100000
	CTL_MEMORY            = 0x00200000
	CTL_NULLCONTEXT       = 0x00400000
	CTL_POSIX             = 0x00800000
	CTL_POSIX_NOSUB       = 0x01000000
	CTL_PUSH              = 0x02000000
	CTL_PUSHCOPY          = 0x04000000
	CTL_PUSHTABLESCOPY    = 0x08000000
	CTL_STARTCHAR         = 0x10000000
	CTL_USE_LENGTH        = 0x20000000
	CTL_UTF8_INPUT        = 0x40000000
	CTL_ZERO_TERMINATE    = 0x80000000

	CTL_DEBUG   = CTL_FULLBINCODE | CTL_INFO
	CTL_ANYINFO = CTL_DEBUG | CTL_BINCODE | CTL_CALLOUT_INFO
	CTL_ANYGLOB = CTL_ALTGLOBAL | CTL_GLOBAL

	CTL2_SUBSTITUTE_CALLOUT          = 0x00000001
	CTL2_SUBSTITUTE_EXTENDED         = 0x00000002
	CTL2_SUBSTITUTE_LITERAL          = 0x00000004
	CTL2_SUBSTITUTE_MATCHED          = 0x00000008
	CTL2_SUBSTITUTE_OVERFLOW_LENGTH  = 0x00000010
	CTL2_SUBSTITUTE_REPLACEMENT_ONLY = 0x00000020
	CTL2_SUBSTITUTE_UNKNOWN_UNSET    = 0x00000040
	CTL2_SUBSTITUTE_UNSET_EMPTY      = 0x00000080
	CTL2_SUBJECT_LITERAL             = 0x00000100
	CTL2_CALLOUT_NO_WHERE            = 0x00000200
	CTL2_CALLOUT_EXTRA               = 0x00000400
	CTL2_ALLVECTOR                   = 0x00000800
	CTL2_NULL_PATTERN                = 0x00001000
	CTL2_NULL_SUBJECT                = 0x00002000
	CTL2_NULL_REPLACEMENT            = 0x00004000
	CTL2_FRAMESIZE                   = 0x00008000
	CTL2_HEAPFRAMES_SIZE             = 0x20000000
	CTL2_NL_SET                      = 0x40000000
	CTL2_BSR_SET                     = 0x80000000

	// CTL_ALLPD are the controls copied from a pattern to its data lines.
	CTL_ALLPD = CTL_AFTERTEXT | CTL_ALLAFTERTEXT | CTL_ALLCAPTURES | CTL_ALLUSEDTEXT |
		CTL_ALTGLOBAL | CTL_GLOBAL | CTL_MARK | CTL_STARTCHAR | CTL_UTF8_INPUT
	CTL2_ALLPD = CTL2_SUBSTITUTE_CALLOUT | CTL2_SUBSTITUTE_EXTENDED | CTL2_SUBSTITUTE_LITERAL |
		CTL2_SUBSTITUTE_MATCHED | CTL2_SUBSTITUTE_OVERFLOW_LENGTH | CTL2_SUBSTITUTE_REPLACEMENT_ONLY |
		CTL2_SUBSTITUTE_UNKNOWN_UNSET | CTL2_SUBSTITUTE_UNSET_EMPTY | CTL2_ALLVECTOR | CTL2_HEAPFRAMES_SIZE
)

// Unset is PCRE2_UNSET for 64-bit PCRE2_SIZE.
const Unset = ^uint64(0)

// CforeUnset is CFORE_UNSET of pcre2test.c (data callout fields).
const CforeUnset = 0xffffffff

// DefaultOveccount is DEFAULT_OVECCOUNT: the ovector size used for data lines
// unless "ovector=n" says otherwise (ovector=0 means "exactly as many as the
// pattern needs").
const DefaultOveccount = 15

// Limits of the copy/get fields.
const (
	MaxCpyGet  = 10
	LenCpyGet  = 64
	MaxNameLen = 32 // MAX_NAME_SIZE
	LocaleSize = 32
	// ReplaceModSize is REPLACE_MODSIZE.
	ReplaceModSize = 100
)

// Which says where a modifier applies.
type Which int

// Modifier applicability.
const (
	CTC Which = iota
	CTM
	PAT
	PATP
	DAT
	DATP
	PD
	PDP
	PND
	PNDP
)

// Type is the type of a modifier's value.
type Type int

// Modifier value types.
const (
	TCHR Type = iota
	TCON
	TCTL
	TBSR
	TIN2
	TINS
	TINT
	TIND
	TNL
	TNN
	TOPT
	TSIZ
	TSTR
)

// Field identifies the storage a modifier writes.
type Field int

// Fields.
const (
	// Common to pattern and data blocks.
	FOptions Field = iota
	FControl
	FControl2
	FJitstack
	FReplacement
	FSubstSkip
	FSubstStop
	// Pattern block only.
	FJit
	FStackguard
	FTables
	FConvertType
	FConvertLength
	FGlobEscape
	FGlobSeparator
	FRegerrorBuffsize
	FLocale
	// Data block only.
	FStartend
	FCerror
	FCfail
	FCalloutData
	FCopy
	FGet
	FOveccount
	FOffset
	// Compile context.
	FCExtra
	FCNewline
	FCBSR
	FCParensNest
	FCMaxPatLen
	FCMaxPatCompLen
	FCMaxVarLookbehind
	// Match context.
	FMMatchLimit
	FMDepthLimit
	FMHeapLimit
	FMOffsetLimit
)

// Mod is an entry of modlist.
type Mod struct {
	Name  string
	Which Which
	Type  Type
	Value uint32
	Field Field
}

// List is modlist of pcre2test.c; sorted by name (binary chop).
var List = []Mod{
	{"aftertext", PNDP, TCTL, CTL_AFTERTEXT, FControl},
	{"allaftertext", PNDP, TCTL, CTL_ALLAFTERTEXT, FControl},
	{"allcaptures", PND, TCTL, CTL_ALLCAPTURES, FControl},
	{"allow_empty_class", PAT, TOPT, ALLOW_EMPTY_CLASS, FOptions},
	{"allow_lookaround_bsk", CTC, TOPT, EXTRA_ALLOW_LOOKAROUND_BSK, FCExtra},
	{"allow_surrogate_escapes", CTC, TOPT, EXTRA_ALLOW_SURROGATE_ESCAPES, FCExtra},
	{"allusedtext", PNDP, TCTL, CTL_ALLUSEDTEXT, FControl},
	{"allvector", PND, TCTL, CTL2_ALLVECTOR, FControl2},
	{"alt_bsux", PAT, TOPT, ALT_BSUX, FOptions},
	{"alt_circumflex", PAT, TOPT, ALT_CIRCUMFLEX, FOptions},
	{"alt_verbnames", PAT, TOPT, ALT_VERBNAMES, FOptions},
	{"altglobal", PND, TCTL, CTL_ALTGLOBAL, FControl},
	{"anchored", PD, TOPT, ANCHORED, FOptions},
	{"ascii_all", CTC, TOPT, EXTRA_ASCII_ALL, FCExtra},
	{"ascii_bsd", CTC, TOPT, EXTRA_ASCII_BSD, FCExtra},
	{"ascii_bss", CTC, TOPT, EXTRA_ASCII_BSS, FCExtra},
	{"ascii_bsw", CTC, TOPT, EXTRA_ASCII_BSW, FCExtra},
	{"ascii_digit", CTC, TOPT, EXTRA_ASCII_DIGIT, FCExtra},
	{"ascii_posix", CTC, TOPT, EXTRA_ASCII_POSIX, FCExtra},
	{"auto_callout", PAT, TOPT, AUTO_CALLOUT, FOptions},
	{"bad_escape_is_literal", CTC, TOPT, EXTRA_BAD_ESCAPE_IS_LITERAL, FCExtra},
	{"bincode", PAT, TCTL, CTL_BINCODE, FControl},
	{"bsr", CTC, TBSR, 0, FCBSR},
	{"callout_capture", DAT, TCTL, CTL_CALLOUT_CAPTURE, FControl},
	{"callout_data", DAT, TINS, 0, FCalloutData},
	{"callout_error", DAT, TIN2, 0, FCerror},
	{"callout_extra", DAT, TCTL, CTL2_CALLOUT_EXTRA, FControl2},
	{"callout_fail", DAT, TIN2, 0, FCfail},
	{"callout_info", PAT, TCTL, CTL_CALLOUT_INFO, FControl},
	{"callout_no_where", DAT, TCTL, CTL2_CALLOUT_NO_WHERE, FControl2},
	{"callout_none", DAT, TCTL, CTL_CALLOUT_NONE, FControl},
	{"caseless", PATP, TOPT, CASELESS, FOptions},
	{"caseless_restrict", CTC, TOPT, EXTRA_CASELESS_RESTRICT, FCExtra},
	{"convert", PAT, TCON, 0, FConvertType},
	{"convert_glob_escape", PAT, TCHR, 0, FGlobEscape},
	{"convert_glob_separator", PAT, TCHR, 0, FGlobSeparator},
	{"convert_length", PAT, TINT, 0, FConvertLength},
	{"copy", DAT, TNN, 0, FCopy},
	{"copy_matched_subject", DAT, TOPT, COPY_MATCHED_SUBJECT, FOptions},
	{"debug", PAT, TCTL, CTL_DEBUG, FControl},
	{"depth_limit", CTM, TINT, 0, FMDepthLimit},
	{"dfa", DAT, TCTL, CTL_DFA, FControl},
	{"dfa_restart", DAT, TOPT, DFA_RESTART, FOptions},
	{"dfa_shortest", DAT, TOPT, DFA_SHORTEST, FOptions},
	{"disable_recurseloop_check", DAT, TOPT, DISABLE_RECURSELOOP_CHK, FOptions},
	{"dollar_endonly", PAT, TOPT, DOLLAR_ENDONLY, FOptions},
	{"dotall", PATP, TOPT, DOTALL, FOptions},
	{"dupnames", PATP, TOPT, DUPNAMES, FOptions},
	{"endanchored", PD, TOPT, ENDANCHORED, FOptions},
	{"escaped_cr_is_lf", CTC, TOPT, EXTRA_ESCAPED_CR_IS_LF, FCExtra},
	{"expand", PAT, TCTL, CTL_EXPAND, FControl},
	{"extended", PATP, TOPT, EXTENDED, FOptions},
	{"extended_more", PATP, TOPT, EXTENDED_MORE, FOptions},
	{"extra_alt_bsux", CTC, TOPT, EXTRA_ALT_BSUX, FCExtra},
	{"find_limits", DAT, TCTL, CTL_FINDLIMITS, FControl},
	{"find_limits_noheap", DAT, TCTL, CTL_FINDLIMITS_NOHEAP, FControl},
	{"firstline", PAT, TOPT, FIRSTLINE, FOptions},
	{"framesize", PAT, TCTL, CTL2_FRAMESIZE, FControl2},
	{"fullbincode", PAT, TCTL, CTL_FULLBINCODE, FControl},
	{"get", DAT, TNN, 0, FGet},
	{"getall", DAT, TCTL, CTL_GETALL, FControl},
	{"global", PNDP, TCTL, CTL_GLOBAL, FControl},
	{"heap_limit", CTM, TINT, 0, FMHeapLimit},
	{"heapframes_size", PND, TCTL, CTL2_HEAPFRAMES_SIZE, FControl2},
	{"hex", PAT, TCTL, CTL_HEXPAT, FControl},
	{"info", PAT, TCTL, CTL_INFO, FControl},
	{"jit", PAT, TIND, 7, FJit},
	{"jitfast", PAT, TCTL, CTL_JITFAST, FControl},
	{"jitstack", PNDP, TINT, 0, FJitstack},
	{"jitverify", PAT, TCTL, CTL_JITVERIFY, FControl},
	{"literal", PAT, TOPT, LITERAL, FOptions},
	{"locale", PAT, TSTR, LocaleSize, FLocale},
	{"mark", PNDP, TCTL, CTL_MARK, FControl},
	{"match_invalid_utf", PAT, TOPT, MATCH_INVALID_UTF, FOptions},
	{"match_limit", CTM, TINT, 0, FMMatchLimit},
	{"match_line", CTC, TOPT, EXTRA_MATCH_LINE, FCExtra},
	{"match_unset_backref", PAT, TOPT, MATCH_UNSET_BACKREF, FOptions},
	{"match_word", CTC, TOPT, EXTRA_MATCH_WORD, FCExtra},
	{"max_pattern_compiled_length", CTC, TSIZ, 0, FCMaxPatCompLen},
	{"max_pattern_length", CTC, TSIZ, 0, FCMaxPatLen},
	{"max_varlookbehind", CTC, TINT, 0, FCMaxVarLookbehind},
	{"memory", PD, TCTL, CTL_MEMORY, FControl},
	{"multiline", PATP, TOPT, MULTILINE, FOptions},
	{"never_backslash_c", PAT, TOPT, NEVER_BACKSLASH_C, FOptions},
	{"never_ucp", PAT, TOPT, NEVER_UCP, FOptions},
	{"never_utf", PAT, TOPT, NEVER_UTF, FOptions},
	{"newline", CTC, TNL, 0, FCNewline},
	{"no_auto_capture", PAT, TOPT, NO_AUTO_CAPTURE, FOptions},
	{"no_auto_possess", PATP, TOPT, NO_AUTO_POSSESS, FOptions},
	{"no_dotstar_anchor", PAT, TOPT, NO_DOTSTAR_ANCHOR, FOptions},
	{"no_jit", DATP, TOPT, NO_JIT, FOptions},
	{"no_start_optimize", PATP, TOPT, NO_START_OPTIMIZE, FOptions},
	{"no_utf_check", PD, TOPT, NO_UTF_CHECK, FOptions},
	{"notbol", DAT, TOPT, NOTBOL, FOptions},
	{"notempty", DAT, TOPT, NOTEMPTY, FOptions},
	{"notempty_atstart", DAT, TOPT, NOTEMPTY_ATSTART, FOptions},
	{"noteol", DAT, TOPT, NOTEOL, FOptions},
	{"null_context", PD, TCTL, CTL_NULLCONTEXT, FControl},
	{"null_pattern", PAT, TCTL, CTL2_NULL_PATTERN, FControl2},
	{"null_replacement", DAT, TCTL, CTL2_NULL_REPLACEMENT, FControl2},
	{"null_subject", DAT, TCTL, CTL2_NULL_SUBJECT, FControl2},
	{"offset", DAT, TINT, 0, FOffset},
	{"offset_limit", CTM, TSIZ, 0, FMOffsetLimit},
	{"ovector", DAT, TINT, 0, FOveccount},
	{"parens_nest_limit", CTC, TINT, 0, FCParensNest},
	{"partial_hard", DAT, TOPT, PARTIAL_HARD, FOptions},
	{"partial_soft", DAT, TOPT, PARTIAL_SOFT, FOptions},
	{"ph", DAT, TOPT, PARTIAL_HARD, FOptions},
	{"posix", PAT, TCTL, CTL_POSIX, FControl},
	{"posix_nosub", PAT, TCTL, CTL_POSIX | CTL_POSIX_NOSUB, FControl},
	{"posix_startend", DAT, TIN2, 0, FStartend},
	{"ps", DAT, TOPT, PARTIAL_SOFT, FOptions},
	{"push", PAT, TCTL, CTL_PUSH, FControl},
	{"pushcopy", PAT, TCTL, CTL_PUSHCOPY, FControl},
	{"pushtablescopy", PAT, TCTL, CTL_PUSHTABLESCOPY, FControl},
	{"recursion_limit", CTM, TINT, 0, FMDepthLimit},
	{"regerror_buffsize", PAT, TINT, 0, FRegerrorBuffsize},
	{"replace", PND, TSTR, ReplaceModSize, FReplacement},
	{"stackguard", PAT, TINT, 0, FStackguard},
	{"startchar", PND, TCTL, CTL_STARTCHAR, FControl},
	{"startoffset", DAT, TINT, 0, FOffset},
	{"subject_literal", PATP, TCTL, CTL2_SUBJECT_LITERAL, FControl2},
	{"substitute_callout", PND, TCTL, CTL2_SUBSTITUTE_CALLOUT, FControl2},
	{"substitute_extended", PND, TCTL, CTL2_SUBSTITUTE_EXTENDED, FControl2},
	{"substitute_literal", PND, TCTL, CTL2_SUBSTITUTE_LITERAL, FControl2},
	{"substitute_matched", PND, TCTL, CTL2_SUBSTITUTE_MATCHED, FControl2},
	{"substitute_overflow_length", PND, TCTL, CTL2_SUBSTITUTE_OVERFLOW_LENGTH, FControl2},
	{"substitute_replacement_only", PND, TCTL, CTL2_SUBSTITUTE_REPLACEMENT_ONLY, FControl2},
	{"substitute_skip", PND, TINT, 0, FSubstSkip},
	{"substitute_stop", PND, TINT, 0, FSubstStop},
	{"substitute_unknown_unset", PND, TCTL, CTL2_SUBSTITUTE_UNKNOWN_UNSET, FControl2},
	{"substitute_unset_empty", PND, TCTL, CTL2_SUBSTITUTE_UNSET_EMPTY, FControl2},
	{"tables", PAT, TINT, 0, FTables},
	{"ucp", PATP, TOPT, UCP, FOptions},
	{"ungreedy", PAT, TOPT, UNGREEDY, FOptions},
	{"use_length", PAT, TCTL, CTL_USE_LENGTH, FControl},
	{"use_offset_limit", PAT, TOPT, USE_OFFSET_LIMIT, FOptions},
	{"utf", PATP, TOPT, UTF, FOptions},
	{"utf8_input", PAT, TCTL, CTL_UTF8_INPUT, FControl},
	{"zero_terminate", DAT, TCTL, CTL_ZERO_TERMINATE, FControl},
}

// c1mod is an entry of c1modlist.
var c1mod = []struct {
	full string
	c    byte
}{
	{"bincode", 'B'}, {"info", 'I'}, {"ascii_all", 'a'}, {"global", 'g'},
	{"caseless", 'i'}, {"multiline", 'm'}, {"no_auto_capture", 'n'},
	{"caseless_restrict", 'r'}, {"dotall", 's'}, {"extended", 'x'},
}

// Lookup finds a long modifier name; the second result is false if unknown.
func Lookup(name string) (*Mod, bool) {
	i := sort.Search(len(List), func(i int) bool { return List[i].Name >= name })
	if i < len(List) && List[i].Name == name {
		return &List[i], true
	}
	return nil, false
}

// Expand returns the full name of a single-character modifier.
func Expand(c byte) (string, bool) {
	for _, m := range c1mod {
		if m.c == c {
			return m.full, true
		}
	}
	return "", false
}

// Names of the newline conventions, indexed by PCRE2_NEWLINE_xx.
var Newlines = []string{"DEFAULT", "CR", "LF", "CRLF", "ANY", "ANYCRLF", "NUL"}

var convertList = []struct {
	name string
	opt  uint32
}{
	{"glob", CONVERT_GLOB},
	{"glob_no_starstar", CONVERT_GLOB_NO_STARSTAR},
	{"glob_no_wild_separator", CONVERT_GLOB_NO_WILD_SEPARATOR},
	{"posix_basic", CONVERT_POSIX_BASIC},
	{"posix_extended", CONVERT_POSIX_EXTENDED},
	{"unset", ConvertUnset},
}

// Common holds the fields that patctl and datctl share.
type Common struct {
	Options     uint32
	Control     uint32
	Control2    uint32
	Jitstack    uint32
	Replacement string
	SubstSkip   uint32
	SubstStop   uint32
}

// PatCtl is patctl of pcre2test.c.
type PatCtl struct {
	Common
	Jit            uint32
	Stackguard     uint32
	TablesID       uint32
	ConvertType    uint32
	ConvertLength  uint32
	GlobEscape     uint32
	GlobSeparator  uint32
	RegerrorBuffsz uint32
	Locale         string
}

// DatCtl is datctl of pcre2test.c.
type DatCtl struct {
	Common
	Startend    [2]uint32
	Cerror      [2]uint32
	Cfail       [2]uint32
	CalloutData int32
	CopyNumbers [MaxCpyGet]int32
	GetNumbers  [MaxCpyGet]int32
	Oveccount   uint32
	Offset      uint32
	CopyNames   []string
	GetNames    []string
}

// NewPatCtl returns the initial default pattern controls (def_patctl).
func NewPatCtl() PatCtl { return PatCtl{ConvertType: ConvertUnset} }

// NewDatCtl returns the initial default data controls (def_datctl).
func NewDatCtl() DatCtl {
	d := DatCtl{}
	d.Oveccount = DefaultOveccount
	d.Startend = [2]uint32{CforeUnset, CforeUnset}
	d.Cerror = [2]uint32{CforeUnset, CforeUnset}
	d.Cfail = [2]uint32{CforeUnset, CforeUnset}
	d.CopyNumbers[0] = -1
	d.GetNumbers[0] = -1
	return d
}

// CompileCtx holds the compile-context fields set by modifiers.
type CompileCtx struct {
	ExtraOptions     uint32
	Newline          uint16
	BSR              uint16
	ParensNestLimit  uint32
	MaxPatLen        uint64
	MaxPatCompLen    uint64
	MaxVarLookbehind uint32
	// Touched records whether a setter was called for each field, so that a
	// runner can avoid calling library setters needlessly.
}

// MatchCtx holds the match-context fields set by modifiers.
type MatchCtx struct {
	MatchLimit  uint32
	DepthLimit  uint32
	HeapLimit   uint32
	OffsetLimit uint64
}

// Ctx says which contexts a decode applies to.
type Ctx int

// Contexts (CTX_xxx).
const (
	CtxPat Ctx = iota
	CtxPopPat
	CtxDefPat
	CtxDat
	CtxDefDat
)

// State is what decode operates on. Pat/Dat/CC/MC may be nil when not
// relevant (as in pcre2test.c, where the pointers passed are NULL).
type State struct {
	Out         io.Writer
	Pat         *PatCtl
	Dat         *DatCtl
	CC          *CompileCtx
	MC          *MatchCtx
	Perltest    bool
	DefaultNL   uint16 // NEWLINE_DEFAULT of the build (LF)
	DefaultBSR  uint16
	DefaultNest uint32
}

func isspace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}

func isdigit(c byte) bool { return c >= '0' && c <= '9' }

// cstr is a NUL-terminated byte buffer view.
type cstr struct{ b []byte }

func (c *cstr) at(i int) byte {
	if i < 0 || i >= len(c.b) {
		return 0
	}
	return c.b[i]
}

func (c *cstr) set(i int, v byte) {
	if i >= 0 && i < len(c.b) {
		c.b[i] = v
	}
}

// strtoul10 parses an unsigned decimal at i the way strtoul(…, 10) does after
// a digit check (saturating at ^uint64(0)); it returns the value and the
// index after the digits.
func (c *cstr) strtoul(i int) (uint64, int) {
	var v uint64
	sat := false
	for isdigit(c.at(i)) {
		d := uint64(c.at(i) - '0')
		if v > (^uint64(0)-d)/10 {
			sat = true
		} else {
			v = v*10 + d
		}
		i++
	}
	if sat {
		return ^uint64(0), i
	}
	return v, i
}

func (c *cstr) strtol(i int) (int64, int) {
	neg := false
	if c.at(i) == '-' {
		neg = true
		i++
	} else if c.at(i) == '+' {
		i++
	}
	v, j := c.strtoul(i)
	if v > 1<<62 {
		if neg {
			return -1 << 62, j
		}
		return 1 << 62, j
	}
	if neg {
		return -int64(v), j
	}
	return int64(v), j
}

func (c *cstr) index(from int, ch byte) int {
	for i := from; i < len(c.b); i++ {
		if c.b[i] == 0 {
			return -1
		}
		if c.b[i] == ch {
			return i
		}
	}
	return -1
}

func strncmpic(a []byte, b string, n int) int {
	for i := 0; i < n; i++ {
		var x, y byte
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x >= 'A' && x <= 'Z' {
			x += 'a' - 'A'
		}
		if y >= 'A' && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return int(x) - int(y)
		}
	}
	return 0
}

func scan(name []byte) int {
	bot, top := 0, len(List)
	for top > bot {
		mid := (bot + top) / 2
		m := List[mid].Name
		n := len(name)
		ml := len(m)
		l := n
		if ml < l {
			l = ml
		}
		c := strings.Compare(string(name[:l]), m[:l])
		if c == 0 {
			if n == ml {
				return mid
			}
			c = n - ml
		}
		if c > 0 {
			bot = mid + 1
		} else {
			top = mid
		}
	}
	return -1
}

// check finds the field for modifier m in the given context, or prints why
// not (check_modifier). It returns false when the modifier is not valid here.
func (s *State) check(m *Mod, ctx Ctx, c byte) bool {
	if s.Perltest {
		switch m.Which {
		case PNDP, PATP, DATP, PDP:
		default:
			fmt.Fprintf(s.Out, "** '%s' is not allowed in a Perl-compatible test\n", m.Name)
			return false
		}
	}
	ok := false
	switch m.Which {
	case CTC:
		ok = (ctx == CtxDefPat || ctx == CtxPat) && s.CC != nil
	case CTM:
		ok = (ctx == CtxDefDat || ctx == CtxDat) && s.MC != nil
	case DAT, DATP:
		ok = s.Dat != nil
	case PAT, PATP:
		ok = s.Pat != nil
	case PD, PDP, PND, PNDP:
		if s.Dat != nil {
			ok = true
		} else if s.Pat != nil && (m.Which == PD || m.Which == PDP || ctx != CtxDefPat) {
			ok = true
		}
	}
	if !ok {
		if c == 0 {
			fmt.Fprintf(s.Out, "** '%s' is not valid here\n", m.Name)
		} else {
			fmt.Fprintf(s.Out, "** /%c is not valid here\n", c)
		}
	}
	return ok
}

// common returns the shared block that a PD-type modifier writes.
func (s *State) common(m *Mod) *Common {
	switch m.Which {
	case DAT, DATP:
		return &s.Dat.Common
	case PAT, PATP:
		return &s.Pat.Common
	default: // PD, PDP, PND, PNDP: data block if present, else pattern
		if s.Dat != nil {
			return &s.Dat.Common
		}
		return &s.Pat.Common
	}
}

// u32 returns a pointer to the uint32 field written by m (not for strings,
// NN, IN2 etc.).
func (s *State) u32(m *Mod) *uint32 {
	switch m.Field {
	case FOptions:
		return &s.common(m).Options
	case FControl:
		return &s.common(m).Control
	case FControl2:
		return &s.common(m).Control2
	case FJitstack:
		return &s.common(m).Jitstack
	case FSubstSkip:
		return &s.common(m).SubstSkip
	case FSubstStop:
		return &s.common(m).SubstStop
	case FJit:
		return &s.Pat.Jit
	case FStackguard:
		return &s.Pat.Stackguard
	case FTables:
		return &s.Pat.TablesID
	case FConvertType:
		return &s.Pat.ConvertType
	case FConvertLength:
		return &s.Pat.ConvertLength
	case FGlobEscape:
		return &s.Pat.GlobEscape
	case FGlobSeparator:
		return &s.Pat.GlobSeparator
	case FRegerrorBuffsize:
		return &s.Pat.RegerrorBuffsz
	case FOveccount:
		return &s.Dat.Oveccount
	case FOffset:
		return &s.Dat.Offset
	case FCExtra:
		return &s.CC.ExtraOptions
	case FCParensNest:
		return &s.CC.ParensNestLimit
	case FCMaxVarLookbehind:
		return &s.CC.MaxVarLookbehind
	case FMMatchLimit:
		return &s.MC.MatchLimit
	case FMDepthLimit:
		return &s.MC.DepthLimit
	case FMHeapLimit:
		return &s.MC.HeapLimit
	}
	panic("mods: no uint32 field for " + m.Name)
}

func u32overflow(v uint64) bool { return v > 0xffffffff }

// Decode ports decode_modifiers(): it interprets the modifier list p (which
// is the remainder of a pattern line or of a data line after "\="), applying
// it to the state. It returns false after printing a diagnostic.
func (s *State) Decode(p0 []byte, ctx Ctx) bool {
	buf := &cstr{b: append(append([]byte(nil), p0...), 0)}
	// A NUL in the middle ends the string, as in C.
	for i, c := range buf.b {
		if c == 0 {
			buf.b = buf.b[:i+1]
			break
		}
	}
	p := 0
	first := true
	out := s.Out

	for {
		for isspace(buf.at(p)) || buf.at(p) == ',' {
			p++
		}
		if buf.at(p) == 0 {
			break
		}
		ep := p
		for buf.at(ep) != 0 && buf.at(ep) != ',' {
			ep++
		}
		if buf.at(ep) == 0 {
			for ep > p && isspace(buf.at(ep-1)) {
				ep--
			}
			buf.set(ep, 0)
		}
		off := false
		if buf.at(p) == '-' {
			off = true
			p++
		}
		pp := p
		for pp < ep && buf.at(pp) != '=' {
			pp++
		}
		idx := scan(buf.b[p:pp])

		if idx < 0 {
			mp := p
			if !first {
				fmt.Fprintf(out, "** Unrecognized modifier '%s'\n", buf.b[p:ep])
				if ep-p == 1 {
					fmt.Fprintf(out, "** Single-character modifiers must come first\n")
				}
				return false
			}
			for cc := buf.at(p); cc != ',' && cc != '\n' && cc != 0; cc = buf.at(p) {
				full, ok := Expand(cc)
				if !ok {
					fmt.Fprintf(out, "** Unrecognized modifier '%c' in '%s'\n", cc, buf.b[mp:ep])
					return false
				}
				m, _ := Lookup(full)
				if !s.check(m, ctx, cc) {
					return false
				}
				f := s.u32(m)
				if cc == 'x' && *f&EXTENDED != 0 {
					*f &^= EXTENDED
					*f |= EXTENDED_MORE
				} else {
					*f |= m.Value
				}
				p++
			}
			continue
		}

		m := &List[idx]
		if m.Type != TCTL && m.Type != TOPT && (m.Type != TIND || buf.at(pp) == '=') {
			if buf.at(pp) != '=' {
				pp++
				fmt.Fprintf(out, "** '=' expected after '%s'\n", m.Name)
				return false
			}
			pp++
			if off {
				fmt.Fprintf(out, "** '-' is not valid for '%s'\n", m.Name)
				return false
			}
		} else if c := buf.at(pp); c != ',' && c != '\n' && c != ' ' && c != 0 {
			fmt.Fprintf(out, "** Unrecognized modifier '%s'\n", buf.b[p:ep])
			return false
		}

		length := ep - pp
		if !s.check(m, ctx, 0) {
			return false
		}
		invalid := func() bool {
			fmt.Fprintf(out, "** Invalid value in '%s'\n", buf.b[p:ep])
			return false
		}

		switch m.Type {
		case TCTL, TOPT:
			f := s.u32(m)
			if off {
				*f &^= m.Value
			} else {
				*f |= m.Value
			}

		case TBSR:
			arg := buf.b[pp:ep]
			set := func(v uint16, isSet bool) {
				s.CC.BSR = v
				if ctx == CtxPat || ctx == CtxDefPat {
					if isSet {
						s.Pat.Control2 |= CTL2_BSR_SET
					} else {
						s.Pat.Control2 &^= CTL2_BSR_SET
					}
				} else {
					if isSet {
						s.Dat.Control2 |= CTL2_BSR_SET
					} else {
						s.Dat.Control2 &^= CTL2_BSR_SET
					}
				}
			}
			switch {
			case length == 7 && strncmpic(arg, "default", 7) == 0:
				set(s.DefaultBSR, false)
			case length == 7 && strncmpic(arg, "anycrlf", 7) == 0:
				set(BSR_ANYCRLF, true)
			case length == 7 && strncmpic(arg, "unicode", 7) == 0:
				set(BSR_UNICODE, true)
			default:
				return invalid()
			}
			pp = ep

		case TCHR:
			*s.u32(m) = uint32(buf.at(pp))
			pp++

		case TCON:
			f := s.u32(m)
			for ; ; pp++ {
				colon := buf.index(pp, ':')
				end := ep
				if colon >= 0 && colon < ep {
					end = colon
				}
				l := end - pp
				k := 0
				for ; k < len(convertList); k++ {
					if strncmpic(buf.b[pp:], convertList[k].name, l) == 0 {
						if *f == ConvertUnset {
							*f = convertList[k].opt
						} else {
							*f |= convertList[k].opt
						}
						break
					}
				}
				if k >= len(convertList) {
					return invalid()
				}
				pp += l
				if buf.at(pp) != ':' {
					break
				}
			}

		case TIN2:
			if !isdigit(buf.at(pp)) {
				return invalid()
			}
			var f *[2]uint32
			if m.Field == FStartend {
				f = &s.Dat.Startend
			} else if m.Field == FCerror {
				f = &s.Dat.Cerror
			} else {
				f = &s.Dat.Cfail
			}
			v, e := buf.strtoul(pp)
			if u32overflow(v) {
				return invalid()
			}
			f[0] = uint32(v)
			if buf.at(e) == ':' {
				v, e = buf.strtoul(e + 1)
				if u32overflow(v) {
					return invalid()
				}
				f[1] = uint32(v)
			} else {
				f[1] = 0
			}
			pp = e

		case TSIZ:
			if !isdigit(buf.at(pp)) {
				return invalid()
			}
			v, e := buf.strtoul(pp)
			if v == ^uint64(0) {
				return invalid()
			}
			switch m.Field {
			case FCMaxPatLen:
				s.CC.MaxPatLen = v
			case FCMaxPatCompLen:
				s.CC.MaxPatCompLen = v
			case FMOffsetLimit:
				s.MC.OffsetLimit = v
			}
			pp = e

		case TIND, TINT:
			if m.Type == TIND && length == 0 {
				*s.u32(m) = m.Value
				break
			}
			if !isdigit(buf.at(pp)) {
				return invalid()
			}
			v, e := buf.strtoul(pp)
			if u32overflow(v) {
				return invalid()
			}
			*s.u32(m) = uint32(v)
			pp = e

		case TINS:
			if !isdigit(buf.at(pp)) && buf.at(pp) != '-' {
				return invalid()
			}
			v, e := buf.strtol(pp)
			if v > 0x7fffffff || v < -0x80000000 {
				return invalid()
			}
			s.Dat.CalloutData = int32(v)
			pp = e

		case TNL:
			arg := buf.b[pp:ep]
			i := 0
			for ; i < len(Newlines); i++ {
				if length == len(Newlines[i]) && strncmpic(arg, Newlines[i], length) == 0 {
					break
				}
			}
			if i >= len(Newlines) {
				return invalid()
			}
			setNL := func(c *Common, isSet bool) {
				if isSet {
					c.Control2 |= CTL2_NL_SET
				} else {
					c.Control2 &^= CTL2_NL_SET
				}
			}
			var c *Common
			if ctx == CtxPat || ctx == CtxDefPat {
				c = &s.Pat.Common
			} else {
				c = &s.Dat.Common
			}
			if i == 0 {
				s.CC.Newline = s.DefaultNL
				setNL(c, false)
			} else {
				s.CC.Newline = uint16(i)
				setNL(c, true)
			}
			pp = ep

		case TNN:
			var nums *[MaxCpyGet]int32
			var names *[]string
			if m.Field == FCopy {
				nums, names = &s.Dat.CopyNumbers, &s.Dat.CopyNames
			} else {
				nums, names = &s.Dat.GetNumbers, &s.Dat.GetNames
			}
			if isdigit(buf.at(pp)) || buf.at(pp) == '-' {
				ct := MaxCpyGet - 1
				v, e := buf.strtol(pp)
				if v > 0x7fffffff || v < -0x80000000 {
					return invalid()
				}
				value := int32(v)
				slot := 0
				if value >= 0 {
					for nums[slot] >= 0 && ct > 0 {
						ct--
						slot++
					}
					if nums[slot] >= 0 && ct == 0 {
						// "while (*field >= 0 && ct-- > 0)" leaves ct at -1
						ct--
					}
					if ct <= 0 {
						fmt.Fprintf(out, "** Too many numeric '%s' modifiers\n", m.Name)
						return false
					}
				}
				nums[slot] = value
				if ct > 0 && slot+1 < MaxCpyGet {
					nums[slot+1] = -1
				}
				pp = e
			} else {
				if length > 0 {
					if length > MaxNameLen {
						fmt.Fprintf(out, "** Group name in '%s' is too long\n", m.Name)
						return false
					}
					used := 0
					for _, n := range *names {
						used += len(n) + 1
					}
					if used+length+2 > LenCpyGet {
						fmt.Fprintf(out, "** Too many characters in named '%s' modifiers\n", m.Name)
						return false
					}
					*names = append(*names, string(buf.b[pp:pp+length]))
				}
				pp = ep
			}

		case TSTR:
			if length+1 > int(m.Value) {
				fmt.Fprintf(out, "** Overlong value for '%s' (max %d code units)\n", m.Name, int(m.Value)-1)
				return false
			}
			v := string(buf.b[pp : pp+length])
			if m.Field == FLocale {
				s.Pat.Locale = v
			} else {
				s.common(m).Replacement = v
			}
			pp = ep
		}

		if c := buf.at(pp); c != ',' && c != '\n' && c != ' ' && c != 0 {
			fmt.Fprintf(out, "** Comma expected after modifier item '%s'\n", m.Name)
			return false
		}
		p = pp
		first = false

		if ctx == CtxPopPat && (s.Pat.Options != 0 || s.Pat.TablesID != 0 || s.Pat.Locale != "" ||
			s.Pat.Control&notPopControls != 0) {
			fmt.Fprintf(out, "** '%s' is not valid here\n", m.Name)
			return false
		}
	}
	return true
}

const notPopControls = CTL_HEXPAT | CTL_POSIX | CTL_POSIX_NOSUB | CTL_PUSH | CTL_PUSHCOPY | CTL_PUSHTABLESCOPY | CTL_USE_LENGTH
