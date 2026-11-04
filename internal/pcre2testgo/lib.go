package pcre2testgo

import "github.com/go-regexp/pcre2/internal/pcre2testgo/mods"

// Unsupported is returned by a Lib method that the library under test does not
// provide. The runner records the feature as unsupported and carries on.
const Unsupported = 1 << 30

// CompileSettings are the compile-context values for one Compile call.
type CompileSettings struct {
	mods.CompileCtx
	// Null asks for a compile with a nil context (null_context).
	Null bool
	// NullPattern asks for a nil pattern pointer (null_pattern).
	NullPattern bool
}

// MatchSettings are the match-context values for one Match call.
type MatchSettings struct {
	mods.MatchCtx
	Null bool
	// Callout, when non-nil, is to be called for every callout; the result
	// is the callout's return value. Only set for a Code that implements
	// CalloutCapable.
	Callout func(*CalloutBlock) int
}

// CodeExtra carries information that pcre2test reads from the internals of a
// compiled pattern rather than through pcre2_pattern_info().
type CodeExtra struct {
	Known         bool // false when the library cannot provide any of this
	FirstCaseless bool
	LastCaseless  bool
	NLSet         bool
	BSRSet        bool
	HasBkPorX     bool // \P, \p or \X in the pattern
	HasCallout    bool // (?C...) item in the pattern
	// StartBits is the 32-byte "starting code units" bitmap, or nil.
	StartBits []byte
}

// Code is a compiled pattern.
type Code interface {
	// Info is pcre2_pattern_info() for a 32-bit-valued item.
	Info(what uint32) (uint64, int)
	NameTable() (table []byte, count, entrySize uint32)
	Extra() CodeExtra
	// NewMatchData creates match data with the given ovector count; zero
	// means "from the pattern".
	NewMatchData(oveccount uint32) MatchData
	Match(subject []byte, start uint64, options uint32, md MatchData, ms MatchSettings) int
	NumberFromName(name string) int
	Free()
}

// The interfaces below are optional: a Code that implements one gets the
// corresponding pcre2test feature exercised; otherwise cases that need it are
// reported as unsupported.

// DFAMatcher is implemented by a Code that offers pcre2_dfa_match().
type DFAMatcher interface {
	// DFAMatch is pcre2_dfa_match(); workspace has DFAWorkspaceSize ints.
	DFAMatch(subject []byte, start uint64, options uint32, md MatchData, ms MatchSettings, workspace []int32) int
}

// DFAWorkspaceSize is DFA_WS_DIMENSION of pcre2test.c.
const DFAWorkspaceSize = 1000

// CodeDumper is implemented by a Code that can print its compiled form the way
// pcre2_printint() does (the "bincode" and "fullbincode" modifiers).
type CodeDumper interface {
	// PrintInt returns the dump that pcre2test writes after the line of
	// dashes: the text of pcre2_printint(code, f, full), final line of dashes
	// included.
	PrintInt(full bool) string
}

// Substituter is implemented by a Code that offers pcre2_substitute().
type Substituter interface {
	// Substitute is pcre2_substitute(). outCap is the capacity of the output
	// buffer in code units. It returns the result code, the output (valid when
	// rc >= 0, and for PCRE2_SUBSTITUTE_OVERFLOW_LENGTH failures nothing) and
	// the final value of the length argument: the output length on success,
	// the offset in the replacement for a replacement error, the length
	// needed for an overflow, or PCRE2_UNSET.
	Substitute(subject []byte, start uint64, options uint32, md MatchData, ms MatchSettings,
		replacement []byte, nullReplacement bool, outCap uint64) (rc int, out []byte, outlen uint64)
}

// PatternConverter is implemented by a Lib that offers pcre2_pattern_convert()
// (the "convert" pattern modifier).
type PatternConverter interface {
	Convert(pattern []byte, options uint32, glob GlobSettings, outCap uint64) ConvertResult
}

// GlobSettings are the convert-context values the modifiers set.
type GlobSettings struct {
	EscapeSet    bool
	Escape       uint32 // 0 means "no escape"
	SeparatorSet bool
	Separator    uint32
}

// ConvertResult is the outcome of Convert.
type ConvertResult struct {
	Out          []byte
	RC           int    // 0 or a PCRE2_ERROR_* code
	ErrOffset    uint64 // pcre2_pattern_convert's converted-length output on error
	BadEscape    bool   // pcre2_set_glob_escape() refused the character
	BadSeparator bool   // pcre2_set_glob_separator() refused the character
}

// Substitute option bits (pcre2.h).
const (
	SubstituteGlobal          = 0x00000100
	SubstituteExtended        = 0x00000200
	SubstituteUnsetEmpty      = 0x00000400
	SubstituteUnknownUnset    = 0x00000800
	SubstituteOverflowLength  = 0x00001000
	SubstituteLiteral         = 0x00008000
	SubstituteMatched         = 0x00010000
	SubstituteReplacementOnly = 0x00020000
)

// MatchData is a match data block.
type MatchData interface {
	Ovector() []uint64
	OvectorCount() uint32
	// Mark returns the (*MARK) name, or nil if none was set.
	Mark() []byte
	StartChar() uint64
	// UsedChars returns the leftmost and rightmost consulted characters
	// (allusedtext), ok false if unavailable.
	UsedChars() (left, right uint64, ok bool)

	CopyByNumber(n uint32, units int) (b []byte, rc int)
	LengthByNumber(n uint32) (uint64, int)
	CopyByName(name string, units int) (b []byte, rc int)
	LengthByName(name string) (uint64, int)
	GetByNumber(n uint32) (b []byte, rc int)
	GetByName(name string) (b []byte, rc int)
	ListGet() (list [][]byte, rc int)
}

// Lib is the library under test.
type Lib interface {
	// Compile compiles a pattern. On failure the Code is nil.
	Compile(pattern []byte, options uint32, cs CompileSettings) (Code, int, uint64)
	// ErrorMessage is pcre2_get_error_message(); ok is false for an unknown
	// error number (PCRE2_ERROR_BADDATA).
	ErrorMessage(code int) (msg string, ok bool)
}

// CalloutBlock is pcre2_callout_block (8-bit).
type CalloutBlock struct {
	Version             uint32
	CalloutNumber       uint32
	CaptureTop          uint32
	CaptureLast         uint32
	OffsetVector        []uint64
	Mark                []byte // nil when no mark
	Subject             []byte
	StartMatch          uint64
	CurrentPosition     uint64
	PatternPosition     uint64
	NextItemLength      uint64
	CalloutStringOffset uint64
	CalloutString       []byte // nil for a numbered callout
	// CalloutDelimiter is the delimiter that opened CalloutString (the code
	// unit just before the string in the library's copy).
	CalloutDelimiter byte
	CalloutFlags     uint32
}

// Callout flags (pcre2.h).
const (
	CalloutStartMatch = 0x00000001
	CalloutBacktrack  = 0x00000002
)

// ErrorCallout is PCRE2_ERROR_CALLOUT.
const ErrorCallout = -37

// CalloutEnumBlock is pcre2_callout_enumerate_block (8-bit).
type CalloutEnumBlock struct {
	PatternPosition     uint64
	NextItemLength      uint64
	CalloutNumber       uint32
	CalloutStringOffset uint64
	CalloutString       []byte // nil for a numbered callout
	CalloutDelimiter    byte
}

// CalloutCapable is implemented by a Code whose Match calls MatchSettings.Callout.
type CalloutCapable interface {
	SupportsCallouts() bool
}

// CalloutEnumerator is implemented by a Code that offers
// pcre2_callout_enumerate().
type CalloutEnumerator interface {
	// CalloutEnumerate calls fn for every callout in the pattern; a non-zero
	// result of fn stops the scan and is returned.
	CalloutEnumerate(fn func(CalloutEnumBlock) int) int
}
