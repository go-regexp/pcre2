// Data structures of the interpretive matcher: the heap frame and the match
// block of pcre2_intmodedep.h (heapframe, match_block), the frame vector that
// pcre2_match() caches in the match data block, and the small helpers that the
// macros of pcre2_match.c (IS_NEWLINE, WAS_NEWLINE, CHECK_PARTIAL, ...) stand
// for.
//
// Pointers into the subject or into the compiled code are int offsets: eptr
// and friends index mb.subject (start_subject is index 0), ecode and friends
// index mb.startCode. -1 plays the part of NULL for the mark fields and for
// the "unset" last_group_offset (PCRE2_UNSET in C, where it is a byte offset
// into the frame vector; here it is a frame index).
package pcre2

// Offsets that C's sizeof/offsetof give for the 64-bit heapframe (see
// pcre2_intmodedep.h:790): the ovector follows 136 bytes of fixed fields.
const (
	heapframeAlignment = 8 // HEAPFRAME_ALIGNMENT
)

// heapframe is the backtracking frame (pcre2_intmodedep.h:790). The fields up
// to occu are preserved over RMATCH but not copied to new frames; the rest,
// from eptr on, is copied whenever a new frame becomes current.
type heapframe struct {
	ecode          int    // the current position in the pattern
	tempSptr       [2]int // short-term pointer values
	length         int    // character, string or code length
	backFrame      int    // number of frames to subtract on RRETURN (C: bytes)
	tempSize       int    // short-term size values
	rdepth         uint32 // function "recursion" depth
	groupFrameType uint32 // type information for group frames
	temp32         [4]uint32
	returnID       uint8
	op             uint8
	occu           [6]byte // other case code units

	eptr            int // MUST BE FIRST of the copied part
	startMatch      int // can be adjusted by \K
	mark            int // most recent mark on the success path (-1: none)
	recurseLastUsed int
	currentRecurse  uint32
	captureLast     uint32
	lastGroupOffset int // frame index of the most recent group frame, -1 if none
	offsetTop       int
	ovector         []uint64 // 2*top_bracket entries, a window on frameStore.ovec
}

// frameStore is the frame vector cached in MatchData.heapframes. The size the
// limits are checked against is the C size in bytes (MatchData.heapframesSz);
// the Go slices grow lazily underneath it.
type frameStore struct {
	frames []heapframe
	ovec   []uint64
	stride int // len of each frame's ovector
}

func newFrameStore(stride, n int) *frameStore {
	fs := &frameStore{stride: stride}
	fs.grow(n)
	return fs
}

// grow makes room for n frames, keeping the contents of the existing ones.
func (fs *frameStore) grow(n int) {
	if n <= len(fs.frames) {
		return
	}
	nf := make([]heapframe, n)
	copy(nf, fs.frames)
	no := make([]uint64, n*fs.stride)
	copy(no, fs.ovec)
	for i := range nf {
		nf[i].ovector = no[i*fs.stride : (i+1)*fs.stride : (i+1)*fs.stride]
	}
	fs.frames, fs.ovec = nf, no
}

// Group frame type values (pcre2_match.c:111).
const (
	GF_CAPTURE    uint32 = 0x00010000
	GF_NOCAPTURE  uint32 = 0x00020000
	GF_CONDASSERT uint32 = 0x00030000
	GF_RECURSE    uint32 = 0x00040000
)

func GF_IDMASK(a uint32) uint32   { return a & 0xffff0000 }
func GF_DATAMASK(a uint32) uint32 { return a & 0x0000ffff }

const recurseUnset = 0xffffffff // RECURSE_UNSET

// Non-error returns from and within match() (pcre2_match.c:87).
const (
	MATCH_MATCH   = 1
	MATCH_NOMATCH = 0

	MATCH_ACCEPT        = -999
	MATCH_KETRPOS       = -998
	MATCH_COMMIT        = -997
	MATCH_PRUNE         = -996
	MATCH_SKIP          = -995
	MATCH_SKIP_ARG      = -994
	MATCH_THEN          = -993
	MATCH_BACKTRACK_MAX = MATCH_THEN
	MATCH_BACKTRACK_MIN = MATCH_COMMIT
)

// Repetition types (pcre2_match.c:123).
const (
	REPTYPE_MIN = iota
	REPTYPE_MAX
	REPTYPE_POS
)

const uint32Max = 0xffffffff

var rep_min = [...]uint32{0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0}
var rep_max = [...]uint32{uint32Max, uint32Max, uint32Max, uint32Max, 1, 1, 0, 0, uint32Max, uint32Max, 1}
var rep_typ = [...]uint32{REPTYPE_MAX, REPTYPE_MIN, REPTYPE_MAX, REPTYPE_MIN, REPTYPE_MAX, REPTYPE_MIN,
	REPTYPE_MAX, REPTYPE_MIN, REPTYPE_POS, REPTYPE_POS, REPTYPE_POS, REPTYPE_POS}

// Public options permitted at match time (pcre2_match.c:73).
const PUBLIC_MATCH_OPTIONS = PCRE2_ANCHORED | PCRE2_ENDANCHORED | PCRE2_NOTBOL | PCRE2_NOTEOL | PCRE2_NOTEMPTY |
	PCRE2_NOTEMPTY_ATSTART | PCRE2_NO_UTF_CHECK | PCRE2_PARTIAL_HARD |
	PCRE2_PARTIAL_SOFT | PCRE2_NO_JIT | PCRE2_COPY_MATCHED_SUBJECT |
	PCRE2_DISABLE_RECURSELOOP_CHECK

// matchBlock is match_block (pcre2_intmodedep.h:864): the "static" data of one
// pcre2_match() call.
type matchBlock struct {
	heapLimit          uint32
	matchLimit         uint32
	matchLimitDepth    uint32
	matchCallCount     uint32
	hitend             bool
	hasthen            bool
	allowemptypartial  bool
	lcc, fcc, ctypes   []byte
	startOffset        int
	endOffsetTop       int
	partial            uint16
	bsrConvention      uint16
	nameCount          uint16
	nameEntrySize      uint16
	nameTable          []byte
	startCode          []byte
	subject            []byte // start_subject is index 0
	checkSubject       int
	endSubject         int
	trueEndSubject     int
	endMatchPtr        int
	startUsedPtr       int
	lastUsedPtr        int
	mark               int // code offset of the mark name, -1: NULL
	nomatchMark        int
	verbEcodePtr       int // code offset
	verbSkipPtr        int // subject offset (from OP_SKIP)
	verbSkipCode       int // code offset (from OP_SKIP_ARG)
	verbCurrentRecurse uint32
	moptions           uint32
	poptions           uint32
	skipArgCount       uint32
	ignoreSkipArg      uint32
	nltype             uint32
	nllen              uint32
	nl                 [4]byte
	utf                bool
	cb                 *CalloutBlock
	cbvec              []uint64 // scratch for the callout's offset vector
	calloutData        any
	callout            func(cb *CalloutBlock, data any) int
}

// isNewline is IS_NEWLINE(p) (pcre2_internal.h:496); it may set mb.nllen.
func (mb *matchBlock) isNewline(p int) bool {
	if mb.nltype != NLTYPE_FIXED {
		if p < mb.endSubject {
			ok, n := is_newline(mb.subject, p, mb.nltype, mb.endSubject, mb.utf)
			if ok {
				mb.nllen = n
			}
			return ok
		}
		return false
	}
	return p <= mb.endSubject-int(mb.nllen) && mb.subject[p] == mb.nl[0] &&
		(mb.nllen == 1 || mb.subject[p+1] == mb.nl[1])
}

// wasNewline is WAS_NEWLINE(p) (pcre2_internal.h:510); it may set mb.nllen.
func (mb *matchBlock) wasNewline(p int) bool {
	if mb.nltype != NLTYPE_FIXED {
		if p > 0 {
			ok, n := was_newline(mb.subject, p, mb.nltype, 0, mb.utf)
			if ok {
				mb.nllen = n
			}
			return ok
		}
		return false
	}
	return p >= int(mb.nllen) && mb.subject[p-int(mb.nllen)] == mb.nl[0] &&
		(mb.nllen == 1 || mb.subject[p-int(mb.nllen)+1] == mb.nl[1])
}

// scheck is the test of SCHECK_PARTIAL() (pcre2_match.c:537): it reports true
// when a hard partial match must be returned immediately.
func (mb *matchBlock) scheck(eptr int) bool {
	if mb.partial != 0 && (eptr > mb.startUsedPtr || mb.allowemptypartial) {
		mb.hitend = true
		if mb.partial > 1 {
			return true
		}
	}
	return false
}

// crlfPartial is the recurring test "partial matching, at the CR of a CRLF
// newline that ends the subject": it sets hitend and reports true when a hard
// partial match must be returned.
func (mb *matchBlock) crlfPartial(isLast bool, b byte) bool {
	if mb.partial != 0 && isLast && mb.nltype == NLTYPE_FIXED && mb.nllen == 2 && b == mb.nl[0] {
		mb.hitend = true
		if mb.partial > 1 {
			return true
		}
	}
	return false
}

// acrossChar is ACROSSCHAR(p < end, p, p++): skip continuation bytes.
func acrossChar(s []byte, p, end int) int {
	for p < end && s[p]&0xc0 == 0x80 {
		p++
	}
	return p
}

// markName returns the name of the mark whose name starts at code offset m
// (the byte before it is its length), or nil.
func (mb *matchBlock) markName(m int) []byte {
	if m < 0 {
		return nil
	}
	return mb.startCode[m : m+int(mb.startCode[m-1])]
}

// hspace and vspace are the HSPACE_CASES / VSPACE_CASES of pcre2_internal.h.
func isHspace(c uint32) bool {
	switch c {
	case 0x09, 0x20, 0xa0, 0x1680, 0x180e, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005,
		0x2006, 0x2007, 0x2008, 0x2009, 0x200A, 0x202f, 0x205f, 0x3000:
		return true
	}
	return false
}

func isVspace(c uint32) bool {
	switch c {
	case 0x0a, 0x0b, 0x0c, 0x0d, 0x85, 0x2028, 0x2029:
		return true
	}
	return false
}

// propTest is the property test shared by OP_PROP/OP_NOTPROP and the repeated
// forms (pcre2_match.c:2493 and following) before the "notmatch" inversion.
// ok is false for an unknown property type (PCRE2_ERROR_INTERNAL).
func propTest(proptype int, fc uint32, val uint32) (res bool, ok bool) {
	prop := GET_UCD(fc)
	switch proptype {
	case PT_ANY:
		return true, true
	case PT_LAMP:
		ct := uint32(prop.chartype)
		return ct == ucp_Lu || ct == ucp_Ll || ct == ucp_Lt, true
	case PT_GC:
		return val == ucp_gentype[prop.chartype], true
	case PT_PC:
		return val == uint32(prop.chartype), true
	case PT_SC:
		return val == uint32(prop.script), true
	case PT_SCX:
		return val == uint32(prop.script) || MAPBIT(ucd_script_sets[UCD_SCRIPTX_PROP(prop):], val), true
	case PT_ALNUM:
		g := ucp_gentype[prop.chartype]
		return g == ucp_L || g == ucp_N, true
	case PT_SPACE, PT_PXSPACE:
		if isHspace(fc) || isVspace(fc) {
			return true, true
		}
		return ucp_gentype[prop.chartype] == ucp_Z, true
	case PT_WORD:
		ct := uint32(prop.chartype)
		g := ucp_gentype[ct]
		return g == ucp_L || g == ucp_N || ct == ucp_Mn || ct == ucp_Pc, true
	case PT_CLIST:
		cp := ucd_caseless_sets[val:]
		for i := 0; ; i++ {
			if fc < cp[i] {
				return false, true
			}
			if fc == cp[i] {
				return true, true
			}
		}
	case PT_UCNC:
		return fc == CHAR_DOLLAR_SIGN || fc == CHAR_COMMERCIAL_AT || fc == CHAR_GRAVE_ACCENT ||
			(fc >= 0xa0 && fc <= 0xd7ff) || fc >= 0xe000, true
	case PT_BIDICL:
		return UCD_BIDICLASS_PROP(prop) == val, true
	case PT_BOOL:
		return MAPBIT(ucd_boolprop_sets[UCD_BPROPS_PROP(prop):], val), true
	}
	return false, false
}
