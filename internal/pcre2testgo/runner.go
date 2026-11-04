// Package pcre2testgo is a Go reimplementation of the subset of pcre2test
// (PCRE2 10.44, 8-bit, no JIT) that is needed to run the testinput files of
// the PCRE2 distribution against a Go library and to print the results in
// pcre2test's exact output format.
//
// Reference: src/pcre2test.c and doc/pcre2test.txt of PCRE2 10.44. The
// structure mirrors the C program: Run is main()'s input loop, processPattern,
// processData, processCommand, showPatternInfo and copyAndGet port the
// functions of the same names.
//
// Anything pcre2test does that the library under test cannot do (DFA matching,
// callouts, substitution, serialization, POSIX interface, conversion, code
// dumps, memory tracing, ...) is recorded in Result.Unsupported rather than
// guessed at, so that conformance reports can tell "wrong" from "not offered".
package pcre2testgo

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/go-regexp/pcre2/internal/pcre2testgo/mods"
)

// Return codes of the process functions (PR_OK, PR_SKIP, PR_ABEND).
const (
	prOK = iota
	prSkip
	prAbend
)

const (
	junkOffset       = 0xdeadbeef
	defaultOveccount = 15
)

// Info codes (pcre2.h).
const (
	infoAllOptions     = 0
	infoArgOptions     = 1
	infoBackrefMax     = 2
	infoBSR            = 3
	infoCaptureCount   = 4
	infoFirstCodeUnit  = 5
	infoFirstCodeType  = 6
	infoFirstBitmap    = 7
	infoHasCrOrLf      = 8
	infoJChanged       = 9
	infoLastCodeUnit   = 11
	infoLastCodeType   = 12
	infoMatchEmpty     = 13
	infoMatchLimit     = 14
	infoMaxLookbehind  = 15
	infoMinLength      = 16
	infoNameCount      = 17
	infoNameEntrySize  = 18
	infoNameTable      = 19
	infoNewline        = 20
	infoDepthLimit     = 21
	infoSize           = 22
	infoHasBackslashC  = 23
	infoFrameSize      = 24
	infoHeapLimit      = 25
	infoExtraOptions   = 26
	errNoMatch         = -1
	errPartial         = -2
	errUTF8Err1        = -3
	errUTF32Err2       = -28
	errNoMemory        = -48
	errUnset           = -55
	errJITBadOption    = -45
	errBadUTFOffset    = -36
	errNoUniqueSubstr  = -50
	unsetSize          = ^uint64(0)
	defaultMatchLimit  = 10000000
	defaultDepthLimit  = 10000000
	defaultHeapLimit   = 20000000
	defaultParensNest  = 250
	pcre2test8bitMode  = 8
	parensNestDefault  = 220
	defaultMaxVarLB    = 255
	callbackSupported  = false
	maxLookbehindUnset = 0
)

// Result is what running a piece of testinput produced.
type Result struct {
	// Output is the text pcre2test would have written.
	Output []byte
	// Unsupported lists the pcre2test features that were needed and that the
	// library under test does not offer (sorted, unique).
	Unsupported []string
	// Abend is true if the run was abandoned ("** pcre2test run abandoned").
	Abend bool
}

// Runner executes testinput. A Runner keeps pcre2test's state between lines
// (defaults set with #pattern/#subject, #forbid_utf, ...), so a whole file
// must be fed through the same Runner, case by case.
type Runner struct {
	lib Lib
	out *bytes.Buffer

	lines [][]byte
	pos   int

	// defaults
	defPat mods.PatCtl
	defDat mods.DatCtl
	defCC  mods.CompileCtx
	defMC  mods.MatchCtx

	forbidUTF    uint32
	localNL      uint16
	perltest     bool
	skipping     bool
	unsupported  map[string]bool
	abend        bool
	patStackUsed int

	// current pattern
	code         Code
	dfaMatched   int
	dfaWS        []int32
	pbufSize     int // pbuffer8_size of pcre2test.c: input buffer size, doubled on demand
	patCtl       mods.PatCtl
	cc           mods.CompileCtx
	utf          bool
	maxCapCount  uint32
	maxLookbhind uint32
	hasCallout   bool
	patBytes     []byte
}

// New returns a Runner for lib.
func New(lib Lib) *Runner {
	r := &Runner{lib: lib}
	r.defPat = mods.NewPatCtl()
	r.defDat = mods.NewDatCtl()
	r.defCC = mods.CompileCtx{
		Newline: mods.NEWLINE_LF, BSR: mods.BSR_UNICODE, ParensNestLimit: parensNestDefault,
		MaxPatLen: unsetSize, MaxPatCompLen: unsetSize, MaxVarLookbehind: defaultMaxVarLB,
	}
	r.defMC = mods.MatchCtx{MatchLimit: defaultMatchLimit, DepthLimit: defaultDepthLimit, HeapLimit: defaultHeapLimit, OffsetLimit: unsetSize}
	r.unsupported = map[string]bool{}
	r.pbufSize = 50000
	return r
}

// readAccount mimics extend_inputline(): a line of n bytes read into the input
// buffer from offset used makes the buffer double (permanently) whenever 1000
// bytes or fewer remain before the line is complete.
func (r *Runner) readAccount(used, n int) {
	for {
		rlen := r.pbufSize - used
		if rlen > 1000 {
			take := n
			if take > rlen-1 {
				take = rlen - 1
			}
			used += take
			n -= take
			if n == 0 {
				return
			}
		} else {
			r.pbufSize *= 2
		}
	}
}

func (r *Runner) unsup(feature string) { r.unsupported[feature] = true }

func (r *Runner) printf(format string, a ...any) { fmt.Fprintf(r.out, format, a...) }

// Reset forgets the Unsupported set (call between cases).
func (r *Runner) resetResult() {
	r.unsupported = map[string]bool{}
	r.abend = false
}

// Run feeds input (zero or more complete input lines) through the runner and
// returns what pcre2test would have printed. The runner is left in a state
// where more input can follow (a pattern left open by the end of input stays
// open, as in the C program).
func (r *Runner) Run(input []byte) Result {
	r.resetResult()
	r.out = &bytes.Buffer{}
	r.lines = splitLines(input)
	r.pos = 0
	for !r.abend {
		line, ok := r.nextLine()
		if !ok {
			break
		}
		r.out.Write(line)
		r.readAccount(0, len(line))
		r.handleLine(line)
	}
	res := Result{Output: r.out.Bytes(), Abend: r.abend}
	for k := range r.unsupported {
		res.Unsupported = append(res.Unsupported, k)
	}
	sort.Strings(res.Unsupported)
	return res
}

// DiscardOpenPattern frees the current pattern, as a blank line would.
func (r *Runner) DiscardOpenPattern() {
	if r.code != nil {
		r.code.Free()
		r.code = nil
	}
	r.skipping = false
}

func splitLines(b []byte) [][]byte {
	var lines [][]byte
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			lines = append(lines, b)
			break
		}
		lines = append(lines, b[:i+1])
		b = b[i+1:]
	}
	return lines
}

func (r *Runner) nextLine() ([]byte, bool) {
	if r.pos >= len(r.lines) {
		return nil, false
	}
	l := r.lines[r.pos]
	r.pos++
	return l, true
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}

func at(b []byte, i int) byte {
	if i < len(b) {
		return b[i]
	}
	return 0
}

const delimiters = "/!\"'`%&-=_:;,@~"

// handleLine is the body of main()'s loop for one input line (already echoed).
func (r *Runner) handleLine(line []byte) {
	rc := prOK
	expectData := r.code != nil
	p := 0
	if expectData || r.skipping {
		for isSpace(at(line, p)) {
			p++
		}
		if p >= len(line) {
			r.DiscardOpenPattern()
		} else if !r.skipping && !(line[p] == '\\' && at(line, p+1) == '=' && isSpace(at(line, p+2))) {
			rc = r.processData(line)
		}
	} else if line[0] == '#' {
		if isSpace(at(line, 1)) || at(line, 1) == '!' || at(line, 1) == 0 {
			return
		}
		rc = r.processCommand(line)
	} else if strings.IndexByte(delimiters, line[0]) >= 0 {
		rc = r.processPattern(line)
	} else {
		for isSpace(at(line, p)) {
			p++
		}
		if p < len(line) {
			r.printf("** Invalid pattern delimiter '%c' (x%x).\n", line[0], line[0])
			rc = prSkip
		}
	}
	switch rc {
	case prSkip:
		r.skipping = true
	case prAbend:
		r.printf("** pcre2test run abandoned\n")
		r.abend = true
	}
}

func (r *Runner) newState(ctx mods.Ctx) *mods.State {
	return &mods.State{
		Out: r.out, Perltest: r.perltest,
		DefaultNL: mods.NEWLINE_LF, DefaultBSR: mods.BSR_UNICODE,
	}
}

var cmdNames = []string{"forbid_utf", "load", "loadtables", "newline_default", "pattern", "perltest", "pop", "popcopy", "save", "subject"}

func (r *Runner) processCommand(line []byte) int {
	cmd := ""
	cmdlen := 0
	for _, n := range cmdNames {
		if bytes.HasPrefix(line[1:], []byte(n)) && isSpace(at(line, len(n)+1)) {
			cmd, cmdlen = n, len(n)
			break
		}
	}
	arg := line[cmdlen+1:]
	if cmd == "" {
		arg = line[1:]
	}
	if r.perltest && cmd != "pattern" && cmd != "subject" {
		r.printf("** #%s is not allowed after #perltest\n", cmd)
		return prAbend
	}
	switch cmd {
	case "":
		r.printf("** Unknown command: %s", line)
	case "forbid_utf":
		r.forbidUTF = mods.NEVER_UTF | mods.NEVER_UCP
	case "perltest":
		r.perltest = true
	case "pattern":
		st := r.newState(mods.CtxDefPat)
		st.Pat, st.CC = &r.defPat, &r.defCC
		st.Decode(arg, mods.CtxDefPat)
		if r.defPat.Jit == 0 && r.defPat.Control&mods.CTL_JITVERIFY != 0 {
			r.defPat.Jit = 7
		}
	case "subject":
		st := r.newState(mods.CtxDefDat)
		st.Dat, st.MC = &r.defDat, &r.defMC
		st.Decode(arg, mods.CtxDefDat)
	case "newline_default":
		// The build default is LF, which is accepted: it unsets the local default
		// unless the list names only other conventions.
		r.localNL = 0
		var first uint16
		f := strings.Fields(string(arg))
		for _, w := range f {
			for i := 1; i < len(mods.Newlines); i++ {
				if strings.EqualFold(w, mods.Newlines[i]) {
					if i == mods.NEWLINE_LF {
						return prOK
					}
					if first == 0 {
						first = uint16(i)
					}
				}
			}
		}
		r.localNL = first
	case "pop", "popcopy":
		r.unsup("pattern stack (#pop)")
		return prSkip
	case "save":
		r.unsup("serialization (#save)")
	case "load":
		r.unsup("serialization (#load)")
	case "loadtables":
		r.unsup("binary tables (#loadtables)")
	}
	return prOK
}

// processPattern ports process_pattern().
func (r *Runner) processPattern(first []byte) int {
	buf := append([]byte(nil), first...)
	delim := buf[0]
	if r.perltest && delim != '/' {
		r.printf("** The only allowed delimiter after #perltest is '/'\n")
		return prAbend
	}

	r.patCtl = r.defPat
	r.cc = r.defCC

	// Find the end of the pattern, reading more lines if necessary.
	p := 1
	for {
		for p < len(buf) {
			if buf[p] == '\\' && p+1 < len(buf) {
				p++
			} else if buf[p] == delim {
				break
			}
			p++
		}
		if p < len(buf) {
			break
		}
		l, ok := r.nextLine()
		if !ok {
			r.printf("** Unexpected EOF\n")
			return prAbend
		}
		r.out.Write(l)
		r.readAccount(len(buf), len(l))
		buf = append(buf, l...)
	}
	if at(buf, p+1) == '\\' {
		buf[p] = '\\'
		p++
	}
	// buf[1:p] is the pattern; the modifiers start after buf[p].
	pat := append([]byte{}, buf[1:p]...) // never nil: nil means null_pattern
	mod := buf[p+1:]

	st := r.newState(mods.CtxPat)
	st.Pat, st.CC = &r.patCtl, &r.cc
	if !st.Decode(mod, mods.CtxPat) {
		return prSkip
	}
	pc := &r.patCtl
	utf := pc.Options&(mods.UTF|mods.MATCH_INVALID_UTF) != 0

	if pc.Control&mods.CTL_UTF8_INPUT != 0 {
		r.printf("** The utf8_input modifier is not allowed in 8-bit mode\n")
		return prSkip
	}
	if pc.ConvertType != mods.ConvertUnset && pc.Control&mods.CTL_POSIX != 0 {
		r.printf("** The convert and posix modifiers are mutually exclusive\n")
		return prSkip
	}
	for _, ex := range []uint32{
		mods.CTL_POSIX | mods.CTL_PUSH, mods.CTL_POSIX | mods.CTL_PUSHCOPY, mods.CTL_POSIX | mods.CTL_PUSHTABLESCOPY,
		mods.CTL_PUSH | mods.CTL_PUSHCOPY, mods.CTL_PUSH | mods.CTL_PUSHTABLESCOPY,
		mods.CTL_PUSHCOPY | mods.CTL_PUSHTABLESCOPY, mods.CTL_EXPAND | mods.CTL_HEXPAT,
	} {
		c := pc.Control & ex
		if c != 0 && c != (c&(^c+1)) {
			r.showControls(c, 0, "** Not allowed together:")
			r.printf("\n")
			return prSkip
		}
	}
	if pc.Jit == 0 && pc.Control&(mods.CTL_JITVERIFY|mods.CTL_JITFAST) != 0 {
		pc.Jit = 7
	}

	// Hex or expanded patterns.
	patlen := len(pat)
	switch {
	case pc.Control&mods.CTL_HEXPAT != 0:
		var out []byte
		src := buf[1:]
		// the C code walks buffer+1 until NUL, which includes the modifier
		// text after the pattern's own terminating NUL? No: the NUL placed at
		// the closing delimiter ends it, so only the pattern text is walked.
		src = pat
		for i := 0; i < len(src); i++ {
			if isSpace(src[i]) {
				continue
			}
			c := src[i]
			i++
			if c == '\'' || c == '"' {
				q := i
				for ; ; i++ {
					if i >= len(src) {
						r.printf("** Missing closing quote in hex pattern: opening quote is at offset %d.\n", q-1)
						return prSkip
					}
					if src[i] == c {
						break
					}
					out = append(out, src[i])
				}
				continue
			}
			if !isXDigit(c) {
				r.printf("** Unexpected non-hex-digit '%c' at offset %d in hex pattern: quote missing?\n", c, i-1)
				return prSkip
			}
			if i >= len(src) {
				r.printf("** Odd number of digits in hex pattern\n")
				return prSkip
			}
			d := src[i]
			if !isXDigit(d) {
				r.printf("** Unexpected non-hex-digit '%c' at offset %d in hex pattern: quote missing?\n", d, i)
				return prSkip
			}
			out = append(out, hexVal(c)<<4|hexVal(d))
		}
		pat = out
		patlen = len(pat)
	case pc.Control&mods.CTL_EXPAND != 0:
		var out []byte
		for i := 0; i < len(pat); i++ {
			pcIdx := i
			count := 1
			length := 1
			if pat[i] == '\\' && at(pat, i+1) == '[' {
				for pe := i + 2; pe < len(pat); pe++ {
					if pat[pe] == ']' && at(pat, pe+1) == '{' {
						clen := pe - pcIdx - 2
						pe += 2
						v, e := atoi(pat, pe)
						if v > 0xffffffff {
							r.printf("** Pattern repeat count too large\n")
							return prSkip
						}
						pe = e
						if at(pat, pe) == '}' {
							if v == 0 {
								r.printf("** Zero repeat not allowed\n")
								return prSkip
							}
							pcIdx += 2
							count = int(v)
							length = clen
							i = pe
							break
						}
					}
				}
			}
			for len(out)+count*length > r.pbufSize {
				r.pbufSize *= 2 // expand_input_buffers()
			}
			for ; count > 0; count-- {
				out = append(out, pat[pcIdx:pcIdx+length]...)
			}
		}
		pat = out
		patlen = len(pat)
		if pc.Control&mods.CTL_INFO != 0 {
			r.printf("Expanded: %s\n", pat)
		}
	}
	_ = patlen
	if pat == nil {
		pat = []byte{}
	}

	// Character tables.
	if pc.Locale != "" {
		if pc.TablesID != 0 {
			r.printf("** 'Locale' and 'tables' must not both be set\n")
			return prSkip
		}
		r.unsup("locale")
		return prSkip
	}
	switch pc.TablesID {
	case 0:
	case 1, 2:
		r.unsup("character tables (tables=1/2)")
	case 3:
		r.unsup("binary tables (tables=3)")
		return prSkip
	default:
		r.printf("** 'Tables' must specify 0, 1, 2, or 3.\n")
		return prSkip
	}
	if pc.Stackguard != 0 {
		r.unsup("stackguard")
	}

	if pc.Control&mods.CTL_POSIX != 0 {
		r.unsup("POSIX interface")
		return prSkip
	}

	if pc.Control&(mods.CTL_PUSH|mods.CTL_PUSHCOPY|mods.CTL_PUSHTABLESCOPY) != 0 {
		r.unsup("pattern stack (push)")
	}
	if pc.ConvertType != mods.ConvertUnset {
		var rc int
		if pat, rc = r.convertPattern(pat, utf); rc != prOK {
			return rc
		}
	}

	if pc.Control2&mods.CTL2_NL_SET == 0 && r.localNL != 0 {
		r.cc.Newline = r.localNL
	}
	useForbid := r.forbidUTF
	if pc.Options&mods.LITERAL != 0 {
		useForbid = 0
	}

	// null_pattern passes a NULL pattern; with a zero-terminated pattern (the
	// default) C reports "NULL with non-zero length", which a nil Go slice
	// stands for. With use_length or hex the length is given (0 here) and NULL
	// is accepted as an empty pattern, which an empty non-nil slice stands for.
	if pc.Control2&mods.CTL2_NULL_PATTERN != 0 && pc.Control&(mods.CTL_HEXPAT|mods.CTL_USE_LENGTH) != 0 && len(pat) > 0 {
		r.unsup("NULL pattern with non-zero length (null_pattern)")
		return prSkip
	}
	cs := CompileSettings{CompileCtx: r.cc, Null: pc.Control&mods.CTL_NULLCONTEXT != 0,
		NullPattern: pc.Control2&mods.CTL2_NULL_PATTERN != 0 && pc.Control&(mods.CTL_HEXPAT|mods.CTL_USE_LENGTH) == 0}
	code, errorcode, erroroffset := r.lib.Compile(pat, pc.Options|useForbid, cs)

	jitrc := 0
	if code != nil && pc.Jit != 0 {
		jitrc = errJITBadOption
		if pc.Control&mods.CTL_JITVERIFY != 0 {
			r.printf("JIT compilation was not successful")
			if !r.printError(jitrc, " (", ")\n") {
				return prAbend
			}
		}
	}

	if code == nil {
		r.printf("Failed: error %d at offset %d: ", errorcode, int(erroroffset))
		if !r.printError(errorcode, "", "\n") {
			return prAbend
		}
		return prSkip
	}
	r.code = code
	r.dfaMatched = 0
	r.utf = false
	if v, rc := code.Info(infoAllOptions); rc == 0 {
		r.utf = uint32(v)&mods.UTF != 0
	}
	_ = utf
	r.patBytes = pat

	ex := code.Extra()
	if r.forbidUTF != 0 && ex.HasBkPorX {
		r.printf("** \\P, \\p, and \\X are not allowed after the #forbid_utf command\n")
		return prSkip
	}
	r.hasCallout = ex.HasCallout || pc.Options&mods.AUTO_CALLOUT != 0

	if v, rc := r.patternInfo(infoMaxLookbehind, false); rc != 0 {
		return prAbend
	} else {
		r.maxLookbhind = uint32(v)
	}
	if v, rc := r.patternInfo(infoCaptureCount, false); rc < 0 {
		return prAbend
	} else {
		r.maxCapCount = uint32(v)
	}

	if pc.Control&mods.CTL_MEMORY != 0 {
		r.showMemoryInfo()
	}
	if pc.Control2&mods.CTL2_FRAMESIZE != 0 {
		r.showFrameSize()
	}
	if pc.Control&mods.CTL_ANYINFO != 0 {
		if rc := r.showPatternInfo(jitrc); rc != prOK {
			return rc
		}
	}
	if pc.Control&mods.CTL_PUSH != 0 {
		r.code.Free()
		r.code = nil
	}
	return prOK
}

func isXDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	return c - 'A' + 10
}

func atoi(b []byte, i int) (uint64, int) {
	var v uint64
	for i < len(b) && b[i] >= '0' && b[i] <= '9' {
		if v > (^uint64(0)-9)/10 {
			v = ^uint64(0)
		} else {
			v = v*10 + uint64(b[i]-'0')
		}
		i++
	}
	return v, i
}

func (r *Runner) printError(code int, before, after string) bool {
	msg, ok := r.lib.ErrorMessage(code)
	if !ok {
		r.printf("\n** pcre2test internal error: cannot interpret error number\n** Unexpected return (%d) from pcre2_get_error_message()\n", errBadDataLen)
		return false
	}
	r.printf("%s%s%s", before, msg, after)
	return true
}

// errBadDataLen is PCRE2_ERROR_BADDATA, the "length" pcre2_get_error_message
// returns for an unknown error number.
const errBadDataLen = -29

func (r *Runner) patternInfo(what uint32, unsetOK bool) (uint64, int) {
	v, rc := r.code.Info(what)
	if rc >= 0 {
		return v, 0
	}
	if rc != errUnset || !unsetOK {
		r.printf("Error %d from pcre2_pattern_info_8(%d)\n", rc, what)
	}
	return v, rc
}

func (r *Runner) showControls(controls, controls2 uint32, before string) {
	names := []struct {
		on   bool
		name string
	}{
		{controls&mods.CTL_AFTERTEXT != 0, " aftertext"},
		{controls&mods.CTL_ALLAFTERTEXT != 0, " allaftertext"},
		{controls&mods.CTL_ALLCAPTURES != 0, " allcaptures"},
		{controls&mods.CTL_ALLUSEDTEXT != 0, " allusedtext"},
		{controls2&mods.CTL2_ALLVECTOR != 0, " allvector"},
		{controls&mods.CTL_ALTGLOBAL != 0, " altglobal"},
		{controls&mods.CTL_BINCODE != 0, " bincode"},
		{controls2&mods.CTL2_BSR_SET != 0, " bsr"},
		{controls&mods.CTL_CALLOUT_CAPTURE != 0, " callout_capture"},
		{controls2&mods.CTL2_CALLOUT_EXTRA != 0, " callout_extra"},
		{controls&mods.CTL_CALLOUT_INFO != 0, " callout_info"},
		{controls&mods.CTL_CALLOUT_NONE != 0, " callout_none"},
		{controls2&mods.CTL2_CALLOUT_NO_WHERE != 0, " callout_no_where"},
		{controls&mods.CTL_DFA != 0, " dfa"},
		{controls&mods.CTL_EXPAND != 0, " expand"},
		{controls&mods.CTL_FINDLIMITS != 0, " find_limits"},
		{controls&mods.CTL_FINDLIMITS_NOHEAP != 0, " find_limits_noheap"},
		{controls2&mods.CTL2_FRAMESIZE != 0, " framesize"},
		{controls&mods.CTL_FULLBINCODE != 0, " fullbincode"},
		{controls&mods.CTL_GETALL != 0, " getall"},
		{controls&mods.CTL_GLOBAL != 0, " global"},
		{controls2&mods.CTL2_HEAPFRAMES_SIZE != 0, " heapframes_size"},
		{controls&mods.CTL_HEXPAT != 0, " hex"},
		{controls&mods.CTL_INFO != 0, " info"},
		{controls&mods.CTL_JITFAST != 0, " jitfast"},
		{controls&mods.CTL_JITVERIFY != 0, " jitverify"},
		{controls&mods.CTL_MARK != 0, " mark"},
		{controls&mods.CTL_MEMORY != 0, " memory"},
		{controls2&mods.CTL2_NL_SET != 0, " newline"},
		{controls&mods.CTL_NULLCONTEXT != 0, " null_context"},
		{controls2&mods.CTL2_NULL_REPLACEMENT != 0, " null_replacement"},
		{controls2&mods.CTL2_NULL_SUBJECT != 0, " null_subject"},
		{controls&mods.CTL_POSIX != 0, " posix"},
		{controls&mods.CTL_POSIX_NOSUB != 0, " posix_nosub"},
		{controls&mods.CTL_PUSH != 0, " push"},
		{controls&mods.CTL_PUSHCOPY != 0, " pushcopy"},
		{controls&mods.CTL_PUSHTABLESCOPY != 0, " pushtablescopy"},
		{controls&mods.CTL_STARTCHAR != 0, " startchar"},
		{controls2&mods.CTL2_SUBSTITUTE_CALLOUT != 0, " substitute_callout"},
		{controls2&mods.CTL2_SUBSTITUTE_EXTENDED != 0, " substitute_extended"},
		{controls2&mods.CTL2_SUBSTITUTE_LITERAL != 0, " substitute_literal"},
		{controls2&mods.CTL2_SUBSTITUTE_MATCHED != 0, " substitute_matched"},
		{controls2&mods.CTL2_SUBSTITUTE_OVERFLOW_LENGTH != 0, " substitute_overflow_length"},
		{controls2&mods.CTL2_SUBSTITUTE_REPLACEMENT_ONLY != 0, " substitute_replacement_only"},
		{controls2&mods.CTL2_SUBSTITUTE_UNKNOWN_UNSET != 0, " substitute_unknown_unset"},
		{controls2&mods.CTL2_SUBSTITUTE_UNSET_EMPTY != 0, " substitute_unset_empty"},
		{controls&mods.CTL_USE_LENGTH != 0, " use_length"},
		{controls&mods.CTL_UTF8_INPUT != 0, " utf8_input"},
		{controls&mods.CTL_ZERO_TERMINATE != 0, " zero_terminate"},
	}
	r.printf("%s", before)
	for _, n := range names {
		if n.on {
			r.printf("%s", n.name)
		}
	}
}

func (r *Runner) showCompileOptions(options uint32, before, after string) {
	if options == 0 {
		r.printf("%s <none>%s", before, after)
		return
	}
	names := []struct {
		bit  uint32
		name string
	}{
		{mods.ALT_BSUX, " alt_bsux"}, {mods.ALT_CIRCUMFLEX, " alt_circumflex"}, {mods.ALT_VERBNAMES, " alt_verbnames"},
		{mods.ALLOW_EMPTY_CLASS, " allow_empty_class"}, {mods.ANCHORED, " anchored"}, {mods.AUTO_CALLOUT, " auto_callout"},
		{mods.CASELESS, " caseless"}, {mods.DOLLAR_ENDONLY, " dollar_endonly"}, {mods.DOTALL, " dotall"},
		{mods.DUPNAMES, " dupnames"}, {mods.ENDANCHORED, " endanchored"}, {mods.EXTENDED, " extended"},
		{mods.EXTENDED_MORE, " extended_more"}, {mods.FIRSTLINE, " firstline"}, {mods.LITERAL, " literal"},
		{mods.MATCH_INVALID_UTF, " match_invalid_utf"}, {mods.MATCH_UNSET_BACKREF, " match_unset_backref"},
		{mods.MULTILINE, " multiline"}, {mods.NEVER_BACKSLASH_C, " never_backslash_c"}, {mods.NEVER_UCP, " never_ucp"},
		{mods.NEVER_UTF, " never_utf"}, {mods.NO_AUTO_CAPTURE, " no_auto_capture"}, {mods.NO_AUTO_POSSESS, " no_auto_possess"},
		{mods.NO_DOTSTAR_ANCHOR, " no_dotstar_anchor"}, {mods.NO_UTF_CHECK, " no_utf_check"},
		{mods.NO_START_OPTIMIZE, " no_start_optimize"}, {mods.UCP, " ucp"}, {mods.UNGREEDY, " ungreedy"},
		{mods.USE_OFFSET_LIMIT, " use_offset_limit"}, {mods.UTF, " utf"},
	}
	r.printf("%s", before)
	for _, n := range names {
		if options&n.bit != 0 {
			r.printf("%s", n.name)
		}
	}
	r.printf("%s", after)
}

func (r *Runner) showExtraOptions(options uint32, before, after string) {
	if options == 0 {
		r.printf("%s <none>%s", before, after)
		return
	}
	names := []struct {
		bit  uint32
		name string
	}{
		{mods.EXTRA_ALLOW_SURROGATE_ESCAPES, " allow_surrogate_escapes"}, {mods.EXTRA_ALT_BSUX, " alt_bsux"},
		{mods.EXTRA_ASCII_BSD, " ascii_bsd"}, {mods.EXTRA_ASCII_BSS, " ascii_bss"}, {mods.EXTRA_ASCII_BSW, " ascii_bsw"},
		{mods.EXTRA_ASCII_DIGIT, " ascii_digit"}, {mods.EXTRA_ASCII_POSIX, " ascii_posix"},
		{mods.EXTRA_BAD_ESCAPE_IS_LITERAL, " bad_escape_is_literal"}, {mods.EXTRA_CASELESS_RESTRICT, " caseless_restrict"},
		{mods.EXTRA_ESCAPED_CR_IS_LF, " escaped_cr_is_lf"}, {mods.EXTRA_MATCH_WORD, " match_word"}, {mods.EXTRA_MATCH_LINE, " match_line"},
	}
	r.printf("%s", before)
	for _, n := range names {
		if options&n.bit != 0 {
			r.printf("%s", n.name)
		}
	}
	r.printf("%s", after)
}

func printOK(c uint32) bool { return c >= 32 && c < 127 }

// showPatternInfo ports show_pattern_info() for an 8-bit non-JIT build.
func (r *Runner) showPatternInfo(jitrc int) int {
	pc := &r.patCtl
	if pc.Control&(mods.CTL_BINCODE|mods.CTL_FULLBINCODE) != 0 {
		r.printf("------------------------------------------------------------------\n")
		if d, ok := r.code.(CodeDumper); ok {
			r.printf("%s", d.PrintInt(pc.Control&mods.CTL_FULLBINCODE != 0))
		} else {
			r.unsup("compiled code dump (bincode/fullbincode)")
		}
	}
	if pc.Control&mods.CTL_INFO != 0 {
		var heapLimit, matchLimit, depthLimit uint64
		var heapSet, matchSet, depthSet bool
		get := func(what uint32, set *bool, v *uint64) bool {
			x, rc := r.patternInfo(what, true)
			switch rc {
			case 0:
				*set = true
				*v = x
			case errUnset:
				*set = false
			default:
				return false
			}
			return true
		}
		if !get(infoHeapLimit, &heapSet, &heapLimit) || !get(infoMatchLimit, &matchSet, &matchLimit) || !get(infoDepthLimit, &depthSet, &depthLimit) {
			return prAbend
		}
		var failed int
		must := func(what uint32) uint64 {
			x, rc := r.patternInfo(what, false)
			if rc != 0 {
				failed++
			}
			return x
		}
		backrefmax := must(infoBackrefMax)
		bsr := must(infoBSR)
		captureCount := must(infoCaptureCount)
		firstCunit := must(infoFirstCodeUnit)
		firstCtype := must(infoFirstCodeType)
		hasBackslashC := must(infoHasBackslashC)
		hasCrOrLf := must(infoHasCrOrLf)
		jchanged := must(infoJChanged)
		lastCunit := must(infoLastCodeUnit)
		lastCtype := must(infoLastCodeType)
		matchEmpty := must(infoMatchEmpty)
		minLength := must(infoMinLength)
		nameCount := must(infoNameCount)
		nameEntrySize := must(infoNameEntrySize)
		newlineConv := must(infoNewline)
		if failed != 0 {
			return prAbend
		}
		ex := r.code.Extra()
		if !ex.Known {
			r.unsup("compiled-code internals (first/last caseless, start bits, NL/BSR set)")
		}

		r.printf("Capture group count = %d\n", captureCount)
		if backrefmax > 0 {
			r.printf("Max back reference = %d\n", backrefmax)
		}
		if r.maxLookbhind > 0 {
			r.printf("Max lookbehind = %d\n", r.maxLookbhind)
		}
		if heapSet {
			r.printf("Heap limit = %d\n", heapLimit)
		}
		if matchSet {
			r.printf("Match limit = %d\n", matchLimit)
		}
		if depthSet {
			r.printf("Depth limit = %d\n", depthLimit)
		}
		if nameCount > 0 {
			r.printf("Named capture groups:\n")
			table, _, _ := r.code.NameTable()
			const imm2 = 2
			for ; nameCount > 0; nameCount-- {
				if len(table) < imm2 {
					break
				}
				nm := table[imm2:]
				if i := bytes.IndexByte(nm, 0); i >= 0 {
					nm = nm[:i]
				}
				length := uint64(len(nm))
				r.printf("  ")
				if r.utf {
					r.out.Write(nm)
				} else {
					pchars(nm, false, r.out)
				}
				for ; length < nameEntrySize-imm2; length++ {
					r.out.WriteByte(' ')
				}
				r.printf("%3d\n", int(table[0])<<8|int(table[1]))
				if uint64(len(table)) >= nameEntrySize {
					table = table[nameEntrySize:]
				} else {
					table = nil
				}
			}
		}
		if hasCrOrLf != 0 {
			r.printf("Contains explicit CR or LF match\n")
		}
		if hasBackslashC != 0 {
			r.printf("Contains \\C\n")
		}
		if matchEmpty != 0 {
			r.printf("May match empty string\n")
		}

		var compileOptions, overallOptions, extraOptions uint32
		if v, _ := r.patternInfo(infoArgOptions, false); true {
			compileOptions = uint32(v)
		}
		if v, _ := r.patternInfo(infoAllOptions, false); true {
			overallOptions = uint32(v)
		}
		if v, _ := r.patternInfo(infoExtraOptions, false); true {
			extraOptions = uint32(v)
		}
		if pc.Options&mods.NEVER_UTF == 0 {
			compileOptions &^= mods.NEVER_UTF
			overallOptions &^= mods.NEVER_UTF
		}
		if pc.Options&mods.NEVER_UCP == 0 {
			compileOptions &^= mods.NEVER_UCP
			overallOptions &^= mods.NEVER_UCP
		}
		if compileOptions|overallOptions != 0 {
			if compileOptions == overallOptions {
				r.showCompileOptions(compileOptions, "Options:", "\n")
			} else {
				r.showCompileOptions(compileOptions, "Compile options:", "\n")
				r.showCompileOptions(overallOptions, "Overall options:", "\n")
			}
		}
		if extraOptions != 0 {
			r.showExtraOptions(extraOptions, "Extra options:", "\n")
		}
		if jchanged != 0 {
			r.printf("Duplicate name status changes\n")
		}
		if pc.Control2&mods.CTL2_BSR_SET != 0 || ex.BSRSet {
			if bsr == mods.BSR_UNICODE {
				r.printf("\\R matches any Unicode newline\n")
			} else {
				r.printf("\\R matches CR, LF, or CRLF\n")
			}
		}
		if pc.Control2&mods.CTL2_NL_SET != 0 || ex.NLSet {
			switch newlineConv {
			case mods.NEWLINE_CR:
				r.printf("Forced newline is CR\n")
			case mods.NEWLINE_LF:
				r.printf("Forced newline is LF\n")
			case mods.NEWLINE_CRLF:
				r.printf("Forced newline is CRLF\n")
			case mods.NEWLINE_ANYCRLF:
				r.printf("Forced newline is CR, LF, or CRLF\n")
			case mods.NEWLINE_ANY:
				r.printf("Forced newline is any Unicode newline\n")
			case mods.NEWLINE_NUL:
				r.printf("Forced newline is NUL\n")
			}
		}
		if firstCtype == 2 {
			r.printf("First code unit at start or follows newline\n")
		} else if firstCtype == 1 {
			cl := ""
			if ex.FirstCaseless {
				cl = " (caseless)"
			}
			if printOK(uint32(firstCunit)) {
				r.printf("First code unit = '%c'%s\n", firstCunit, cl)
			} else {
				r.printf("First code unit = ")
				pchar(uint32(firstCunit), false, r.out)
				r.printf("%s\n", cl)
			}
		} else if ex.StartBits != nil {
			c := 24
			r.printf("Starting code units: ")
			for i := 0; i < 256; i++ {
				if ex.StartBits[i/8]&(1<<(uint(i)&7)) != 0 {
					if c > 75 {
						r.printf("\n  ")
						c = 2
					}
					if printOK(uint32(i)) && i != ' ' {
						r.printf("%c ", i)
						c += 2
					} else {
						r.printf("\\x%02x ", i)
						c += 5
					}
				}
			}
			r.printf("\n")
		}
		if lastCtype != 0 {
			cl := ""
			if ex.LastCaseless {
				cl = " (caseless)"
			}
			if printOK(uint32(lastCunit)) {
				r.printf("Last code unit = '%c'%s\n", lastCunit, cl)
			} else {
				r.printf("Last code unit = ")
				pchar(uint32(lastCunit), false, r.out)
				r.printf("%s\n", cl)
			}
		}
		if overallOptions&mods.NO_START_OPTIMIZE == 0 {
			r.printf("Subject length lower bound = %d\n", int(minLength))
		}
		if pc.Jit != 0 && pc.Control&mods.CTL_JITVERIFY != 0 {
			r.printf("JIT support is not available in this version of PCRE2\n")
		}
	}
	if pc.Control&mods.CTL_CALLOUT_INFO != 0 {
		if rc := r.calloutEnumerate(); rc != prOK {
			return rc
		}
	}
	_ = jitrc
	return prOK
}
