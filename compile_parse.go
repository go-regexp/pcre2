// Port of parse_regex() of pcre2_compile.c (PCRE2 10.44, 8-bit): the first
// pass over the pattern, which writes the parsed pattern (a META_ stream of
// uint32) and the table of named groups.
//
// Pointer conventions of this file: a pattern pointer is an int index into
// pat (which is cb.startPattern, so an index is also the C offset
// ptr - cb->start_pattern); a parsed_pattern pointer is an int index into
// cb.parsedPattern; a NULL parsed_pattern pointer is -1.
package pcre2

import "runtime"

// nest_save is the structure for dealing with nested groups
// (pcre2_compile.c:2725-2732).
type nest_save struct {
	nestDepth  uint16
	resetGroup uint16
	maxGroup   uint16
	flags      uint16
	options    uint32
	xoptions   uint32
}

// Nest save flags (pcre2_compile.c:2734-2736).
const (
	NSF_RESET      = 0x0001
	NSF_CONDASSERT = 0x0002
	NSF_ATOMICSR   = 0x0004
)

// Options that are tracked during parsing (pcre2_compile.c:2743-2749).
const (
	PARSE_TRACKED_OPTIONS = PCRE2_CASELESS | PCRE2_DOTALL | PCRE2_DUPNAMES |
		PCRE2_EXTENDED | PCRE2_EXTENDED_MORE | PCRE2_MULTILINE | PCRE2_NO_AUTO_CAPTURE |
		PCRE2_UNGREEDY

	PARSE_TRACKED_EXTRA_OPTIONS = PCRE2_EXTRA_CASELESS_RESTRICT |
		PCRE2_EXTRA_ASCII_BSD | PCRE2_EXTRA_ASCII_BSS | PCRE2_EXTRA_ASCII_BSW |
		PCRE2_EXTRA_ASCII_DIGIT | PCRE2_EXTRA_ASCII_POSIX
)

// States used for analyzing ranges in character classes (pcre2_compile.c:2754).
const (
	RANGE_NO = iota
	RANGE_STARTED
	RANGE_OK_ESCAPED
	RANGE_OK_LITERAL
)

// parse_putoffset is PUTOFFSET (64-bit PCRE2_SIZE: two elements,
// pcre2_compile.c:99-100). It returns the advanced index.
func parse_putoffset(pp []uint32, p int, offset uint64) int {
	pp[p] = uint32(offset >> 32)
	pp[p+1] = uint32(offset & 0xffffffff)
	return p + 2
}

func parse_isdigit(c byte) bool { return c >= '0' && c <= '9' }

// parse_manage_callouts is manage_callouts() (pcre2_compile.c:2594); a private
// copy so that this file does not depend on the argument layout of the
// original. previous callout -1 means NULL.
func parse_manage_callouts(ptr int, pcalloutptr *int, autoCallout bool, pp int, cb *compile_block) int {
	parsed := cb.parsedPattern
	previous := *pcalloutptr
	if previous >= 0 {
		parsed[previous+2] = uint32(uint64(ptr) - uint64(parsed[previous+1]))
	}
	if !autoCallout {
		previous = -1
	} else {
		if previous < 0 || previous != pp-4 || parsed[previous+3] != 255 {
			previous = pp
			pp += 4
			parsed[previous] = META_CALLOUT_NUMBER
			parsed[previous+2] = 0
			parsed[previous+3] = 255
		}
		parsed[previous+1] = uint32(ptr)
	}
	*pcalloutptr = previous
	return pp
}

// parse_handle_escdsw is handle_escdsw() (pcre2_compile.c:2641).
func parse_handle_escdsw(escape int, pp int, options, xoptions uint32, cb *compile_block) int {
	parsed := cb.parsedPattern
	var asciiOption uint32
	prop := ESC_p
	switch escape {
	case ESC_D:
		prop = ESC_P
		asciiOption = PCRE2_EXTRA_ASCII_BSD
	case ESC_d:
		asciiOption = PCRE2_EXTRA_ASCII_BSD
	case ESC_S:
		prop = ESC_P
		asciiOption = PCRE2_EXTRA_ASCII_BSS
	case ESC_s:
		asciiOption = PCRE2_EXTRA_ASCII_BSS
	case ESC_W:
		prop = ESC_P
		asciiOption = PCRE2_EXTRA_ASCII_BSW
	case ESC_w:
		asciiOption = PCRE2_EXTRA_ASCII_BSW
	}
	if options&PCRE2_UCP == 0 || xoptions&asciiOption != 0 {
		parsed[pp] = META_ESCAPE + uint32(escape)
		pp++
	} else {
		parsed[pp] = META_ESCAPE + uint32(prop)
		pp++
		switch escape {
		case ESC_d, ESC_D:
			parsed[pp] = PT_PC<<16 | ucp_Nd
			pp++
		case ESC_s, ESC_S:
			parsed[pp] = PT_SPACE << 16
			pp++
		case ESC_w, ESC_W:
			parsed[pp] = PT_WORD << 16
			pp++
		}
	}
	return pp
}

// parse_regex is parse_regex() (pcre2_compile.c:2773). pat is cb.startPattern
// and ptr the index where scanning starts (the pattern ends at cb.endPattern).
// It returns zero on success or a non-zero error code, with the error offset
// placed in cb.erroroffset. A write beyond the parsed pattern buffer (which
// the C code prevents by sizing) is reported as ERR63, never a panic.
func parse_regex(pat []byte, ptr int, options uint32, hasLookbehind *bool, cb *compile_block) (rc int) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(runtime.Error); ok {
				cb.erroroffset = uint64(ptr)
				rc = ERR63 // internal error (parsed pattern overflow)
				return
			}
			panic(r)
		}
	}()

	var (
		c                uint32
		delimiter        uint32
		namelen          uint32
		classRangeState  uint32
		verblengthptr    = -1
		verbstartptr     = -1
		previousCallout  = -1
		parsed           = cb.parsedPattern
		pp               = 0 // parsed_pattern (index)
		parsedPatternEnd = cb.parsedPatternEnd
		thisParsedItem   = -1
		prevParsedItem   = -1
		metaQuantifier   uint32
		addAfterMark     uint32
		xoptions         = cb.cx.extraOptions
		nestDepth        uint16
		afterManual      int
		expectCondAssert int
		errorcode        int
		escape           int
		i                int
		inescq           bool
		inverbname       bool
		utf              = options&PCRE2_UTF != 0
		autoCallout      = options&PCRE2_AUTO_CALLOUT != 0
		isdupname        bool
		negateClass      bool
		okquantifier     bool
		thisptr          int
		name             int
		ptrend           = cb.endPattern
		verbnamestart    int
		topNest          = -1
		nests            []nest_save
	)

	// byte at index i, 0 beyond the end (C reads the terminator).
	at := func(i int) byte { return cuAt(pat, i) }
	fail := func(e int) int {
		errorcode = e
		cb.erroroffset = uint64(ptr)
		return e
	}
	failBack := func(e int) int {
		ptr--
		return fail(e)
	}
	putLiteral := func(v uint32) {
		parsed[pp] = v
		pp++
		okquantifier = true
	}
	put := func(v uint32) {
		parsed[pp] = v
		pp++
	}
	isNewline := func(p int) bool {
		if cb.nltype != NLTYPE_FIXED {
			if p < ptrend {
				ok, l := is_newline(pat, p, cb.nltype, ptrend, utf)
				if ok {
					cb.nllen = l
					return true
				}
			}
			return false
		}
		return p <= ptrend-int(cb.nllen) && pat[p] == cb.nl[0] &&
			(cb.nllen == 1 || at(p+1) == cb.nl[1])
	}

	// nest stack: its capacity is that of the C workspace (pcre2_compile.c:2849-2856).
	nestMax := int(cb.workspaceSize / 16)
	pushNest := func(flags uint16) bool { // the common "top_nest" creation
		if topNest < 0 {
			topNest = 0
		} else if topNest+1 >= nestMax {
			return false
		} else {
			topNest++
		}
		for len(nests) <= topNest {
			nests = append(nests, nest_save{})
		}
		nests[topNest] = nest_save{nestDepth: nestDepth, flags: flags,
			options: options & PARSE_TRACKED_OPTIONS, xoptions: xoptions & PARSE_TRACKED_EXTRA_OPTIONS}
		return true
	}

	// Insert leading items for word and line matching.
	if xoptions&PCRE2_EXTRA_MATCH_LINE != 0 {
		put(META_CIRCUMFLEX)
		put(META_NOCAPTURE)
	} else if xoptions&PCRE2_EXTRA_MATCH_WORD != 0 {
		put(META_ESCAPE + ESC_b)
		put(META_NOCAPTURE)
	}

	// finish is the code from PARSED_END (pcre2_compile.c:4989) on.
	finish := func() int {
		pp = parse_manage_callouts(ptr, &previousCallout, autoCallout, pp, cb)
		if xoptions&PCRE2_EXTRA_MATCH_LINE != 0 {
			put(META_KET)
			put(META_DOLLAR)
		} else if xoptions&PCRE2_EXTRA_MATCH_WORD != 0 {
			put(META_KET)
			put(META_ESCAPE + ESC_b)
		}
		if pp >= parsedPatternEnd {
			return fail(ERR63)
		}
		parsed[pp] = META_END
		if nestDepth == 0 {
			return 0
		}
		return fail(ERR14) // UNCLOSED_PARENTHESIS
	}

	// A literal pattern is processed separately (pcre2_compile.c:2827).
	if options&PCRE2_LITERAL != 0 {
		for ptr < ptrend {
			if pp >= parsedPatternEnd {
				return fail(ERR63)
			}
			thisptr = ptr
			c, ptr = GETCHARINCTEST(utf, pat, ptr)
			if autoCallout {
				pp = parse_manage_callouts(thisptr, &previousCallout, autoCallout, pp, cb)
			}
			putLiteral(c)
		}
		return finish() // PARSED_END
	}

	// PCRE2_EXTENDED_MORE implies PCRE2_EXTENDED
	if options&PCRE2_EXTENDED_MORE != 0 {
		options |= PCRE2_EXTENDED
	}

	// setRecursion is SET_RECURSION (pcre2_compile.c:4428).
	setRecursion := func(n int) {
		put(META_RECURSE | uint32(n))
		offset := uint64(ptr)
		ptr++
		pp = parse_putoffset(parsed, pp, offset)
		okquantifier = true
	}

mainLoop:
	for ptr < ptrend {
		var (
			prevExpectCondAssert int
			minRepeat, maxRepeat uint32
			terminator           uint32
			prevMetaQuantifier   uint32
			prevOkquantifier     bool
			tempptr              int
			offset               uint64
		)

		if pp >= parsedPatternEnd {
			return fail(ERR63)
		}
		if uint32(nestDepth) > cb.cx.parensNestLimit {
			return fail(ERR19)
		}

		if thisParsedItem != pp {
			prevParsedItem = thisParsedItem
			thisParsedItem = pp
		}

		thisptr = ptr
		c, ptr = GETCHARINCTEST(utf, pat, ptr)

		// Copy quoted literals until \E.
		if inescq {
			if c == CHAR_BACKSLASH && ptr < ptrend && pat[ptr] == CHAR_E {
				inescq = false
				ptr++
			} else {
				if expectCondAssert > 0 {
					ptr--
					return fail(ERR28)
				}
				if inverbname {
					put(c)
				} else {
					t := afterManual
					afterManual--
					if t <= 0 {
						pp = parse_manage_callouts(thisptr, &previousCallout, autoCallout, pp, cb)
					}
					putLiteral(c)
				}
				metaQuantifier = 0
			}
			continue
		}

		// The "name" part of a (*VERB:NAME) item.
		if inverbname &&
			(options&(PCRE2_EXTENDED|PCRE2_ALT_VERBNAMES) != (PCRE2_EXTENDED|PCRE2_ALT_VERBNAMES) ||
				(c > 255 && (c|1) != 0x200f && (c|1) != 0x2029) ||
				(c < 256 && c != CHAR_NUMBER_SIGN && cb.ctypes[c]&ctype_space == 0 && c != CHAR_NEL)) {

			switch c {
			default:
				put(c)

			case CHAR_RIGHT_PARENTHESIS:
				inverbname = false
				verbnamelength := uint32(pp - verblengthptr - 1)
				if ptr-verbnamestart-1 > int(MAX_MARK) {
					ptr--
					return fail(ERR76)
				}
				parsed[verblengthptr] = verbnamelength
				if addAfterMark != 0 {
					put(addAfterMark)
					addAfterMark = 0
				}

			case CHAR_BACKSLASH:
				if options&PCRE2_ALT_VERBNAMES != 0 {
					escape = check_escape(pat, &ptr, ptrend, &c, &errorcode, options, xoptions, false, cb)
					if errorcode != 0 {
						return fail(errorcode)
					}
				} else {
					escape = 0
				}
				switch escape {
				case 0:
					put(c)
				case ESC_ub:
					put(CHAR_u)
					putLiteral(CHAR_LEFT_CURLY_BRACKET)
				case ESC_Q:
					inescq = true
				case ESC_E:
					// ignore
				default:
					return fail(ERR40)
				}
			}
			continue
		}

		// \Q and \E are handled here so that A\Q\E+ is A+.
		if c == CHAR_BACKSLASH && ptr < ptrend {
			if pat[ptr] == CHAR_Q || pat[ptr] == CHAR_E {
				inescq = pat[ptr] == CHAR_Q
				ptr++
				continue
			}
		}

		// Skip over whitespace and # comments in extended mode.
		if options&PCRE2_EXTENDED != 0 {
			if c < 256 && cb.ctypes[c]&ctype_space != 0 {
				continue
			}
			if c == CHAR_NEL || (c|1) == 0x200f || (c|1) == 0x2029 {
				continue
			}
			if c == CHAR_NUMBER_SIGN {
				for ptr < ptrend {
					if isNewline(ptr) {
						ptr += int(cb.nllen)
						break
					}
					ptr++
					if utf {
						ptr = FORWARDCHARTEST(pat, ptr, ptrend)
					}
				}
				continue
			}
		}

		// Skip over bracketed comments
		if c == CHAR_LEFT_PARENTHESIS && ptrend-ptr >= 2 &&
			pat[ptr] == CHAR_QUESTION_MARK && pat[ptr+1] == CHAR_NUMBER_SIGN {
			for {
				ptr++
				if !(ptr < ptrend && pat[ptr] != CHAR_RIGHT_PARENTHESIS) {
					break
				}
			}
			if ptr >= ptrend {
				return fail(ERR18)
			}
			ptr++
			continue
		}

		// If the next item is not a quantifier, fill in length of any previous
		// callout and create an auto callout if required.
		isQuant := c == CHAR_ASTERISK || c == CHAR_PLUS || c == CHAR_QUESTION_MARK
		if !isQuant && c == CHAR_LEFT_CURLY_BRACKET {
			tempptr = ptr
			isQuant = read_repeat_counts(pat, &tempptr, ptrend, nil, nil, &errorcode)
		}
		if !isQuant {
			t := afterManual
			afterManual--
			if t <= 0 {
				pp = parse_manage_callouts(thisptr, &previousCallout, autoCallout, pp, cb)
				thisParsedItem = pp
			}
		}

		// Expecting a conditional assertion?
		if expectCondAssert > 0 {
			ok := c == CHAR_LEFT_PARENTHESIS && ptrend-ptr >= 3 &&
				(at(ptr) == CHAR_QUESTION_MARK || at(ptr) == CHAR_ASTERISK)
			if ok {
				if at(ptr) == CHAR_ASTERISK {
					ok = cb.ctypes[at(ptr+1)]&ctype_lcletter != 0
				} else {
					switch at(ptr + 1) {
					case CHAR_C:
						ok = expectCondAssert == 2
					case CHAR_EQUALS_SIGN, CHAR_EXCLAMATION_MARK:
					case CHAR_LESS_THAN_SIGN:
						ok = at(ptr+2) == CHAR_EQUALS_SIGN || at(ptr+2) == CHAR_EXCLAMATION_MARK
					default:
						ok = false
					}
				}
			}
			if !ok {
				ptr--
				return fail(ERR28)
			}
		}

		prevExpectCondAssert = expectCondAssert
		expectCondAssert = 0

		prevOkquantifier = okquantifier
		prevMetaQuantifier = metaQuantifier
		okquantifier = false
		metaQuantifier = 0

		// A following + or ? modifies a previous quantifier.
		if prevMetaQuantifier != 0 && (c == CHAR_QUESTION_MARK || c == CHAR_PLUS) {
			idx := pp - 1
			if prevMetaQuantifier == META_MINMAX {
				idx = pp - 3
			}
			add := uint32(0x00010000)
			if c == CHAR_QUESTION_MARK {
				add = 0x00020000
			}
			parsed[idx] = prevMetaQuantifier + add
			continue
		}

		// checkQuantifier is CHECK_QUANTIFIER (pcre2_compile.c:4457); it returns
		// a non-zero error code (already failed) when not allowed.
		checkQuantifier := func() int {
			if !prevOkquantifier {
				return failBack(ERR9)
			}
			if parsed[prevParsedItem] == META_ACCEPT {
				for p := pp - 1; p >= verbstartptr; p-- {
					parsed[p+1] = parsed[p]
				}
				parsed[verbstartptr] = META_NOCAPTURE
				parsed[pp+1] = META_KET
				pp += 2
			}
			put(metaQuantifier)
			if c == CHAR_LEFT_CURLY_BRACKET {
				put(minRepeat)
				put(maxRepeat)
			}
			return 0
		}

		// defineName is DEFINE_NAME (pcre2_compile.c:4833).
		defineName := func(term uint32) int {
			var off uint64
			if !read_name(pat, &ptr, ptrend, utf, term, &off, &name, &namelen, &errorcode, cb) {
				return fail(errorcode)
			}
			if cb.bracount >= MAX_GROUP_NUMBER {
				return fail(ERR97)
			}
			cb.bracount++
			put(META_CAPTURE | cb.bracount)
			nestDepth++
			if int(cb.namesFound) >= MAX_NAME_COUNT {
				return fail(ERR49)
			}
			if namelen+IMM2_SIZE+1 > uint32(cb.nameEntrySize) {
				cb.nameEntrySize = uint16(namelen + IMM2_SIZE + 1)
			}
			isdupname = false
			n := name
			nl := int(namelen)
			for i = 0; i < int(cb.namesFound); i++ {
				ng := &cb.namedGroups[i]
				if namelen == uint32(ng.length) && strncmp(pat[n:n+nl], ng.name, uint64(namelen)) == 0 {
					if ng.number == cb.bracount {
						break
					}
					if options&PCRE2_DUPNAMES == 0 {
						return fail(ERR43)
					}
					ng.isdup = 1
					isdupname = true
					cb.dupnames = true
				} else if ng.number == cb.bracount {
					return fail(ERR65)
				}
			}
			if i < int(cb.namesFound) {
				return 0 // ignore duplicate with same number
			}
			if cb.namesFound >= uint16(cb.namedGroupListSize) || int(cb.namesFound) >= len(cb.namedGroups) {
				newsize := cb.namedGroupListSize * 2
				if newsize == 0 {
					newsize = 20
				}
				newspace := make([]named_group, newsize)
				copy(newspace, cb.namedGroups)
				cb.namedGroups = newspace
				cb.namedGroupListSize = newsize
			}
			dup := uint16(0)
			if isdupname {
				dup = 1
			}
			cb.namedGroups[cb.namesFound] = named_group{name: pat[n : n+nl],
				length: uint16(namelen), number: cb.bracount, isdup: dup}
			cb.namesFound++
			return 0
		}

		// postAssertion is POST_ASSERTION (pcre2_compile.c:4806).
		postAssertion := func() int {
			nestDepth++
			if prevExpectCondAssert > 0 {
				if !pushNest(NSF_CONDASSERT) {
					return fail(ERR84)
				}
			}
			return 0
		}
		// postLookbehind is POST_LOOKBEHIND (pcre2_compile.c:4790).
		postLookbehind := func() int {
			*hasLookbehind = true
			off := uint64(ptr - 2)
			pp = parse_putoffset(parsed, pp, off)
			ptr += 2
			return postAssertion()
		}
		atomicGroup := func() {
			put(META_ATOMIC)
			nestDepth++
			ptr++
		}

		switch c {
		default:
			putLiteral(c)

		// ---- Escape sequence ----
		case CHAR_BACKSLASH:
			tempptr = ptr
			escape = check_escape(pat, &ptr, ptrend, &c, &errorcode, options, xoptions, false, cb)
			failedEsc := errorcode != 0
		escLoop:
			for {
				if failedEsc { // ESCAPE_FAILED (pcre2_compile.c:3210)
					failedEsc = false
					if xoptions&PCRE2_EXTRA_BAD_ESCAPE_IS_LITERAL == 0 {
						return fail(errorcode)
					}
					ptr = tempptr
					if ptr >= ptrend {
						c = CHAR_BACKSLASH
					} else {
						c, ptr = GETCHARINCTEST(utf, pat, ptr)
					}
					escape = 0
				}

				if escape == 0 {
					putLiteral(c)
				} else if escape < 0 {
					off := uint64(ptr - 1)
					escape = -escape
					put(META_BACKREF | uint32(escape))
					if escape < 10 {
						if cb.smallRefOffset[escape] == PCRE2_UNSET {
							cb.smallRefOffset[escape] = off
						}
					} else {
						pp = parse_putoffset(parsed, pp, off)
					}
					okquantifier = true
				} else {
					switch escape {
					case ESC_C:
						if options&PCRE2_NEVER_BACKSLASH_C != 0 {
							errorcode = ERR83
							failedEsc = true
							continue escLoop
						}
						okquantifier = true
						put(META_ESCAPE + uint32(escape))

					case ESC_ub:
						put(CHAR_u)
						putLiteral(CHAR_LEFT_CURLY_BRACKET)

					case ESC_X, ESC_H, ESC_h, ESC_N, ESC_R, ESC_V, ESC_v:
						okquantifier = true
						put(META_ESCAPE + uint32(escape))

					case ESC_d, ESC_D, ESC_s, ESC_S, ESC_w, ESC_W:
						okquantifier = true
						pp = parse_handle_escdsw(escape, pp, options, xoptions, cb)

					case ESC_P, ESC_p:
						var negated bool
						var ptype, pdata uint16
						if !get_ucp(pat, &ptr, &negated, &ptype, &pdata, &errorcode, cb) {
							failedEsc = true
							continue escLoop
						}
						if negated {
							if escape == ESC_P {
								escape = ESC_p
							} else {
								escape = ESC_P
							}
						}
						put(META_ESCAPE + uint32(escape))
						put(uint32(ptype)<<16 | uint32(pdata))
						okquantifier = true

					case ESC_g, ESC_k:
						if ptr >= ptrend || (pat[ptr] != CHAR_LEFT_CURLY_BRACKET &&
							pat[ptr] != CHAR_LESS_THAN_SIGN && pat[ptr] != CHAR_APOSTROPHE) {
							if escape == ESC_g {
								errorcode = ERR57
							} else {
								errorcode = ERR69
							}
							failedEsc = true
							continue escLoop
						}
						switch pat[ptr] {
						case CHAR_LESS_THAN_SIGN:
							terminator = CHAR_GREATER_THAN_SIGN
						case CHAR_APOSTROPHE:
							terminator = CHAR_APOSTROPHE
						default:
							terminator = CHAR_RIGHT_CURLY_BRACKET
						}

						if escape == ESC_g && terminator != CHAR_RIGHT_CURLY_BRACKET {
							p := ptr + 1
							if read_number(pat, &p, ptrend, int32(cb.bracount), MAX_GROUP_NUMBER, ERR61, &i, &errorcode) {
								if p >= ptrend || uint32(pat[p]) != terminator {
									errorcode = ERR57
									failedEsc = true
									continue escLoop
								}
								ptr = p
								setRecursion(i)
								break
							}
							if errorcode != 0 {
								failedEsc = true
								continue escLoop
							}
						}

						if !read_name(pat, &ptr, ptrend, utf, terminator, &offset, &name, &namelen, &errorcode, cb) {
							failedEsc = true
							continue escLoop
						}
						if escape == ESC_k || terminator == CHAR_RIGHT_CURLY_BRACKET {
							put(META_BACKREF_BYNAME)
						} else {
							put(META_RECURSE_BYNAME)
						}
						put(namelen)
						pp = parse_putoffset(parsed, pp, offset)
						okquantifier = true

					default: // \A, \B, \b, \G, \K, \Z, \z cannot be quantified.
						put(META_ESCAPE + uint32(escape))
					}
				}
				break escLoop
			}

		// ---- Single-character special items ----
		case CHAR_CIRCUMFLEX_ACCENT:
			put(META_CIRCUMFLEX)

		case CHAR_DOLLAR_SIGN:
			put(META_DOLLAR)

		case CHAR_DOT:
			put(META_DOT)
			okquantifier = true

		// ---- Quantifiers ----
		case CHAR_ASTERISK:
			metaQuantifier = META_ASTERISK
			if e := checkQuantifier(); e != 0 {
				return e
			}
		case CHAR_PLUS:
			metaQuantifier = META_PLUS
			if e := checkQuantifier(); e != 0 {
				return e
			}
		case CHAR_QUESTION_MARK:
			metaQuantifier = META_QUERY
			if e := checkQuantifier(); e != 0 {
				return e
			}

		case CHAR_LEFT_CURLY_BRACKET:
			if !read_repeat_counts(pat, &ptr, ptrend, &minRepeat, &maxRepeat, &errorcode) {
				if errorcode != 0 {
					return fail(errorcode)
				}
				putLiteral(c)
				break
			}
			metaQuantifier = META_MINMAX
			if e := checkQuantifier(); e != 0 {
				return e
			}

		// ---- Character class ----
		case CHAR_LEFT_SQUARE_BRACKET:
			okquantifier = true

			// [[:<:]] and [[:>:]] (pcre2_compile.c:4504)
			if ptrend-ptr >= 6 &&
				(strncmp_c8(pat[ptr:], "[:<:]]", 6) == 0 || strncmp_c8(pat[ptr:], "[:>:]]", 6) == 0) {
				put(META_ESCAPE + ESC_b)
				if pat[ptr+2] == CHAR_LESS_THAN_SIGN {
					put(META_LOOKAHEAD)
				} else {
					put(META_LOOKBEHIND)
					*hasLookbehind = true
					pp = parse_putoffset(parsed, pp, 0)
				}
				if options&PCRE2_UCP == 0 {
					put(META_ESCAPE + ESC_w)
				} else {
					put(META_ESCAPE + ESC_p)
					put(PT_WORD << 16)
				}
				put(META_KET)
				ptr += 6
				break
			}

			if ptr < ptrend && (pat[ptr] == CHAR_COLON || pat[ptr] == CHAR_DOT ||
				pat[ptr] == CHAR_EQUALS_SIGN) &&
				check_posix_syntax(pat, ptr, ptrend, &tempptr) {
				first := pat[ptr]
				ptr--
				if first == CHAR_COLON {
					return fail(ERR12)
				}
				return fail(ERR13)
			}

			negateClass = false
			for ptr < ptrend {
				c, ptr = GETCHARINCTEST(utf, pat, ptr)
				if c == CHAR_BACKSLASH {
					if ptr < ptrend && pat[ptr] == CHAR_E {
						ptr++
					} else if ptrend-ptr >= 3 && strncmp_c8(pat[ptr:], "Q\\E", 3) == 0 {
						ptr += 3
					} else {
						break
					}
				} else if options&PCRE2_EXTENDED_MORE != 0 && (c == CHAR_SPACE || c == CHAR_HT) {
					continue
				} else if !negateClass && c == CHAR_CIRCUMFLEX_ACCENT {
					negateClass = true
				} else {
					break
				}
			}

			if c == CHAR_RIGHT_SQUARE_BRACKET && cb.externalOptions&PCRE2_ALLOW_EMPTY_CLASS != 0 {
				if negateClass {
					put(META_CLASS_EMPTY_NOT)
				} else {
					put(META_CLASS_EMPTY)
				}
				break
			}

			if negateClass {
				put(META_CLASS_NOT)
			} else {
				put(META_CLASS)
			}
			classRangeState = RANGE_NO

			for {
				charIsLiteral := true
				doLiteral := false // CLASS_LITERAL
				cont := false      // CLASS_CONTINUE

				if inescq {
					if c == CHAR_BACKSLASH && ptr < ptrend && pat[ptr] == CHAR_E {
						inescq = false
						ptr++
						cont = true
					} else {
						doLiteral = true
					}
				} else if options&PCRE2_EXTENDED_MORE != 0 && (c == CHAR_SPACE || c == CHAR_HT) {
					cont = true
				} else if c == CHAR_LEFT_SQUARE_BRACKET && ptrend-ptr >= 3 &&
					(pat[ptr] == CHAR_COLON || pat[ptr] == CHAR_DOT || pat[ptr] == CHAR_EQUALS_SIGN) &&
					check_posix_syntax(pat, ptr, ptrend, &tempptr) {
					// POSIX class names
					posixNegate := false
					if classRangeState == RANGE_STARTED {
						return fail(ERR50)
					}
					if pat[ptr] != CHAR_COLON {
						return failBack(ERR13)
					}
					ptr++
					if pat[ptr] == CHAR_CIRCUMFLEX_ACCENT {
						posixNegate = true
						ptr++
					}
					posixClass := check_posix_name(pat, ptr, tempptr-ptr)
					if posixClass < 0 {
						return fail(ERR30)
					}
					ptr = tempptr + 2

					if ptr < ptrend-1 && pat[ptr] == CHAR_MINUS && pat[ptr+1] != CHAR_RIGHT_SQUARE_BRACKET {
						return fail(ERR50)
					}
					classRangeState = RANGE_NO

					handled := false
					if options&PCRE2_UCP != 0 && xoptions&PCRE2_EXTRA_ASCII_POSIX == 0 &&
						!(xoptions&PCRE2_EXTRA_ASCII_DIGIT != 0 && (posixClass == PC_DIGIT || posixClass == PC_XDIGIT)) {
						ptype := int(posix_substitutes[2*posixClass])
						pvalue := int(posix_substitutes[2*posixClass+1])
						if ptype >= 0 {
							if posixNegate {
								put(META_ESCAPE + ESC_P)
							} else {
								put(META_ESCAPE + ESC_p)
							}
							put(uint32(ptype)<<16 | uint32(pvalue))
							handled = true
						} else if pvalue != 0 {
							if posixNegate {
								put(META_ESCAPE + ESC_H)
							} else {
								put(META_ESCAPE + ESC_h)
							}
							handled = true
						}
					}
					if !handled {
						if posixNegate {
							put(META_POSIX_NEG)
						} else {
							put(META_POSIX)
						}
						put(uint32(posixClass))
					}
				} else if c == CHAR_MINUS && classRangeState >= RANGE_OK_ESCAPED {
					if classRangeState == RANGE_OK_LITERAL {
						put(META_RANGE_LITERAL)
					} else {
						put(META_RANGE_ESCAPED)
					}
					classRangeState = RANGE_STARTED
				} else if c != CHAR_BACKSLASH {
					doLiteral = true
				} else {
					// Escapes in a class
					tempptr = ptr
					escape = check_escape(pat, &ptr, ptrend, &c, &errorcode, options, xoptions, true, cb)
					if errorcode != 0 {
						if xoptions&PCRE2_EXTRA_BAD_ESCAPE_IS_LITERAL == 0 {
							return fail(errorcode)
						}
						ptr = tempptr
						if ptr >= ptrend {
							c = CHAR_BACKSLASH
						} else {
							c, ptr = GETCHARINCTEST(utf, pat, ptr)
						}
						escape = 0
					}

					switch escape {
					case 0:
						charIsLiteral = false
						doLiteral = true
					case ESC_b:
						c = CHAR_BS
						charIsLiteral = false
						doLiteral = true
					case ESC_Q:
						inescq = true
						cont = true
					case ESC_E:
						cont = true
					case ESC_B, ESC_R, ESC_X:
						ptr--
						return fail(ERR7)
					}

					if !doLiteral && !cont {
						if classRangeState == RANGE_STARTED {
							return fail(ERR50)
						}
						classRangeState = RANGE_NO
						switch escape {
						case ESC_N:
							return fail(ERR71)
						case ESC_H, ESC_h, ESC_V, ESC_v:
							put(META_ESCAPE + uint32(escape))
						case ESC_d, ESC_D, ESC_s, ESC_S, ESC_w, ESC_W:
							pp = parse_handle_escdsw(escape, pp, options, xoptions, cb)
						case ESC_P, ESC_p:
							var negated bool
							var ptype, pdata uint16
							if !get_ucp(pat, &ptr, &negated, &ptype, &pdata, &errorcode, cb) {
								return fail(errorcode)
							}
							if negated {
								if escape == ESC_P {
									escape = ESC_p
								} else {
									escape = ESC_P
								}
							}
							put(META_ESCAPE + uint32(escape))
							put(uint32(ptype)<<16 | uint32(pdata))
						default:
							ptr--
							return fail(ERR7)
						}

						if ptr < ptrend-1 && pat[ptr] == CHAR_MINUS && pat[ptr+1] != CHAR_RIGHT_SQUARE_BRACKET {
							return fail(ERR50)
						}
					}
				}

				if doLiteral { // CLASS_LITERAL (pcre2_compile.c:3743)
					if classRangeState == RANGE_STARTED {
						if c == parsed[pp-2] { // optimize one-char range
							pp--
						} else if parsed[pp-2] > c {
							return failBack(ERR8)
						} else {
							if !charIsLiteral && parsed[pp-1] == META_RANGE_LITERAL {
								parsed[pp-1] = META_RANGE_ESCAPED
							}
							putLiteral(c)
						}
						classRangeState = RANGE_NO
					} else {
						if charIsLiteral {
							classRangeState = RANGE_OK_LITERAL
						} else {
							classRangeState = RANGE_OK_ESCAPED
						}
						putLiteral(c)
					}
				}

				// CLASS_CONTINUE
				if ptr >= ptrend {
					return fail(ERR6)
				}
				c, ptr = GETCHARINCTEST(utf, pat, ptr)
				if c == CHAR_RIGHT_SQUARE_BRACKET && !inescq {
					break
				}
			}

			if classRangeState == RANGE_STARTED {
				parsed[pp-1] = CHAR_MINUS
				classRangeState = RANGE_NO
			}
			put(META_CLASS_END)

		// ---- Opening parenthesis ----
		case CHAR_LEFT_PARENTHESIS:
			if ptr >= ptrend {
				return fail(ERR14)
			}

			if pat[ptr] != CHAR_QUESTION_MARK {
				if pat[ptr] != CHAR_ASTERISK {
					nestDepth++
					if options&PCRE2_NO_AUTO_CAPTURE == 0 {
						if cb.bracount >= MAX_GROUP_NUMBER {
							return fail(ERR97)
						}
						cb.bracount++
						put(META_CAPTURE | cb.bracount)
					} else {
						put(META_NOCAPTURE)
					}
				} else if ptrend-ptr <= 1 || func() bool { c = uint32(pat[ptr+1]); return c == CHAR_RIGHT_PARENTHESIS }() {
					break
				} else if c <= 255 && cb.ctypes[c]&ctype_lcletter != 0 {
					// alpha assertions
					vnOff := 0
					if !read_name(pat, &ptr, ptrend, utf, 0, &offset, &name, &namelen, &errorcode, cb) {
						return fail(errorcode)
					}
					if ptr >= ptrend || pat[ptr] != CHAR_COLON {
						return fail(ERR95)
					}
					names := string(alasnames)
					for i = 0; i < alascount; i++ {
						if namelen == uint32(alasmeta[i].len) &&
							strncmp_c8(pat[name:], names[vnOff:], uint64(namelen)) == 0 {
							break
						}
						vnOff += int(alasmeta[i].len) + 1
					}
					if i >= alascount {
						return fail(ERR95)
					}

					meta := uint32(alasmeta[i].meta)
					if prevExpectCondAssert > 0 && (meta < META_LOOKAHEAD || meta > META_LOOKBEHINDNOT) {
						if meta == META_LOOKAHEAD_NA || meta == META_LOOKBEHIND_NA {
							return fail(ERR98)
						}
						return fail(ERR28)
					}

					switch meta {
					default:
						return fail(ERR89)
					case META_ATOMIC:
						atomicGroup()
					case META_LOOKAHEAD:
						put(META_LOOKAHEAD)
						ptr++
						if e := postAssertion(); e != 0 {
							return e
						}
					case META_LOOKAHEAD_NA:
						put(META_LOOKAHEAD_NA)
						ptr++
						if e := postAssertion(); e != 0 {
							return e
						}
					case META_LOOKAHEADNOT:
						put(META_LOOKAHEADNOT)
						ptr++
						if e := postAssertion(); e != 0 {
							return e
						}
					case META_LOOKBEHIND, META_LOOKBEHINDNOT, META_LOOKBEHIND_NA:
						put(meta)
						ptr--
						if e := postLookbehind(); e != 0 {
							return e
						}
					case META_SCRIPT_RUN, META_ATOMIC_SCRIPT_RUN:
						put(META_SCRIPT_RUN)
						nestDepth++
						ptr++
						if meta == META_ATOMIC_SCRIPT_RUN {
							put(META_ATOMIC)
							if !pushNest(NSF_ATOMICSR) {
								return fail(ERR84)
							}
						}
					}
				} else {
					// (*VERB) and (*VERB:NAME)
					vnOff := 0
					if !read_name(pat, &ptr, ptrend, utf, 0, &offset, &name, &namelen, &errorcode, cb) {
						return fail(errorcode)
					}
					if ptr >= ptrend || (pat[ptr] != CHAR_COLON && pat[ptr] != CHAR_RIGHT_PARENTHESIS) {
						return fail(ERR60)
					}
					names := string(verbnames)
					for i = 0; i < verbcount; i++ {
						if namelen == uint32(verbs[i].len) &&
							strncmp_c8(pat[name:], names[vnOff:], uint64(namelen)) == 0 {
							break
						}
						vnOff += int(verbs[i].len) + 1
					}
					if i >= verbcount {
						return fail(ERR60)
					}

					if pat[ptr] == CHAR_COLON && ptr+1 < ptrend && pat[ptr+1] == CHAR_RIGHT_PARENTHESIS {
						ptr++
					}
					if verbs[i].has_arg > 0 && pat[ptr] != CHAR_COLON {
						return fail(ERR66)
					}

					verbstartptr = pp
					okquantifier = uint32(verbs[i].meta) == META_ACCEPT

					skipped := pat[ptr]
					ptr++
					if skipped == CHAR_COLON {
						if verbs[i].has_arg < 0 {
							addAfterMark = uint32(verbs[i].meta)
							put(META_MARK)
						} else {
							v := uint32(verbs[i].meta)
							if v != META_MARK {
								v += 0x00010000
							}
							put(v)
						}
						verblengthptr = pp
						pp++
						verbnamestart = ptr
						inverbname = true
					} else {
						put(uint32(verbs[i].meta))
					}
				}
				break // done with this parenthesis
			}

			// ---- Items starting (? ----
			ptr++
			if ptr >= ptrend {
				return fail(ERR14)
			}

			switch pat[ptr] {
			default:
				if pat[ptr] == CHAR_MINUS && ptrend-ptr > 1 && parse_isdigit(pat[ptr+1]) {
					goto recursionByNumber
				}
				goto optionsOrReset

			case CHAR_P:
				ptr++
				if ptr >= ptrend {
					return fail(ERR14)
				}
				if pat[ptr] == CHAR_LESS_THAN_SIGN {
					if e := defineName(CHAR_GREATER_THAN_SIGN); e != 0 {
						return e
					}
					break
				}
				if pat[ptr] == CHAR_GREATER_THAN_SIGN {
					goto recurseByName
				}
				if pat[ptr] != CHAR_EQUALS_SIGN {
					return fail(ERR41)
				}
				if !read_name(pat, &ptr, ptrend, utf, CHAR_RIGHT_PARENTHESIS, &offset, &name, &namelen, &errorcode, cb) {
					return fail(errorcode)
				}
				put(META_BACKREF_BYNAME)
				put(namelen)
				pp = parse_putoffset(parsed, pp, offset)
				okquantifier = true

			case CHAR_R:
				i = 0
				ptr++
				if ptr >= ptrend || pat[ptr] != CHAR_RIGHT_PARENTHESIS {
					return fail(ERR58)
				}
				setRecursion(i)

			case CHAR_PLUS:
				if ptrend-ptr < 2 || !parse_isdigit(pat[ptr+1]) {
					return fail(ERR29)
				}
				goto recursionByNumber

			case CHAR_0, CHAR_1, CHAR_2, CHAR_3, CHAR_4, CHAR_5, CHAR_6, CHAR_7, CHAR_8, CHAR_9:
				goto recursionByNumber

			case CHAR_AMPERSAND:
				goto recurseByName

			case CHAR_C:
				ptr++
				if ptr >= ptrend {
					return fail(ERR14)
				}
				expectCondAssert = prevExpectCondAssert - 1

				if previousCallout >= 0 && options&PCRE2_AUTO_CALLOUT != 0 &&
					previousCallout == pp-4 && parsed[pp-1] == 255 {
					pp = previousCallout
				}

				previousCallout = pp
				afterManual = 1

				if pat[ptr] != CHAR_RIGHT_PARENTHESIS && !parse_isdigit(pat[ptr]) {
					startptr := ptr
					delimiter = 0
					for i = 0; callout_start_delims[i] != 0; i++ {
						if uint32(pat[ptr]) == callout_start_delims[i] {
							delimiter = callout_end_delims[i]
							break
						}
					}
					if delimiter == 0 {
						return fail(ERR82)
					}
					parsed[pp] = META_CALLOUT_STRING
					pp += 3
					for {
						ptr++
						if ptr >= ptrend {
							ptr = startptr
							return fail(ERR81)
						}
						if uint32(pat[ptr]) == delimiter {
							ptr++
							if ptr >= ptrend || uint32(pat[ptr]) != delimiter {
								break
							}
						}
					}
					calloutlength := uint64(ptr - startptr)
					if calloutlength > 0xffffffff {
						return fail(ERR72)
					}
					put(uint32(calloutlength))
					pp = parse_putoffset(parsed, pp, uint64(startptr))
				} else {
					n := 0
					parsed[pp] = META_CALLOUT_NUMBER
					pp += 3
					for ptr < ptrend && parse_isdigit(pat[ptr]) {
						n = n*10 + int(pat[ptr]) - CHAR_0
						ptr++
						if n > 255 {
							return fail(ERR38)
						}
					}
					put(uint32(n))
				}

				if ptr >= ptrend || pat[ptr] != CHAR_RIGHT_PARENTHESIS {
					return fail(ERR39)
				}
				ptr++
				parsed[previousCallout+1] = uint32(ptr)
				parsed[previousCallout+2] = 0

			case CHAR_LEFT_PARENTHESIS:
				ptr++
				if ptr >= ptrend {
					return fail(ERR14)
				}
				nestDepth++

				if pat[ptr] == CHAR_QUESTION_MARK || pat[ptr] == CHAR_ASTERISK {
					put(META_COND_ASSERT)
					ptr--
					expectCondAssert = 2
					break
				}

				if read_number(pat, &ptr, ptrend, int32(cb.bracount), MAX_GROUP_NUMBER, ERR61, &i, &errorcode) {
					if i <= 0 {
						return fail(ERR15)
					}
					put(META_COND_NUMBER)
					off := uint64(ptr - 2)
					pp = parse_putoffset(parsed, pp, off)
					put(uint32(i))
				} else if errorcode != 0 {
					return fail(errorcode)
				} else if ptrend-ptr >= 10 && strncmp_c8(pat[ptr:], "VERSION", 7) == 0 &&
					pat[ptr+7] != CHAR_RIGHT_PARENTHESIS {
					var ge uint32
					var major, minor int
					ptr += 7
					if pat[ptr] == CHAR_GREATER_THAN_SIGN {
						ge = 1
						ptr++
					}
					if pat[ptr] != CHAR_EQUALS_SIGN {
						return fail(ERR79)
					}
					ptr++
					if !parse_isdigit(at(ptr)) {
						return fail(ERR79)
					}
					if !read_number(pat, &ptr, ptrend, -1, 1000, ERR79, &major, &errorcode) {
						return fail(errorcode)
					}
					if ptr >= ptrend {
						return fail(ERR79)
					}
					if pat[ptr] == CHAR_DOT {
						ptr++
						if ptr >= ptrend || !parse_isdigit(pat[ptr]) {
							return fail(ERR79)
						}
						minor = (int(pat[ptr]) - CHAR_0) * 10
						ptr++
						if ptr >= ptrend {
							return fail(ERR79)
						}
						if parse_isdigit(pat[ptr]) {
							minor += int(pat[ptr]) - CHAR_0
							ptr++
						}
						if ptr >= ptrend || pat[ptr] != CHAR_RIGHT_PARENTHESIS {
							return fail(ERR79)
						}
					}
					put(META_COND_VERSION)
					put(ge)
					put(uint32(major))
					put(uint32(minor))
				} else {
					wasRAmpersand := false
					if pat[ptr] == CHAR_R && ptrend-ptr > 1 && pat[ptr+1] == CHAR_AMPERSAND {
						terminator = CHAR_RIGHT_PARENTHESIS
						wasRAmpersand = true
						ptr++
					} else if pat[ptr] == CHAR_LESS_THAN_SIGN {
						terminator = CHAR_GREATER_THAN_SIGN
					} else if pat[ptr] == CHAR_APOSTROPHE {
						terminator = CHAR_APOSTROPHE
					} else {
						terminator = CHAR_RIGHT_PARENTHESIS
						ptr--
					}
					if !read_name(pat, &ptr, ptrend, utf, terminator, &offset, &name, &namelen, &errorcode, cb) {
						return fail(errorcode)
					}

					var meta uint32
					if wasRAmpersand {
						meta = META_COND_RNAME
						ptr--
					} else if terminator == CHAR_RIGHT_PARENTHESIS {
						if namelen == 6 && strncmp_c8(pat[name:], "DEFINE", 6) == 0 {
							meta = META_COND_DEFINE
						} else {
							for i = 1; i < int(namelen); i++ {
								if !parse_isdigit(pat[name+i]) {
									break
								}
							}
							if pat[name] == CHAR_R && i >= int(namelen) {
								meta = META_COND_RNUMBER
							} else {
								meta = META_COND_NAME
							}
						}
						ptr--
					} else {
						meta = META_COND_NAME
					}
					put(meta)
					if meta != META_COND_DEFINE {
						put(namelen)
					}
					pp = parse_putoffset(parsed, pp, offset)
				}

				if ptr >= ptrend || pat[ptr] != CHAR_RIGHT_PARENTHESIS {
					return fail(ERR24)
				}
				ptr++

			case CHAR_GREATER_THAN_SIGN:
				atomicGroup()

			case CHAR_EQUALS_SIGN:
				put(META_LOOKAHEAD)
				ptr++
				if e := postAssertion(); e != 0 {
					return e
				}

			case CHAR_ASTERISK:
				put(META_LOOKAHEAD_NA)
				ptr++
				if e := postAssertion(); e != 0 {
					return e
				}

			case CHAR_EXCLAMATION_MARK:
				put(META_LOOKAHEADNOT)
				ptr++
				if e := postAssertion(); e != 0 {
					return e
				}

			case CHAR_LESS_THAN_SIGN:
				if ptrend-ptr <= 1 ||
					(pat[ptr+1] != CHAR_EQUALS_SIGN && pat[ptr+1] != CHAR_EXCLAMATION_MARK &&
						pat[ptr+1] != CHAR_ASTERISK) {
					if e := defineName(CHAR_GREATER_THAN_SIGN); e != 0 {
						return e
					}
					break
				}
				switch pat[ptr+1] {
				case CHAR_EQUALS_SIGN:
					put(META_LOOKBEHIND)
				case CHAR_EXCLAMATION_MARK:
					put(META_LOOKBEHINDNOT)
				default:
					put(META_LOOKBEHIND_NA)
				}
				if e := postLookbehind(); e != 0 {
					return e
				}

			case CHAR_APOSTROPHE:
				if e := defineName(CHAR_APOSTROPHE); e != 0 {
					return e
				}
			}
			break // end of ( handling

		optionsOrReset:
			// (?| or an option setting (pcre2_compile.c:4169).
			nestDepth++
			if !pushNest(0) {
				return fail(ERR84)
			}
			if pat[ptr] == CHAR_VERTICAL_LINE {
				nests[topNest].resetGroup = uint16(cb.bracount)
				nests[topNest].maxGroup = uint16(cb.bracount)
				nests[topNest].flags |= NSF_RESET
				cb.externalFlags |= PCRE2_DUPCAPUSED
				put(META_NOCAPTURE)
				ptr++
			} else {
				hyphenok := true
				oldoptions := options
				oldxoptions := xoptions
				nests[topNest].resetGroup = 0
				nests[topNest].maxGroup = 0
				var set, unset, xset, xunset uint32
				optset := &set
				xoptset := &xset

				if ptr < ptrend && pat[ptr] == CHAR_CIRCUMFLEX_ACCENT {
					options &^= PCRE2_CASELESS | PCRE2_MULTILINE | PCRE2_NO_AUTO_CAPTURE |
						PCRE2_DOTALL | PCRE2_EXTENDED | PCRE2_EXTENDED_MORE
					xoptions &^= PCRE2_EXTRA_CASELESS_RESTRICT
					hyphenok = false
					ptr++
				}

				for ptr < ptrend && pat[ptr] != CHAR_RIGHT_PARENTHESIS && pat[ptr] != CHAR_COLON {
					ch := pat[ptr]
					ptr++
					switch ch {
					case CHAR_MINUS:
						if !hyphenok {
							ptr--
							return fail(ERR94)
						}
						optset = &unset
						xoptset = &xunset
						hyphenok = false

					case CHAR_a:
						if ptr < ptrend {
							if pat[ptr] == CHAR_D {
								*xoptset |= PCRE2_EXTRA_ASCII_BSD
								ptr++
								break
							}
							if pat[ptr] == CHAR_P {
								*xoptset |= PCRE2_EXTRA_ASCII_POSIX | PCRE2_EXTRA_ASCII_DIGIT
								ptr++
								break
							}
							if pat[ptr] == CHAR_S {
								*xoptset |= PCRE2_EXTRA_ASCII_BSS
								ptr++
								break
							}
							if pat[ptr] == CHAR_T {
								*xoptset |= PCRE2_EXTRA_ASCII_DIGIT
								ptr++
								break
							}
							if pat[ptr] == CHAR_W {
								*xoptset |= PCRE2_EXTRA_ASCII_BSW
								ptr++
								break
							}
						}
						*xoptset |= PCRE2_EXTRA_ASCII_BSD | PCRE2_EXTRA_ASCII_BSS |
							PCRE2_EXTRA_ASCII_BSW | PCRE2_EXTRA_ASCII_DIGIT | PCRE2_EXTRA_ASCII_POSIX

					case CHAR_J:
						*optset |= PCRE2_DUPNAMES
						cb.externalFlags |= PCRE2_JCHANGED
					case CHAR_i:
						*optset |= PCRE2_CASELESS
					case CHAR_m:
						*optset |= PCRE2_MULTILINE
					case CHAR_n:
						*optset |= PCRE2_NO_AUTO_CAPTURE
					case CHAR_r:
						*xoptset |= PCRE2_EXTRA_CASELESS_RESTRICT
					case CHAR_s:
						*optset |= PCRE2_DOTALL
					case CHAR_U:
						*optset |= PCRE2_UNGREEDY
					case CHAR_x:
						*optset |= PCRE2_EXTENDED
						if ptr < ptrend && pat[ptr] == CHAR_x {
							*optset |= PCRE2_EXTENDED_MORE
							ptr++
						}
					default:
						ptr--
						return fail(ERR11)
					}
				}

				if set&(PCRE2_EXTENDED|PCRE2_EXTENDED_MORE) == PCRE2_EXTENDED || unset&PCRE2_EXTENDED != 0 {
					unset |= PCRE2_EXTENDED_MORE
				}
				options = (options | set) &^ unset
				xoptions = (xoptions | xset) &^ xunset

				if ptr >= ptrend {
					return fail(ERR14)
				}
				endch := pat[ptr]
				ptr++
				if endch == CHAR_RIGHT_PARENTHESIS {
					nestDepth--
					if topNest > 0 && nests[topNest-1].nestDepth == nestDepth {
						topNest--
					} else {
						nests[topNest].nestDepth = nestDepth
					}
				} else {
					put(META_NOCAPTURE)
				}

				if options != oldoptions || xoptions != oldxoptions {
					put(META_OPTIONS)
					put(options)
					put(xoptions)
				}
			}
			break

		recursionByNumber:
			{
				allow := int32(cb.bracount)
				if parse_isdigit(pat[ptr]) {
					allow = -1
				}
				if !read_number(pat, &ptr, ptrend, allow, MAX_GROUP_NUMBER, ERR61, &i, &errorcode) {
					return fail(errorcode)
				}
				if i < 0 {
					return failBack(ERR15)
				}
				if ptr >= ptrend || pat[ptr] != CHAR_RIGHT_PARENTHESIS {
					return fail(ERR14)
				}
				setRecursion(i)
			}
			break

		recurseByName:
			if !read_name(pat, &ptr, ptrend, utf, CHAR_RIGHT_PARENTHESIS, &offset, &name, &namelen, &errorcode, cb) {
				return fail(errorcode)
			}
			put(META_RECURSE_BYNAME)
			put(namelen)
			pp = parse_putoffset(parsed, pp, offset)
			okquantifier = true

		// ---- Branch terminators ----
		case CHAR_VERTICAL_LINE:
			if topNest >= 0 && nests[topNest].nestDepth == nestDepth &&
				nests[topNest].flags&NSF_RESET != 0 {
				if cb.bracount > uint32(nests[topNest].maxGroup) {
					nests[topNest].maxGroup = uint16(cb.bracount)
				}
				cb.bracount = uint32(nests[topNest].resetGroup)
			}
			put(META_ALT)

		case CHAR_RIGHT_PARENTHESIS:
			okquantifier = true
			if topNest >= 0 && nests[topNest].nestDepth == nestDepth {
				options = (options &^ PARSE_TRACKED_OPTIONS) | nests[topNest].options
				xoptions = (xoptions &^ PARSE_TRACKED_EXTRA_OPTIONS) | nests[topNest].xoptions
				if nests[topNest].flags&NSF_RESET != 0 && uint32(nests[topNest].maxGroup) > cb.bracount {
					cb.bracount = uint32(nests[topNest].maxGroup)
				}
				if nests[topNest].flags&NSF_CONDASSERT != 0 {
					okquantifier = false
				}
				if nests[topNest].flags&NSF_ATOMICSR != 0 {
					put(META_KET)
				}
				if topNest == 0 {
					topNest = -1
				} else {
					topNest--
				}
			}
			if nestDepth == 0 {
				return failBack(ERR22)
			}
			nestDepth--
			put(META_KET)
		}
		continue mainLoop
	}

	// End of pattern reached. Check for missing ) at the end of a verb name.
	if inverbname && ptr >= ptrend {
		return fail(ERR60)
	}
	return finish()
}
