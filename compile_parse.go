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
	xNSF_RESET      = 0x0001
	xNSF_CONDASSERT = 0x0002
	xNSF_ATOMICSR   = 0x0004
)

// Options that are tracked during parsing (pcre2_compile.c:2743-2749).
const (
	xPARSE_TRACKED_OPTIONS = PCRE2_CASELESS | PCRE2_DOTALL | PCRE2_DUPNAMES |
		PCRE2_EXTENDED | PCRE2_EXTENDED_MORE | PCRE2_MULTILINE | PCRE2_NO_AUTO_CAPTURE |
		PCRE2_UNGREEDY

	xPARSE_TRACKED_EXTRA_OPTIONS = PCRE2_EXTRA_CASELESS_RESTRICT |
		PCRE2_EXTRA_ASCII_BSD | PCRE2_EXTRA_ASCII_BSS | PCRE2_EXTRA_ASCII_BSW |
		PCRE2_EXTRA_ASCII_DIGIT | PCRE2_EXTRA_ASCII_POSIX
)

// States used for analyzing ranges in character classes (pcre2_compile.c:2754).
const (
	xRANGE_NO = iota
	xRANGE_STARTED
	xRANGE_OK_ESCAPED
	xRANGE_OK_LITERAL
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
			parsed[previous] = xMETA_CALLOUT_NUMBER
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
	prop := xESC_p
	switch escape {
	case xESC_D:
		prop = xESC_P
		asciiOption = PCRE2_EXTRA_ASCII_BSD
	case xESC_d:
		asciiOption = PCRE2_EXTRA_ASCII_BSD
	case xESC_S:
		prop = xESC_P
		asciiOption = PCRE2_EXTRA_ASCII_BSS
	case xESC_s:
		asciiOption = PCRE2_EXTRA_ASCII_BSS
	case xESC_W:
		prop = xESC_P
		asciiOption = PCRE2_EXTRA_ASCII_BSW
	case xESC_w:
		asciiOption = PCRE2_EXTRA_ASCII_BSW
	}
	if options&PCRE2_UCP == 0 || xoptions&asciiOption != 0 {
		parsed[pp] = xMETA_ESCAPE + uint32(escape)
		pp++
	} else {
		parsed[pp] = xMETA_ESCAPE + uint32(prop)
		pp++
		switch escape {
		case xESC_d, xESC_D:
			parsed[pp] = xPT_PC<<16 | ucp_Nd
			pp++
		case xESC_s, xESC_S:
			parsed[pp] = xPT_SPACE << 16
			pp++
		case xESC_w, xESC_W:
			parsed[pp] = xPT_WORD << 16
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
				rc = xERR63 // internal error (parsed pattern overflow)
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
		if cb.nltype != xNLTYPE_FIXED {
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
			options: options & xPARSE_TRACKED_OPTIONS, xoptions: xoptions & xPARSE_TRACKED_EXTRA_OPTIONS}
		return true
	}

	// Insert leading items for word and line matching.
	if xoptions&PCRE2_EXTRA_MATCH_LINE != 0 {
		put(xMETA_CIRCUMFLEX)
		put(xMETA_NOCAPTURE)
	} else if xoptions&PCRE2_EXTRA_MATCH_WORD != 0 {
		put(xMETA_ESCAPE + xESC_b)
		put(xMETA_NOCAPTURE)
	}

	// finish is the code from PARSED_END (pcre2_compile.c:4989) on.
	finish := func() int {
		pp = parse_manage_callouts(ptr, &previousCallout, autoCallout, pp, cb)
		if xoptions&PCRE2_EXTRA_MATCH_LINE != 0 {
			put(xMETA_KET)
			put(xMETA_DOLLAR)
		} else if xoptions&PCRE2_EXTRA_MATCH_WORD != 0 {
			put(xMETA_KET)
			put(xMETA_ESCAPE + xESC_b)
		}
		if pp >= parsedPatternEnd {
			return fail(xERR63)
		}
		parsed[pp] = xMETA_END
		if nestDepth == 0 {
			return 0
		}
		return fail(xERR14) // UNCLOSED_PARENTHESIS
	}

	// A literal pattern is processed separately (pcre2_compile.c:2827).
	if options&PCRE2_LITERAL != 0 {
		for ptr < ptrend {
			if pp >= parsedPatternEnd {
				return fail(xERR63)
			}
			thisptr = ptr
			c, ptr = xGETCHARINCTEST(utf, pat, ptr)
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
		put(xMETA_RECURSE | uint32(n))
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
			return fail(xERR63)
		}
		if uint32(nestDepth) > cb.cx.parensNestLimit {
			return fail(xERR19)
		}

		if thisParsedItem != pp {
			prevParsedItem = thisParsedItem
			thisParsedItem = pp
		}

		thisptr = ptr
		c, ptr = xGETCHARINCTEST(utf, pat, ptr)

		// Copy quoted literals until \E.
		if inescq {
			if c == xCHAR_BACKSLASH && ptr < ptrend && pat[ptr] == xCHAR_E {
				inescq = false
				ptr++
			} else {
				if expectCondAssert > 0 {
					ptr--
					return fail(xERR28)
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
				(c < 256 && c != xCHAR_NUMBER_SIGN && cb.ctypes[c]&ctype_space == 0 && c != xCHAR_NEL)) {

			switch c {
			default:
				put(c)

			case xCHAR_RIGHT_PARENTHESIS:
				inverbname = false
				verbnamelength := uint32(pp - verblengthptr - 1)
				if ptr-verbnamestart-1 > int(xMAX_MARK) {
					ptr--
					return fail(xERR76)
				}
				parsed[verblengthptr] = verbnamelength
				if addAfterMark != 0 {
					put(addAfterMark)
					addAfterMark = 0
				}

			case xCHAR_BACKSLASH:
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
				case xESC_ub:
					put(xCHAR_u)
					putLiteral(xCHAR_LEFT_CURLY_BRACKET)
				case xESC_Q:
					inescq = true
				case xESC_E:
					// ignore
				default:
					return fail(xERR40)
				}
			}
			continue
		}

		// \Q and \E are handled here so that A\Q\E+ is A+.
		if c == xCHAR_BACKSLASH && ptr < ptrend {
			if pat[ptr] == xCHAR_Q || pat[ptr] == xCHAR_E {
				inescq = pat[ptr] == xCHAR_Q
				ptr++
				continue
			}
		}

		// Skip over whitespace and # comments in extended mode.
		if options&PCRE2_EXTENDED != 0 {
			if c < 256 && cb.ctypes[c]&ctype_space != 0 {
				continue
			}
			if c == xCHAR_NEL || (c|1) == 0x200f || (c|1) == 0x2029 {
				continue
			}
			if c == xCHAR_NUMBER_SIGN {
				for ptr < ptrend {
					if isNewline(ptr) {
						ptr += int(cb.nllen)
						break
					}
					ptr++
					if utf {
						ptr = xFORWARDCHARTEST(pat, ptr, ptrend)
					}
				}
				continue
			}
		}

		// Skip over bracketed comments
		if c == xCHAR_LEFT_PARENTHESIS && ptrend-ptr >= 2 &&
			pat[ptr] == xCHAR_QUESTION_MARK && pat[ptr+1] == xCHAR_NUMBER_SIGN {
			for {
				ptr++
				if !(ptr < ptrend && pat[ptr] != xCHAR_RIGHT_PARENTHESIS) {
					break
				}
			}
			if ptr >= ptrend {
				return fail(xERR18)
			}
			ptr++
			continue
		}

		// If the next item is not a quantifier, fill in length of any previous
		// callout and create an auto callout if required.
		isQuant := c == xCHAR_ASTERISK || c == xCHAR_PLUS || c == xCHAR_QUESTION_MARK
		if !isQuant && c == xCHAR_LEFT_CURLY_BRACKET {
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
			ok := c == xCHAR_LEFT_PARENTHESIS && ptrend-ptr >= 3 &&
				(at(ptr) == xCHAR_QUESTION_MARK || at(ptr) == xCHAR_ASTERISK)
			if ok {
				if at(ptr) == xCHAR_ASTERISK {
					ok = cb.ctypes[at(ptr+1)]&ctype_lcletter != 0
				} else {
					switch at(ptr + 1) {
					case xCHAR_C:
						ok = expectCondAssert == 2
					case xCHAR_EQUALS_SIGN, xCHAR_EXCLAMATION_MARK:
					case xCHAR_LESS_THAN_SIGN:
						ok = at(ptr+2) == xCHAR_EQUALS_SIGN || at(ptr+2) == xCHAR_EXCLAMATION_MARK
					default:
						ok = false
					}
				}
			}
			if !ok {
				ptr--
				return fail(xERR28)
			}
		}

		prevExpectCondAssert = expectCondAssert
		expectCondAssert = 0

		prevOkquantifier = okquantifier
		prevMetaQuantifier = metaQuantifier
		okquantifier = false
		metaQuantifier = 0

		// A following + or ? modifies a previous quantifier.
		if prevMetaQuantifier != 0 && (c == xCHAR_QUESTION_MARK || c == xCHAR_PLUS) {
			idx := pp - 1
			if prevMetaQuantifier == xMETA_MINMAX {
				idx = pp - 3
			}
			add := uint32(0x00010000)
			if c == xCHAR_QUESTION_MARK {
				add = 0x00020000
			}
			parsed[idx] = prevMetaQuantifier + add
			continue
		}

		// checkQuantifier is CHECK_QUANTIFIER (pcre2_compile.c:4457); it returns
		// a non-zero error code (already failed) when not allowed.
		checkQuantifier := func() int {
			if !prevOkquantifier {
				return failBack(xERR9)
			}
			if parsed[prevParsedItem] == xMETA_ACCEPT {
				for p := pp - 1; p >= verbstartptr; p-- {
					parsed[p+1] = parsed[p]
				}
				parsed[verbstartptr] = xMETA_NOCAPTURE
				parsed[pp+1] = xMETA_KET
				pp += 2
			}
			put(metaQuantifier)
			if c == xCHAR_LEFT_CURLY_BRACKET {
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
			if cb.bracount >= xMAX_GROUP_NUMBER {
				return fail(xERR97)
			}
			cb.bracount++
			put(xMETA_CAPTURE | cb.bracount)
			nestDepth++
			if int(cb.namesFound) >= xMAX_NAME_COUNT {
				return fail(xERR49)
			}
			if namelen+xIMM2_SIZE+1 > uint32(cb.nameEntrySize) {
				cb.nameEntrySize = uint16(namelen + xIMM2_SIZE + 1)
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
						return fail(xERR43)
					}
					ng.isdup = 1
					isdupname = true
					cb.dupnames = true
				} else if ng.number == cb.bracount {
					return fail(xERR65)
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
				if !pushNest(xNSF_CONDASSERT) {
					return fail(xERR84)
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
			put(xMETA_ATOMIC)
			nestDepth++
			ptr++
		}

		switch c {
		default:
			putLiteral(c)

		// ---- Escape sequence ----
		case xCHAR_BACKSLASH:
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
						c = xCHAR_BACKSLASH
					} else {
						c, ptr = xGETCHARINCTEST(utf, pat, ptr)
					}
					escape = 0
				}

				if escape == 0 {
					putLiteral(c)
				} else if escape < 0 {
					off := uint64(ptr - 1)
					escape = -escape
					put(xMETA_BACKREF | uint32(escape))
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
					case xESC_C:
						if options&PCRE2_NEVER_BACKSLASH_C != 0 {
							errorcode = xERR83
							failedEsc = true
							continue escLoop
						}
						okquantifier = true
						put(xMETA_ESCAPE + uint32(escape))

					case xESC_ub:
						put(xCHAR_u)
						putLiteral(xCHAR_LEFT_CURLY_BRACKET)

					case xESC_X, xESC_H, xESC_h, xESC_N, xESC_R, xESC_V, xESC_v:
						okquantifier = true
						put(xMETA_ESCAPE + uint32(escape))

					case xESC_d, xESC_D, xESC_s, xESC_S, xESC_w, xESC_W:
						okquantifier = true
						pp = parse_handle_escdsw(escape, pp, options, xoptions, cb)

					case xESC_P, xESC_p:
						var negated bool
						var ptype, pdata uint16
						if !get_ucp(pat, &ptr, &negated, &ptype, &pdata, &errorcode, cb) {
							failedEsc = true
							continue escLoop
						}
						if negated {
							if escape == xESC_P {
								escape = xESC_p
							} else {
								escape = xESC_P
							}
						}
						put(xMETA_ESCAPE + uint32(escape))
						put(uint32(ptype)<<16 | uint32(pdata))
						okquantifier = true

					case xESC_g, xESC_k:
						if ptr >= ptrend || (pat[ptr] != xCHAR_LEFT_CURLY_BRACKET &&
							pat[ptr] != xCHAR_LESS_THAN_SIGN && pat[ptr] != xCHAR_APOSTROPHE) {
							if escape == xESC_g {
								errorcode = xERR57
							} else {
								errorcode = xERR69
							}
							failedEsc = true
							continue escLoop
						}
						switch pat[ptr] {
						case xCHAR_LESS_THAN_SIGN:
							terminator = xCHAR_GREATER_THAN_SIGN
						case xCHAR_APOSTROPHE:
							terminator = xCHAR_APOSTROPHE
						default:
							terminator = xCHAR_RIGHT_CURLY_BRACKET
						}

						if escape == xESC_g && terminator != xCHAR_RIGHT_CURLY_BRACKET {
							p := ptr + 1
							if read_number(pat, &p, ptrend, int32(cb.bracount), xMAX_GROUP_NUMBER, xERR61, &i, &errorcode) {
								if p >= ptrend || uint32(pat[p]) != terminator {
									errorcode = xERR57
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
						if escape == xESC_k || terminator == xCHAR_RIGHT_CURLY_BRACKET {
							put(xMETA_BACKREF_BYNAME)
						} else {
							put(xMETA_RECURSE_BYNAME)
						}
						put(namelen)
						pp = parse_putoffset(parsed, pp, offset)
						okquantifier = true

					default: // \A, \B, \b, \G, \K, \Z, \z cannot be quantified.
						put(xMETA_ESCAPE + uint32(escape))
					}
				}
				break escLoop
			}

		// ---- Single-character special items ----
		case xCHAR_CIRCUMFLEX_ACCENT:
			put(xMETA_CIRCUMFLEX)

		case xCHAR_DOLLAR_SIGN:
			put(xMETA_DOLLAR)

		case xCHAR_DOT:
			put(xMETA_DOT)
			okquantifier = true

		// ---- Quantifiers ----
		case xCHAR_ASTERISK:
			metaQuantifier = xMETA_ASTERISK
			if e := checkQuantifier(); e != 0 {
				return e
			}
		case xCHAR_PLUS:
			metaQuantifier = xMETA_PLUS
			if e := checkQuantifier(); e != 0 {
				return e
			}
		case xCHAR_QUESTION_MARK:
			metaQuantifier = xMETA_QUERY
			if e := checkQuantifier(); e != 0 {
				return e
			}

		case xCHAR_LEFT_CURLY_BRACKET:
			if !read_repeat_counts(pat, &ptr, ptrend, &minRepeat, &maxRepeat, &errorcode) {
				if errorcode != 0 {
					return fail(errorcode)
				}
				putLiteral(c)
				break
			}
			metaQuantifier = xMETA_MINMAX
			if e := checkQuantifier(); e != 0 {
				return e
			}

		// ---- Character class ----
		case xCHAR_LEFT_SQUARE_BRACKET:
			okquantifier = true

			// [[:<:]] and [[:>:]] (pcre2_compile.c:4504)
			if ptrend-ptr >= 6 &&
				(strncmp_c8(pat[ptr:], "[:<:]]", 6) == 0 || strncmp_c8(pat[ptr:], "[:>:]]", 6) == 0) {
				put(xMETA_ESCAPE + xESC_b)
				if pat[ptr+2] == xCHAR_LESS_THAN_SIGN {
					put(xMETA_LOOKAHEAD)
				} else {
					put(xMETA_LOOKBEHIND)
					*hasLookbehind = true
					pp = parse_putoffset(parsed, pp, 0)
				}
				if options&PCRE2_UCP == 0 {
					put(xMETA_ESCAPE + xESC_w)
				} else {
					put(xMETA_ESCAPE + xESC_p)
					put(xPT_WORD << 16)
				}
				put(xMETA_KET)
				ptr += 6
				break
			}

			if ptr < ptrend && (pat[ptr] == xCHAR_COLON || pat[ptr] == xCHAR_DOT ||
				pat[ptr] == xCHAR_EQUALS_SIGN) &&
				check_posix_syntax(pat, ptr, ptrend, &tempptr) {
				first := pat[ptr]
				ptr--
				if first == xCHAR_COLON {
					return fail(xERR12)
				}
				return fail(xERR13)
			}

			negateClass = false
			for ptr < ptrend {
				c, ptr = xGETCHARINCTEST(utf, pat, ptr)
				if c == xCHAR_BACKSLASH {
					if ptr < ptrend && pat[ptr] == xCHAR_E {
						ptr++
					} else if ptrend-ptr >= 3 && strncmp_c8(pat[ptr:], "Q\\E", 3) == 0 {
						ptr += 3
					} else {
						break
					}
				} else if options&PCRE2_EXTENDED_MORE != 0 && (c == xCHAR_SPACE || c == xCHAR_HT) {
					continue
				} else if !negateClass && c == xCHAR_CIRCUMFLEX_ACCENT {
					negateClass = true
				} else {
					break
				}
			}

			if c == xCHAR_RIGHT_SQUARE_BRACKET && cb.externalOptions&PCRE2_ALLOW_EMPTY_CLASS != 0 {
				if negateClass {
					put(xMETA_CLASS_EMPTY_NOT)
				} else {
					put(xMETA_CLASS_EMPTY)
				}
				break
			}

			if negateClass {
				put(xMETA_CLASS_NOT)
			} else {
				put(xMETA_CLASS)
			}
			classRangeState = xRANGE_NO

			for {
				charIsLiteral := true
				doLiteral := false // CLASS_LITERAL
				cont := false      // CLASS_CONTINUE

				if inescq {
					if c == xCHAR_BACKSLASH && ptr < ptrend && pat[ptr] == xCHAR_E {
						inescq = false
						ptr++
						cont = true
					} else {
						doLiteral = true
					}
				} else if options&PCRE2_EXTENDED_MORE != 0 && (c == xCHAR_SPACE || c == xCHAR_HT) {
					cont = true
				} else if c == xCHAR_LEFT_SQUARE_BRACKET && ptrend-ptr >= 3 &&
					(pat[ptr] == xCHAR_COLON || pat[ptr] == xCHAR_DOT || pat[ptr] == xCHAR_EQUALS_SIGN) &&
					check_posix_syntax(pat, ptr, ptrend, &tempptr) {
					// POSIX class names
					posixNegate := false
					if classRangeState == xRANGE_STARTED {
						return fail(xERR50)
					}
					if pat[ptr] != xCHAR_COLON {
						return failBack(xERR13)
					}
					ptr++
					if pat[ptr] == xCHAR_CIRCUMFLEX_ACCENT {
						posixNegate = true
						ptr++
					}
					posixClass := check_posix_name(pat, ptr, tempptr-ptr)
					if posixClass < 0 {
						return fail(xERR30)
					}
					ptr = tempptr + 2

					if ptr < ptrend-1 && pat[ptr] == xCHAR_MINUS && pat[ptr+1] != xCHAR_RIGHT_SQUARE_BRACKET {
						return fail(xERR50)
					}
					classRangeState = xRANGE_NO

					handled := false
					if options&PCRE2_UCP != 0 && xoptions&PCRE2_EXTRA_ASCII_POSIX == 0 &&
						!(xoptions&PCRE2_EXTRA_ASCII_DIGIT != 0 && (posixClass == xPC_DIGIT || posixClass == xPC_XDIGIT)) {
						ptype := int(posix_substitutes[2*posixClass])
						pvalue := int(posix_substitutes[2*posixClass+1])
						if ptype >= 0 {
							if posixNegate {
								put(xMETA_ESCAPE + xESC_P)
							} else {
								put(xMETA_ESCAPE + xESC_p)
							}
							put(uint32(ptype)<<16 | uint32(pvalue))
							handled = true
						} else if pvalue != 0 {
							if posixNegate {
								put(xMETA_ESCAPE + xESC_H)
							} else {
								put(xMETA_ESCAPE + xESC_h)
							}
							handled = true
						}
					}
					if !handled {
						if posixNegate {
							put(xMETA_POSIX_NEG)
						} else {
							put(xMETA_POSIX)
						}
						put(uint32(posixClass))
					}
				} else if c == xCHAR_MINUS && classRangeState >= xRANGE_OK_ESCAPED {
					if classRangeState == xRANGE_OK_LITERAL {
						put(xMETA_RANGE_LITERAL)
					} else {
						put(xMETA_RANGE_ESCAPED)
					}
					classRangeState = xRANGE_STARTED
				} else if c != xCHAR_BACKSLASH {
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
							c = xCHAR_BACKSLASH
						} else {
							c, ptr = xGETCHARINCTEST(utf, pat, ptr)
						}
						escape = 0
					}

					switch escape {
					case 0:
						charIsLiteral = false
						doLiteral = true
					case xESC_b:
						c = xCHAR_BS
						charIsLiteral = false
						doLiteral = true
					case xESC_Q:
						inescq = true
						cont = true
					case xESC_E:
						cont = true
					case xESC_B, xESC_R, xESC_X:
						ptr--
						return fail(xERR7)
					}

					if !doLiteral && !cont {
						if classRangeState == xRANGE_STARTED {
							return fail(xERR50)
						}
						classRangeState = xRANGE_NO
						switch escape {
						case xESC_N:
							return fail(xERR71)
						case xESC_H, xESC_h, xESC_V, xESC_v:
							put(xMETA_ESCAPE + uint32(escape))
						case xESC_d, xESC_D, xESC_s, xESC_S, xESC_w, xESC_W:
							pp = parse_handle_escdsw(escape, pp, options, xoptions, cb)
						case xESC_P, xESC_p:
							var negated bool
							var ptype, pdata uint16
							if !get_ucp(pat, &ptr, &negated, &ptype, &pdata, &errorcode, cb) {
								return fail(errorcode)
							}
							if negated {
								if escape == xESC_P {
									escape = xESC_p
								} else {
									escape = xESC_P
								}
							}
							put(xMETA_ESCAPE + uint32(escape))
							put(uint32(ptype)<<16 | uint32(pdata))
						default:
							ptr--
							return fail(xERR7)
						}

						if ptr < ptrend-1 && pat[ptr] == xCHAR_MINUS && pat[ptr+1] != xCHAR_RIGHT_SQUARE_BRACKET {
							return fail(xERR50)
						}
					}
				}

				if doLiteral { // CLASS_LITERAL (pcre2_compile.c:3743)
					if classRangeState == xRANGE_STARTED {
						if c == parsed[pp-2] { // optimize one-char range
							pp--
						} else if parsed[pp-2] > c {
							return failBack(xERR8)
						} else {
							if !charIsLiteral && parsed[pp-1] == xMETA_RANGE_LITERAL {
								parsed[pp-1] = xMETA_RANGE_ESCAPED
							}
							putLiteral(c)
						}
						classRangeState = xRANGE_NO
					} else {
						if charIsLiteral {
							classRangeState = xRANGE_OK_LITERAL
						} else {
							classRangeState = xRANGE_OK_ESCAPED
						}
						putLiteral(c)
					}
				}

				// CLASS_CONTINUE
				if ptr >= ptrend {
					return fail(xERR6)
				}
				c, ptr = xGETCHARINCTEST(utf, pat, ptr)
				if c == xCHAR_RIGHT_SQUARE_BRACKET && !inescq {
					break
				}
			}

			if classRangeState == xRANGE_STARTED {
				parsed[pp-1] = xCHAR_MINUS
				classRangeState = xRANGE_NO
			}
			put(xMETA_CLASS_END)

		// ---- Opening parenthesis ----
		case xCHAR_LEFT_PARENTHESIS:
			if ptr >= ptrend {
				return fail(xERR14)
			}

			if pat[ptr] != xCHAR_QUESTION_MARK {
				if pat[ptr] != xCHAR_ASTERISK {
					nestDepth++
					if options&PCRE2_NO_AUTO_CAPTURE == 0 {
						if cb.bracount >= xMAX_GROUP_NUMBER {
							return fail(xERR97)
						}
						cb.bracount++
						put(xMETA_CAPTURE | cb.bracount)
					} else {
						put(xMETA_NOCAPTURE)
					}
				} else if ptrend-ptr <= 1 || func() bool { c = uint32(pat[ptr+1]); return c == xCHAR_RIGHT_PARENTHESIS }() {
					break
				} else if c <= 255 && cb.ctypes[c]&ctype_lcletter != 0 {
					// alpha assertions
					vnOff := 0
					if !read_name(pat, &ptr, ptrend, utf, 0, &offset, &name, &namelen, &errorcode, cb) {
						return fail(errorcode)
					}
					if ptr >= ptrend || pat[ptr] != xCHAR_COLON {
						return fail(xERR95)
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
						return fail(xERR95)
					}

					meta := uint32(alasmeta[i].meta)
					if prevExpectCondAssert > 0 && (meta < xMETA_LOOKAHEAD || meta > xMETA_LOOKBEHINDNOT) {
						if meta == xMETA_LOOKAHEAD_NA || meta == xMETA_LOOKBEHIND_NA {
							return fail(xERR98)
						}
						return fail(xERR28)
					}

					switch meta {
					default:
						return fail(xERR89)
					case xMETA_ATOMIC:
						atomicGroup()
					case xMETA_LOOKAHEAD:
						put(xMETA_LOOKAHEAD)
						ptr++
						if e := postAssertion(); e != 0 {
							return e
						}
					case xMETA_LOOKAHEAD_NA:
						put(xMETA_LOOKAHEAD_NA)
						ptr++
						if e := postAssertion(); e != 0 {
							return e
						}
					case xMETA_LOOKAHEADNOT:
						put(xMETA_LOOKAHEADNOT)
						ptr++
						if e := postAssertion(); e != 0 {
							return e
						}
					case xMETA_LOOKBEHIND, xMETA_LOOKBEHINDNOT, xMETA_LOOKBEHIND_NA:
						put(meta)
						ptr--
						if e := postLookbehind(); e != 0 {
							return e
						}
					case xMETA_SCRIPT_RUN, xMETA_ATOMIC_SCRIPT_RUN:
						put(xMETA_SCRIPT_RUN)
						nestDepth++
						ptr++
						if meta == xMETA_ATOMIC_SCRIPT_RUN {
							put(xMETA_ATOMIC)
							if !pushNest(xNSF_ATOMICSR) {
								return fail(xERR84)
							}
						}
					}
				} else {
					// (*VERB) and (*VERB:NAME)
					vnOff := 0
					if !read_name(pat, &ptr, ptrend, utf, 0, &offset, &name, &namelen, &errorcode, cb) {
						return fail(errorcode)
					}
					if ptr >= ptrend || (pat[ptr] != xCHAR_COLON && pat[ptr] != xCHAR_RIGHT_PARENTHESIS) {
						return fail(xERR60)
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
						return fail(xERR60)
					}

					if pat[ptr] == xCHAR_COLON && ptr+1 < ptrend && pat[ptr+1] == xCHAR_RIGHT_PARENTHESIS {
						ptr++
					}
					if verbs[i].has_arg > 0 && pat[ptr] != xCHAR_COLON {
						return fail(xERR66)
					}

					verbstartptr = pp
					okquantifier = uint32(verbs[i].meta) == xMETA_ACCEPT

					skipped := pat[ptr]
					ptr++
					if skipped == xCHAR_COLON {
						if verbs[i].has_arg < 0 {
							addAfterMark = uint32(verbs[i].meta)
							put(xMETA_MARK)
						} else {
							v := uint32(verbs[i].meta)
							if v != xMETA_MARK {
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
				return fail(xERR14)
			}

			switch pat[ptr] {
			default:
				if pat[ptr] == xCHAR_MINUS && ptrend-ptr > 1 && parse_isdigit(pat[ptr+1]) {
					goto recursionByNumber
				}
				goto optionsOrReset

			case xCHAR_P:
				ptr++
				if ptr >= ptrend {
					return fail(xERR14)
				}
				if pat[ptr] == xCHAR_LESS_THAN_SIGN {
					if e := defineName(xCHAR_GREATER_THAN_SIGN); e != 0 {
						return e
					}
					break
				}
				if pat[ptr] == xCHAR_GREATER_THAN_SIGN {
					goto recurseByName
				}
				if pat[ptr] != xCHAR_EQUALS_SIGN {
					return fail(xERR41)
				}
				if !read_name(pat, &ptr, ptrend, utf, xCHAR_RIGHT_PARENTHESIS, &offset, &name, &namelen, &errorcode, cb) {
					return fail(errorcode)
				}
				put(xMETA_BACKREF_BYNAME)
				put(namelen)
				pp = parse_putoffset(parsed, pp, offset)
				okquantifier = true

			case xCHAR_R:
				i = 0
				ptr++
				if ptr >= ptrend || pat[ptr] != xCHAR_RIGHT_PARENTHESIS {
					return fail(xERR58)
				}
				setRecursion(i)

			case xCHAR_PLUS:
				if ptrend-ptr < 2 || !parse_isdigit(pat[ptr+1]) {
					return fail(xERR29)
				}
				goto recursionByNumber

			case xCHAR_0, xCHAR_1, xCHAR_2, xCHAR_3, xCHAR_4, xCHAR_5, xCHAR_6, xCHAR_7, xCHAR_8, xCHAR_9:
				goto recursionByNumber

			case xCHAR_AMPERSAND:
				goto recurseByName

			case xCHAR_C:
				ptr++
				if ptr >= ptrend {
					return fail(xERR14)
				}
				expectCondAssert = prevExpectCondAssert - 1

				if previousCallout >= 0 && options&PCRE2_AUTO_CALLOUT != 0 &&
					previousCallout == pp-4 && parsed[pp-1] == 255 {
					pp = previousCallout
				}

				previousCallout = pp
				afterManual = 1

				if pat[ptr] != xCHAR_RIGHT_PARENTHESIS && !parse_isdigit(pat[ptr]) {
					startptr := ptr
					delimiter = 0
					for i = 0; callout_start_delims[i] != 0; i++ {
						if uint32(pat[ptr]) == callout_start_delims[i] {
							delimiter = callout_end_delims[i]
							break
						}
					}
					if delimiter == 0 {
						return fail(xERR82)
					}
					parsed[pp] = xMETA_CALLOUT_STRING
					pp += 3
					for {
						ptr++
						if ptr >= ptrend {
							ptr = startptr
							return fail(xERR81)
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
						return fail(xERR72)
					}
					put(uint32(calloutlength))
					pp = parse_putoffset(parsed, pp, uint64(startptr))
				} else {
					n := 0
					parsed[pp] = xMETA_CALLOUT_NUMBER
					pp += 3
					for ptr < ptrend && parse_isdigit(pat[ptr]) {
						n = n*10 + int(pat[ptr]) - xCHAR_0
						ptr++
						if n > 255 {
							return fail(xERR38)
						}
					}
					put(uint32(n))
				}

				if ptr >= ptrend || pat[ptr] != xCHAR_RIGHT_PARENTHESIS {
					return fail(xERR39)
				}
				ptr++
				parsed[previousCallout+1] = uint32(ptr)
				parsed[previousCallout+2] = 0

			case xCHAR_LEFT_PARENTHESIS:
				ptr++
				if ptr >= ptrend {
					return fail(xERR14)
				}
				nestDepth++

				if pat[ptr] == xCHAR_QUESTION_MARK || pat[ptr] == xCHAR_ASTERISK {
					put(xMETA_COND_ASSERT)
					ptr--
					expectCondAssert = 2
					break
				}

				if read_number(pat, &ptr, ptrend, int32(cb.bracount), xMAX_GROUP_NUMBER, xERR61, &i, &errorcode) {
					if i <= 0 {
						return fail(xERR15)
					}
					put(xMETA_COND_NUMBER)
					off := uint64(ptr - 2)
					pp = parse_putoffset(parsed, pp, off)
					put(uint32(i))
				} else if errorcode != 0 {
					return fail(errorcode)
				} else if ptrend-ptr >= 10 && strncmp_c8(pat[ptr:], "VERSION", 7) == 0 &&
					pat[ptr+7] != xCHAR_RIGHT_PARENTHESIS {
					var ge uint32
					var major, minor int
					ptr += 7
					if pat[ptr] == xCHAR_GREATER_THAN_SIGN {
						ge = 1
						ptr++
					}
					if pat[ptr] != xCHAR_EQUALS_SIGN {
						return fail(xERR79)
					}
					ptr++
					if !parse_isdigit(at(ptr)) {
						return fail(xERR79)
					}
					if !read_number(pat, &ptr, ptrend, -1, 1000, xERR79, &major, &errorcode) {
						return fail(errorcode)
					}
					if ptr >= ptrend {
						return fail(xERR79)
					}
					if pat[ptr] == xCHAR_DOT {
						ptr++
						if ptr >= ptrend || !parse_isdigit(pat[ptr]) {
							return fail(xERR79)
						}
						minor = (int(pat[ptr]) - xCHAR_0) * 10
						ptr++
						if ptr >= ptrend {
							return fail(xERR79)
						}
						if parse_isdigit(pat[ptr]) {
							minor += int(pat[ptr]) - xCHAR_0
							ptr++
						}
						if ptr >= ptrend || pat[ptr] != xCHAR_RIGHT_PARENTHESIS {
							return fail(xERR79)
						}
					}
					put(xMETA_COND_VERSION)
					put(ge)
					put(uint32(major))
					put(uint32(minor))
				} else {
					wasRAmpersand := false
					if pat[ptr] == xCHAR_R && ptrend-ptr > 1 && pat[ptr+1] == xCHAR_AMPERSAND {
						terminator = xCHAR_RIGHT_PARENTHESIS
						wasRAmpersand = true
						ptr++
					} else if pat[ptr] == xCHAR_LESS_THAN_SIGN {
						terminator = xCHAR_GREATER_THAN_SIGN
					} else if pat[ptr] == xCHAR_APOSTROPHE {
						terminator = xCHAR_APOSTROPHE
					} else {
						terminator = xCHAR_RIGHT_PARENTHESIS
						ptr--
					}
					if !read_name(pat, &ptr, ptrend, utf, terminator, &offset, &name, &namelen, &errorcode, cb) {
						return fail(errorcode)
					}

					var meta uint32
					if wasRAmpersand {
						meta = xMETA_COND_RNAME
						ptr--
					} else if terminator == xCHAR_RIGHT_PARENTHESIS {
						if namelen == 6 && strncmp_c8(pat[name:], "DEFINE", 6) == 0 {
							meta = xMETA_COND_DEFINE
						} else {
							for i = 1; i < int(namelen); i++ {
								if !parse_isdigit(pat[name+i]) {
									break
								}
							}
							if pat[name] == xCHAR_R && i >= int(namelen) {
								meta = xMETA_COND_RNUMBER
							} else {
								meta = xMETA_COND_NAME
							}
						}
						ptr--
					} else {
						meta = xMETA_COND_NAME
					}
					put(meta)
					if meta != xMETA_COND_DEFINE {
						put(namelen)
					}
					pp = parse_putoffset(parsed, pp, offset)
				}

				if ptr >= ptrend || pat[ptr] != xCHAR_RIGHT_PARENTHESIS {
					return fail(xERR24)
				}
				ptr++

			case xCHAR_GREATER_THAN_SIGN:
				atomicGroup()

			case xCHAR_EQUALS_SIGN:
				put(xMETA_LOOKAHEAD)
				ptr++
				if e := postAssertion(); e != 0 {
					return e
				}

			case xCHAR_ASTERISK:
				put(xMETA_LOOKAHEAD_NA)
				ptr++
				if e := postAssertion(); e != 0 {
					return e
				}

			case xCHAR_EXCLAMATION_MARK:
				put(xMETA_LOOKAHEADNOT)
				ptr++
				if e := postAssertion(); e != 0 {
					return e
				}

			case xCHAR_LESS_THAN_SIGN:
				if ptrend-ptr <= 1 ||
					(pat[ptr+1] != xCHAR_EQUALS_SIGN && pat[ptr+1] != xCHAR_EXCLAMATION_MARK &&
						pat[ptr+1] != xCHAR_ASTERISK) {
					if e := defineName(xCHAR_GREATER_THAN_SIGN); e != 0 {
						return e
					}
					break
				}
				switch pat[ptr+1] {
				case xCHAR_EQUALS_SIGN:
					put(xMETA_LOOKBEHIND)
				case xCHAR_EXCLAMATION_MARK:
					put(xMETA_LOOKBEHINDNOT)
				default:
					put(xMETA_LOOKBEHIND_NA)
				}
				if e := postLookbehind(); e != 0 {
					return e
				}

			case xCHAR_APOSTROPHE:
				if e := defineName(xCHAR_APOSTROPHE); e != 0 {
					return e
				}
			}
			break // end of ( handling

		optionsOrReset:
			// (?| or an option setting (pcre2_compile.c:4169).
			nestDepth++
			if !pushNest(0) {
				return fail(xERR84)
			}
			if pat[ptr] == xCHAR_VERTICAL_LINE {
				nests[topNest].resetGroup = uint16(cb.bracount)
				nests[topNest].maxGroup = uint16(cb.bracount)
				nests[topNest].flags |= xNSF_RESET
				cb.externalFlags |= PCRE2_DUPCAPUSED
				put(xMETA_NOCAPTURE)
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

				if ptr < ptrend && pat[ptr] == xCHAR_CIRCUMFLEX_ACCENT {
					options &^= PCRE2_CASELESS | PCRE2_MULTILINE | PCRE2_NO_AUTO_CAPTURE |
						PCRE2_DOTALL | PCRE2_EXTENDED | PCRE2_EXTENDED_MORE
					xoptions &^= PCRE2_EXTRA_CASELESS_RESTRICT
					hyphenok = false
					ptr++
				}

				for ptr < ptrend && pat[ptr] != xCHAR_RIGHT_PARENTHESIS && pat[ptr] != xCHAR_COLON {
					ch := pat[ptr]
					ptr++
					switch ch {
					case xCHAR_MINUS:
						if !hyphenok {
							ptr--
							return fail(xERR94)
						}
						optset = &unset
						xoptset = &xunset
						hyphenok = false

					case xCHAR_a:
						if ptr < ptrend {
							if pat[ptr] == xCHAR_D {
								*xoptset |= PCRE2_EXTRA_ASCII_BSD
								ptr++
								break
							}
							if pat[ptr] == xCHAR_P {
								*xoptset |= PCRE2_EXTRA_ASCII_POSIX | PCRE2_EXTRA_ASCII_DIGIT
								ptr++
								break
							}
							if pat[ptr] == xCHAR_S {
								*xoptset |= PCRE2_EXTRA_ASCII_BSS
								ptr++
								break
							}
							if pat[ptr] == xCHAR_T {
								*xoptset |= PCRE2_EXTRA_ASCII_DIGIT
								ptr++
								break
							}
							if pat[ptr] == xCHAR_W {
								*xoptset |= PCRE2_EXTRA_ASCII_BSW
								ptr++
								break
							}
						}
						*xoptset |= PCRE2_EXTRA_ASCII_BSD | PCRE2_EXTRA_ASCII_BSS |
							PCRE2_EXTRA_ASCII_BSW | PCRE2_EXTRA_ASCII_DIGIT | PCRE2_EXTRA_ASCII_POSIX

					case xCHAR_J:
						*optset |= PCRE2_DUPNAMES
						cb.externalFlags |= PCRE2_JCHANGED
					case xCHAR_i:
						*optset |= PCRE2_CASELESS
					case xCHAR_m:
						*optset |= PCRE2_MULTILINE
					case xCHAR_n:
						*optset |= PCRE2_NO_AUTO_CAPTURE
					case xCHAR_r:
						*xoptset |= PCRE2_EXTRA_CASELESS_RESTRICT
					case xCHAR_s:
						*optset |= PCRE2_DOTALL
					case xCHAR_U:
						*optset |= PCRE2_UNGREEDY
					case xCHAR_x:
						*optset |= PCRE2_EXTENDED
						if ptr < ptrend && pat[ptr] == xCHAR_x {
							*optset |= PCRE2_EXTENDED_MORE
							ptr++
						}
					default:
						ptr--
						return fail(xERR11)
					}
				}

				if set&(PCRE2_EXTENDED|PCRE2_EXTENDED_MORE) == PCRE2_EXTENDED || unset&PCRE2_EXTENDED != 0 {
					unset |= PCRE2_EXTENDED_MORE
				}
				options = (options | set) &^ unset
				xoptions = (xoptions | xset) &^ xunset

				if ptr >= ptrend {
					return fail(xERR14)
				}
				endch := pat[ptr]
				ptr++
				if endch == xCHAR_RIGHT_PARENTHESIS {
					nestDepth--
					if topNest > 0 && nests[topNest-1].nestDepth == nestDepth {
						topNest--
					} else {
						nests[topNest].nestDepth = nestDepth
					}
				} else {
					put(xMETA_NOCAPTURE)
				}

				if options != oldoptions || xoptions != oldxoptions {
					put(xMETA_OPTIONS)
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
				if !read_number(pat, &ptr, ptrend, allow, xMAX_GROUP_NUMBER, xERR61, &i, &errorcode) {
					return fail(errorcode)
				}
				if i < 0 {
					return failBack(xERR15)
				}
				if ptr >= ptrend || pat[ptr] != xCHAR_RIGHT_PARENTHESIS {
					return fail(xERR14)
				}
				setRecursion(i)
			}
			break

		recurseByName:
			if !read_name(pat, &ptr, ptrend, utf, xCHAR_RIGHT_PARENTHESIS, &offset, &name, &namelen, &errorcode, cb) {
				return fail(errorcode)
			}
			put(xMETA_RECURSE_BYNAME)
			put(namelen)
			pp = parse_putoffset(parsed, pp, offset)
			okquantifier = true

		// ---- Branch terminators ----
		case xCHAR_VERTICAL_LINE:
			if topNest >= 0 && nests[topNest].nestDepth == nestDepth &&
				nests[topNest].flags&xNSF_RESET != 0 {
				if cb.bracount > uint32(nests[topNest].maxGroup) {
					nests[topNest].maxGroup = uint16(cb.bracount)
				}
				cb.bracount = uint32(nests[topNest].resetGroup)
			}
			put(xMETA_ALT)

		case xCHAR_RIGHT_PARENTHESIS:
			okquantifier = true
			if topNest >= 0 && nests[topNest].nestDepth == nestDepth {
				options = (options &^ xPARSE_TRACKED_OPTIONS) | nests[topNest].options
				xoptions = (xoptions &^ xPARSE_TRACKED_EXTRA_OPTIONS) | nests[topNest].xoptions
				if nests[topNest].flags&xNSF_RESET != 0 && uint32(nests[topNest].maxGroup) > cb.bracount {
					cb.bracount = uint32(nests[topNest].maxGroup)
				}
				if nests[topNest].flags&xNSF_CONDASSERT != 0 {
					okquantifier = false
				}
				if nests[topNest].flags&xNSF_ATOMICSR != 0 {
					put(xMETA_KET)
				}
				if topNest == 0 {
					topNest = -1
				} else {
					topNest--
				}
			}
			if nestDepth == 0 {
				return failBack(xERR22)
			}
			nestDepth--
			put(xMETA_KET)
		}
		continue mainLoop
	}

	// End of pattern reached. Check for missing ) at the end of a verb name.
	if inverbname && ptr >= ptrend {
		return fail(xERR60)
	}
	return finish()
}
