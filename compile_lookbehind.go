package pcre2

// Lookbehind length checking: pcre2_compile.c:9227-10102. A parsed-pattern
// pointer is an int index into cb.parsedPattern; NULL is -1.

// parsed_recurse_check is the chain used to catch mutual recursion
// (pcre2_intmodedep.h:688).
type parsed_recurse_check struct {
	prev     *parsed_recurse_check
	groupptr int
}

// recurse_cache is used when filling in pattern recursion offsets
// (pcre2_intmodedep.h:696).
type recurse_cache struct {
	group       int
	groupnumber int
}

const intMax = 0x7fffffff

// parsed_skip is parsed_skip() (pcre2_compile.c:9249). Returns -1 for NULL.
func parsed_skip(pp []uint32, pptr int, skiptype uint32) int {
	var nestlevel uint32
	for ; ; pptr++ {
		meta := xMETA_CODE(pp[pptr])
		switch meta {
		default:
			if meta < xMETA_END {
				continue
			}
		case xMETA_END:
			return -1
		case xMETA_BACKREF:
			if xMETA_DATA(pp[pptr]) >= 10 {
				pptr += xSIZEOFFSET
			}
		case xMETA_ESCAPE:
			switch xMETA_DATA(pp[pptr]) {
			case xESC_P, xESC_p:
				pptr += 1
			case xESC_g, xESC_k:
				pptr += 1 + xSIZEOFFSET
			}
		case xMETA_MARK, xMETA_COMMIT_ARG, xMETA_PRUNE_ARG, xMETA_SKIP_ARG, xMETA_THEN_ARG:
			pptr += int(pp[pptr+1])
		case xMETA_CLASS_END:
			if skiptype == xPSKIP_CLASS {
				return pptr
			}
		case xMETA_ATOMIC, xMETA_CAPTURE, xMETA_COND_ASSERT, xMETA_COND_DEFINE,
			xMETA_COND_NAME, xMETA_COND_NUMBER, xMETA_COND_RNAME, xMETA_COND_RNUMBER,
			xMETA_COND_VERSION, xMETA_LOOKAHEAD, xMETA_LOOKAHEADNOT, xMETA_LOOKAHEAD_NA,
			xMETA_LOOKBEHIND, xMETA_LOOKBEHINDNOT, xMETA_LOOKBEHIND_NA, xMETA_NOCAPTURE,
			xMETA_SCRIPT_RUN:
			nestlevel++
		case xMETA_ALT:
			if nestlevel == 0 && skiptype == xPSKIP_ALT {
				return pptr
			}
		case xMETA_KET:
			if nestlevel == 0 {
				return pptr
			}
			nestlevel--
		}
		meta = (meta >> 16) & 0x7fff
		if int(meta) >= len(meta_extra_lengths) {
			return -1
		}
		pptr += int(meta_extra_lengths[meta])
	}
}

// get_grouplength is get_grouplength() (pcre2_compile.c:9368).
func get_grouplength(pptrptr *int, minptr *int, isinline bool, errcodeptr *int,
	lcptr *int, group int, recurses *parsed_recurse_check, cb *compile_block) int {
	gi := cb.groupinfo[2*group:]
	grouplength := -1
	groupminlength := intMax

	if group > 0 && (cb.externalFlags&PCRE2_DUPCAPUSED) == 0 {
		groupinfo := gi[0]
		if groupinfo&xGI_NOT_FIXED_LENGTH != 0 {
			return -1
		}
		if groupinfo&xGI_SET_FIXED_LENGTH != 0 {
			if isinline {
				*pptrptr = parsed_skip(cb.parsedPattern, *pptrptr, xPSKIP_KET)
			}
			*minptr = int(gi[1])
			return int(groupinfo & xGI_FIXED_LENGTH_MASK)
		}
	}

	for {
		var branchminlength int
		branchlength := get_branchlength(pptrptr, &branchminlength, errcodeptr, lcptr, recurses, cb)
		if branchlength < 0 {
			if group > 0 {
				gi[0] |= xGI_NOT_FIXED_LENGTH
			}
			return -1
		}
		if branchlength > grouplength {
			grouplength = branchlength
		}
		if branchminlength < groupminlength {
			groupminlength = branchminlength
		}
		if cb.parsedPattern[*pptrptr] == xMETA_KET {
			break
		}
		*pptrptr += 1
	}

	if group > 0 {
		gi[0] |= xGI_SET_FIXED_LENGTH | uint32(grouplength)
		gi[1] = uint32(groupminlength)
	}
	*minptr = groupminlength
	return grouplength
}

// Pseudo labels for the gotos of get_branchlength.
const (
	glNone = iota
	glRecurseOrBackref
	glCheckGroup
	glRepetition
	glNotFixed
)

// get_branchlength is get_branchlength() (pcre2_compile.c:9442).
func get_branchlength(pptrptr *int, minptr *int, errcodeptr *int, lcptr *int,
	recurses *parsed_recurse_check, cb *compile_block) int {
	pp := cb.parsedPattern
	branchlength := 0
	branchminlength := 0
	var lastitemlength, lastitemminlength uint32
	pptr := *pptrptr
	var offset uint64

	*lcptr++
	if *lcptr-1 > 2000 {
		*errcodeptr = xERR35
		return -1
	}

	for ; ; pptr++ {
		var group uint32
		var itemlength, itemminlength uint32
		var min, max uint32
		label := glNone

		if pp[pptr] < xMETA_END {
			itemlength, itemminlength = 1, 1
		} else {
			code := xMETA_CODE(pp[pptr])
			switch code {
			case xMETA_KET, xMETA_ALT:
				goto exit

			case xMETA_ACCEPT, xMETA_FAIL:
				pptr = parsed_skip(pp, pptr, xPSKIP_ALT)
				if pptr < 0 {
					*errcodeptr = xERR90
					return -1
				}
				goto exit

			case xMETA_MARK, xMETA_COMMIT_ARG, xMETA_PRUNE_ARG, xMETA_SKIP_ARG, xMETA_THEN_ARG:
				pptr += int(pp[pptr+1]) + 1

			case xMETA_CIRCUMFLEX, xMETA_COMMIT, xMETA_DOLLAR, xMETA_PRUNE, xMETA_SKIP, xMETA_THEN:

			case xMETA_OPTIONS:
				pptr += 2

			case xMETA_BIGVALUE:
				itemlength, itemminlength = 1, 1
				pptr += 1

			case xMETA_CLASS, xMETA_CLASS_NOT:
				itemlength, itemminlength = 1, 1
				pptr = parsed_skip(pp, pptr, xPSKIP_CLASS)
				if pptr < 0 {
					*errcodeptr = xERR90
					return -1
				}

			case xMETA_CLASS_EMPTY_NOT, xMETA_DOT:
				itemlength, itemminlength = 1, 1

			case xMETA_CALLOUT_NUMBER:
				pptr += 3

			case xMETA_CALLOUT_STRING:
				pptr += 3 + xSIZEOFFSET

			case xMETA_ESCAPE:
				escape := xMETA_DATA(pp[pptr])
				if escape == xESC_X {
					return -1
				}
				if escape == xESC_R {
					itemminlength = 1
					itemlength = 2
				} else if escape > xESC_b && escape < xESC_Z {
					if (cb.externalOptions&PCRE2_UTF) != 0 && escape == xESC_C {
						*errcodeptr = xERR36
						return -1
					}
					itemlength, itemminlength = 1, 1
					if escape == xESC_p || escape == xESC_P {
						pptr++
					}
				}

			case xMETA_LOOKAHEAD, xMETA_LOOKAHEADNOT, xMETA_LOOKAHEAD_NA:
				*errcodeptr = check_lookbehinds(pptr+1, &pptr, recurses, cb, lcptr)
				if *errcodeptr != 0 {
					return -1
				}
				switch pp[pptr+1] {
				case xMETA_ASTERISK, xMETA_ASTERISK_PLUS, xMETA_ASTERISK_QUERY,
					xMETA_PLUS, xMETA_PLUS_PLUS, xMETA_PLUS_QUERY,
					xMETA_QUERY, xMETA_QUERY_PLUS, xMETA_QUERY_QUERY:
					pptr++
				case xMETA_MINMAX, xMETA_MINMAX_PLUS, xMETA_MINMAX_QUERY:
					pptr += 3
				}

			case xMETA_LOOKBEHIND, xMETA_LOOKBEHINDNOT, xMETA_LOOKBEHIND_NA:
				if !set_lookbehind_lengths(&pptr, errcodeptr, lcptr, recurses, cb) {
					return -1
				}

			case xMETA_BACKREF_BYNAME, xMETA_RECURSE_BYNAME:
				if code == xMETA_BACKREF_BYNAME && (cb.externalOptions&PCRE2_MATCH_UNSET_BACKREF) != 0 {
					label = glNotFixed
					break
				}
				{
					isDupname := false
					metaCode := xMETA_CODE(pp[pptr])
					pptr++
					length := pp[pptr]
					offset, pptr = xGETPLUSOFFSET(pp, pptr)
					name := cb.startPattern[offset:]
					for i := 0; i < int(cb.namesFound); i++ {
						ng := &cb.namedGroups[i]
						if length == uint32(ng.length) && strncmp(name, ng.name, uint64(length)) == 0 {
							group = ng.number
							isDupname = ng.isdup != 0
							break
						}
					}
					if group == 0 {
						*errcodeptr = xERR15
						cb.erroroffset = offset
						return -1
					}
					if metaCode == xMETA_RECURSE_BYNAME ||
						(!isDupname && (cb.externalFlags&PCRE2_DUPCAPUSED) == 0) {
						label = glRecurseOrBackref
					} else {
						label = glNotFixed
					}
				}

			case xMETA_BACKREF:
				if (cb.externalOptions&PCRE2_MATCH_UNSET_BACKREF) != 0 ||
					(cb.externalFlags&PCRE2_DUPCAPUSED) != 0 {
					label = glNotFixed
					break
				}
				group = xMETA_DATA(pp[pptr])
				if group < 10 {
					offset = cb.smallRefOffset[group]
					label = glRecurseOrBackref
					break
				}
				fallthrough

			case xMETA_RECURSE:
				group = xMETA_DATA(pp[pptr])
				offset, pptr = xGETPLUSOFFSET(pp, pptr)
				label = glRecurseOrBackref

			case xMETA_COND_DEFINE:
				pptr = parsed_skip(pp, pptr+1, xPSKIP_KET)
				if pptr < 0 {
					// C would dereference NULL later; report as skip failure.
					*errcodeptr = xERR90
					return -1
				}

			case xMETA_COND_NAME, xMETA_COND_NUMBER, xMETA_COND_RNAME, xMETA_COND_RNUMBER:
				pptr += 2 + xSIZEOFFSET
				label = glCheckGroup

			case xMETA_COND_ASSERT:
				pptr += 1
				label = glCheckGroup

			case xMETA_COND_VERSION:
				pptr += 4
				label = glCheckGroup

			case xMETA_CAPTURE:
				group = xMETA_DATA(pp[pptr])
				pptr++
				label = glCheckGroup

			case xMETA_ATOMIC, xMETA_NOCAPTURE, xMETA_SCRIPT_RUN:
				pptr++
				label = glCheckGroup

			case xMETA_QUERY, xMETA_QUERY_PLUS, xMETA_QUERY_QUERY:
				min, max = 0, 1
				label = glRepetition

			case xMETA_MINMAX, xMETA_MINMAX_PLUS, xMETA_MINMAX_QUERY:
				min = pp[pptr+1]
				max = pp[pptr+2]
				pptr += 2
				label = glRepetition

			default:
				label = glNotFixed
			}

			switch label {
			case glRecurseOrBackref:
				if group > cb.bracount {
					cb.erroroffset = offset
					*errcodeptr = xERR15
					return -1
				}
				if group == 0 {
					*errcodeptr = xERR25
					return -1
				}
				gptr := 0
				for ; pp[gptr] != xMETA_END; gptr++ {
					if xMETA_CODE(pp[gptr]) == xMETA_BIGVALUE {
						gptr++
					} else if pp[gptr] == (xMETA_CAPTURE | group) {
						break
					}
				}
				gptrend := parsed_skip(pp, gptr+1, xPSKIP_KET)
				if gptrend < 0 {
					*errcodeptr = xERR90
					return -1
				}
				if pptr > gptr && pptr < gptrend {
					*errcodeptr = xERR25
					return -1
				}
				var r *parsed_recurse_check
				for r = recurses; r != nil; r = r.prev {
					if r.groupptr == gptr {
						break
					}
				}
				if r != nil {
					*errcodeptr = xERR25
					return -1
				}
				thisRecurse := parsed_recurse_check{prev: recurses, groupptr: gptr}
				gptr++
				var groupminlength int
				grouplength := get_grouplength(&gptr, &groupminlength, false, errcodeptr,
					lcptr, int(group), &thisRecurse, cb)
				if grouplength < 0 {
					if *errcodeptr == 0 {
						*errcodeptr = xERR25
					}
					return -1
				}
				itemlength = uint32(grouplength)
				itemminlength = uint32(groupminlength)

			case glCheckGroup:
				var groupminlength int
				grouplength := get_grouplength(&pptr, &groupminlength, true, errcodeptr,
					lcptr, int(group), recurses, cb)
				if grouplength < 0 {
					return -1
				}
				itemlength = uint32(grouplength)
				itemminlength = uint32(groupminlength)

			case glRepetition:
				if max != xREPEAT_UNLIMITED {
					if lastitemlength != 0 && max != 0 &&
						uint32((intMax-branchlength))/lastitemlength < max-1 {
						*errcodeptr = xERR87
						return -1
					}
					if min == 0 {
						branchminlength -= int(lastitemminlength)
					} else {
						itemminlength = (min - 1) * lastitemminlength
					}
					if max == 0 {
						branchlength -= int(lastitemlength)
					} else {
						itemlength = (max - 1) * lastitemlength
					}
					break
				}
				*errcodeptr = xERR25
				return -1

			case glNotFixed:
				*errcodeptr = xERR25
				return -1
			}
		}

		if intMax-branchlength < int(int32(itemlength)) {
			*errcodeptr = xERR87
			return -1
		}
		branchlength += int(int32(itemlength))
		if branchlength > xLOOKBEHIND_MAX {
			*errcodeptr = xERR87
			return -1
		}
		branchminlength += int(int32(itemminlength))

		lastitemlength = itemlength
		lastitemminlength = itemminlength
	}

exit:
	*pptrptr = pptr
	*minptr = branchminlength
	return branchlength
}

// set_lookbehind_lengths is set_lookbehind_lengths() (pcre2_compile.c:9872).
func set_lookbehind_lengths(pptrptr *int, errcodeptr *int, lcptr *int,
	recurses *parsed_recurse_check, cb *compile_block) bool {
	pp := cb.parsedPattern
	bptr := *pptrptr
	gbptr := bptr
	maxlength := 0
	minlength := intMax
	variable := false

	offset := xREADPLUSOFFSET(pp, bptr)
	*pptrptr += xSIZEOFFSET

	for {
		*pptrptr += 1
		var branchminlength int
		branchlength := get_branchlength(pptrptr, &branchminlength, errcodeptr, lcptr, recurses, cb)
		if branchlength < 0 {
			if *errcodeptr == 0 {
				*errcodeptr = xERR25
			}
			if cb.erroroffset == PCRE2_UNSET {
				cb.erroroffset = offset
			}
			return false
		}
		if branchlength != branchminlength {
			variable = true
		}
		if branchminlength < minlength {
			minlength = branchminlength
		}
		if branchlength > maxlength {
			maxlength = branchlength
		}
		if branchlength > cb.maxLookbehind {
			cb.maxLookbehind = branchlength
		}
		pp[bptr] |= uint32(branchlength)
		bptr = *pptrptr
		if xMETA_CODE(pp[bptr]) != xMETA_ALT {
			break
		}
	}

	if variable {
		pp[gbptr+1] = uint32(minlength)
		if uint32(maxlength) > cb.maxVarlookbehind {
			*errcodeptr = xERR100
			cb.erroroffset = offset
			return false
		}
	} else {
		pp[gbptr+1] = xLOOKBEHIND_MAX
	}
	// pcre2_compile.c:9935 repeats the assignment.
	if variable {
		pp[gbptr+1] = uint32(minlength)
	} else {
		pp[gbptr+1] = xLOOKBEHIND_MAX
	}
	return true
}

// check_lookbehinds is check_lookbehinds() (pcre2_compile.c:9965).
func check_lookbehinds(pptr int, retptr *int, recurses *parsed_recurse_check,
	cb *compile_block, lcptr *int) int {
	pp := cb.parsedPattern
	errorcode := 0
	nestlevel := 0

	cb.erroroffset = PCRE2_UNSET

	for ; pp[pptr] != xMETA_END; pptr++ {
		if pp[pptr] < xMETA_END {
			continue
		}
		switch xMETA_CODE(pp[pptr]) {
		default:
			return xERR70

		case xMETA_ESCAPE:
			if pp[pptr]-xMETA_ESCAPE == xESC_P || pp[pptr]-xMETA_ESCAPE == xESC_p {
				pptr += 1
			}

		case xMETA_KET:
			nestlevel--
			if nestlevel < 0 {
				if retptr != nil {
					*retptr = pptr
				}
				return 0
			}

		case xMETA_ATOMIC, xMETA_CAPTURE, xMETA_COND_ASSERT, xMETA_LOOKAHEAD,
			xMETA_LOOKAHEADNOT, xMETA_LOOKAHEAD_NA, xMETA_NOCAPTURE, xMETA_SCRIPT_RUN:
			nestlevel++

		case xMETA_ACCEPT, xMETA_ALT, xMETA_ASTERISK, xMETA_ASTERISK_PLUS,
			xMETA_ASTERISK_QUERY, xMETA_BACKREF, xMETA_CIRCUMFLEX, xMETA_CLASS,
			xMETA_CLASS_EMPTY, xMETA_CLASS_EMPTY_NOT, xMETA_CLASS_END, xMETA_CLASS_NOT,
			xMETA_COMMIT, xMETA_DOLLAR, xMETA_DOT, xMETA_FAIL, xMETA_PLUS, xMETA_PLUS_PLUS,
			xMETA_PLUS_QUERY, xMETA_PRUNE, xMETA_QUERY, xMETA_QUERY_PLUS, xMETA_QUERY_QUERY,
			xMETA_RANGE_ESCAPED, xMETA_RANGE_LITERAL, xMETA_SKIP, xMETA_THEN:

		case xMETA_RECURSE:
			pptr += xSIZEOFFSET

		case xMETA_BACKREF_BYNAME, xMETA_RECURSE_BYNAME:
			pptr += 1 + xSIZEOFFSET

		case xMETA_COND_DEFINE:
			pptr += xSIZEOFFSET
			nestlevel++

		case xMETA_COND_NAME, xMETA_COND_NUMBER, xMETA_COND_RNAME, xMETA_COND_RNUMBER:
			pptr += 1 + xSIZEOFFSET
			nestlevel++

		case xMETA_COND_VERSION:
			pptr += 3
			nestlevel++

		case xMETA_CALLOUT_STRING:
			pptr += 3 + xSIZEOFFSET

		case xMETA_BIGVALUE, xMETA_POSIX, xMETA_POSIX_NEG:
			pptr += 1

		case xMETA_MINMAX, xMETA_MINMAX_QUERY, xMETA_MINMAX_PLUS, xMETA_OPTIONS:
			pptr += 2

		case xMETA_CALLOUT_NUMBER:
			pptr += 3

		case xMETA_MARK, xMETA_COMMIT_ARG, xMETA_PRUNE_ARG, xMETA_SKIP_ARG, xMETA_THEN_ARG:
			pptr += 1 + int(pp[pptr+1])

		case xMETA_LOOKBEHIND, xMETA_LOOKBEHINDNOT, xMETA_LOOKBEHIND_NA:
			if !set_lookbehind_lengths(&pptr, &errorcode, lcptr, recurses, cb) {
				return errorcode
			}
		}
	}
	return 0
}
