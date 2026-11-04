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
		meta := META_CODE(pp[pptr])
		switch meta {
		default:
			if meta < META_END {
				continue
			}
		case META_END:
			return -1
		case META_BACKREF:
			if META_DATA(pp[pptr]) >= 10 {
				pptr += SIZEOFFSET
			}
		case META_ESCAPE:
			switch META_DATA(pp[pptr]) {
			case ESC_P, ESC_p:
				pptr += 1
			case ESC_g, ESC_k:
				pptr += 1 + SIZEOFFSET
			}
		case META_MARK, META_COMMIT_ARG, META_PRUNE_ARG, META_SKIP_ARG, META_THEN_ARG:
			pptr += int(pp[pptr+1])
		case META_CLASS_END:
			if skiptype == PSKIP_CLASS {
				return pptr
			}
		case META_ATOMIC, META_CAPTURE, META_COND_ASSERT, META_COND_DEFINE,
			META_COND_NAME, META_COND_NUMBER, META_COND_RNAME, META_COND_RNUMBER,
			META_COND_VERSION, META_LOOKAHEAD, META_LOOKAHEADNOT, META_LOOKAHEAD_NA,
			META_LOOKBEHIND, META_LOOKBEHINDNOT, META_LOOKBEHIND_NA, META_NOCAPTURE,
			META_SCRIPT_RUN:
			nestlevel++
		case META_ALT:
			if nestlevel == 0 && skiptype == PSKIP_ALT {
				return pptr
			}
		case META_KET:
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
		if groupinfo&GI_NOT_FIXED_LENGTH != 0 {
			return -1
		}
		if groupinfo&GI_SET_FIXED_LENGTH != 0 {
			if isinline {
				*pptrptr = parsed_skip(cb.parsedPattern, *pptrptr, PSKIP_KET)
			}
			*minptr = int(gi[1])
			return int(groupinfo & GI_FIXED_LENGTH_MASK)
		}
	}

	for {
		var branchminlength int
		branchlength := get_branchlength(pptrptr, &branchminlength, errcodeptr, lcptr, recurses, cb)
		if branchlength < 0 {
			if group > 0 {
				gi[0] |= GI_NOT_FIXED_LENGTH
			}
			return -1
		}
		if branchlength > grouplength {
			grouplength = branchlength
		}
		if branchminlength < groupminlength {
			groupminlength = branchminlength
		}
		if cb.parsedPattern[*pptrptr] == META_KET {
			break
		}
		*pptrptr += 1
	}

	if group > 0 {
		gi[0] |= GI_SET_FIXED_LENGTH | uint32(grouplength)
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
		*errcodeptr = ERR35
		return -1
	}

	for ; ; pptr++ {
		var group uint32
		var itemlength, itemminlength uint32
		var min, max uint32
		label := glNone

		if pp[pptr] < META_END {
			itemlength, itemminlength = 1, 1
		} else {
			code := META_CODE(pp[pptr])
			switch code {
			case META_KET, META_ALT:
				goto exit

			case META_ACCEPT, META_FAIL:
				pptr = parsed_skip(pp, pptr, PSKIP_ALT)
				if pptr < 0 {
					*errcodeptr = ERR90
					return -1
				}
				goto exit

			case META_MARK, META_COMMIT_ARG, META_PRUNE_ARG, META_SKIP_ARG, META_THEN_ARG:
				pptr += int(pp[pptr+1]) + 1

			case META_CIRCUMFLEX, META_COMMIT, META_DOLLAR, META_PRUNE, META_SKIP, META_THEN:

			case META_OPTIONS:
				pptr += 2

			case META_BIGVALUE:
				itemlength, itemminlength = 1, 1
				pptr += 1

			case META_CLASS, META_CLASS_NOT:
				itemlength, itemminlength = 1, 1
				pptr = parsed_skip(pp, pptr, PSKIP_CLASS)
				if pptr < 0 {
					*errcodeptr = ERR90
					return -1
				}

			case META_CLASS_EMPTY_NOT, META_DOT:
				itemlength, itemminlength = 1, 1

			case META_CALLOUT_NUMBER:
				pptr += 3

			case META_CALLOUT_STRING:
				pptr += 3 + SIZEOFFSET

			case META_ESCAPE:
				escape := META_DATA(pp[pptr])
				if escape == ESC_X {
					return -1
				}
				if escape == ESC_R {
					itemminlength = 1
					itemlength = 2
				} else if escape > ESC_b && escape < ESC_Z {
					if (cb.externalOptions&PCRE2_UTF) != 0 && escape == ESC_C {
						*errcodeptr = ERR36
						return -1
					}
					itemlength, itemminlength = 1, 1
					if escape == ESC_p || escape == ESC_P {
						pptr++
					}
				}

			case META_LOOKAHEAD, META_LOOKAHEADNOT, META_LOOKAHEAD_NA:
				*errcodeptr = check_lookbehinds(pptr+1, &pptr, recurses, cb, lcptr)
				if *errcodeptr != 0 {
					return -1
				}
				switch pp[pptr+1] {
				case META_ASTERISK, META_ASTERISK_PLUS, META_ASTERISK_QUERY,
					META_PLUS, META_PLUS_PLUS, META_PLUS_QUERY,
					META_QUERY, META_QUERY_PLUS, META_QUERY_QUERY:
					pptr++
				case META_MINMAX, META_MINMAX_PLUS, META_MINMAX_QUERY:
					pptr += 3
				}

			case META_LOOKBEHIND, META_LOOKBEHINDNOT, META_LOOKBEHIND_NA:
				if !set_lookbehind_lengths(&pptr, errcodeptr, lcptr, recurses, cb) {
					return -1
				}

			case META_BACKREF_BYNAME, META_RECURSE_BYNAME:
				if code == META_BACKREF_BYNAME && (cb.externalOptions&PCRE2_MATCH_UNSET_BACKREF) != 0 {
					label = glNotFixed
					break
				}
				{
					isDupname := false
					metaCode := META_CODE(pp[pptr])
					pptr++
					length := pp[pptr]
					offset, pptr = GETPLUSOFFSET(pp, pptr)
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
						*errcodeptr = ERR15
						cb.erroroffset = offset
						return -1
					}
					if metaCode == META_RECURSE_BYNAME ||
						(!isDupname && (cb.externalFlags&PCRE2_DUPCAPUSED) == 0) {
						label = glRecurseOrBackref
					} else {
						label = glNotFixed
					}
				}

			case META_BACKREF:
				if (cb.externalOptions&PCRE2_MATCH_UNSET_BACKREF) != 0 ||
					(cb.externalFlags&PCRE2_DUPCAPUSED) != 0 {
					label = glNotFixed
					break
				}
				group = META_DATA(pp[pptr])
				if group < 10 {
					offset = cb.smallRefOffset[group]
					label = glRecurseOrBackref
					break
				}
				fallthrough

			case META_RECURSE:
				group = META_DATA(pp[pptr])
				offset, pptr = GETPLUSOFFSET(pp, pptr)
				label = glRecurseOrBackref

			case META_COND_DEFINE:
				pptr = parsed_skip(pp, pptr+1, PSKIP_KET)
				if pptr < 0 {
					// C would dereference NULL later; report as skip failure.
					*errcodeptr = ERR90
					return -1
				}

			case META_COND_NAME, META_COND_NUMBER, META_COND_RNAME, META_COND_RNUMBER:
				pptr += 2 + SIZEOFFSET
				label = glCheckGroup

			case META_COND_ASSERT:
				pptr += 1
				label = glCheckGroup

			case META_COND_VERSION:
				pptr += 4
				label = glCheckGroup

			case META_CAPTURE:
				group = META_DATA(pp[pptr])
				pptr++
				label = glCheckGroup

			case META_ATOMIC, META_NOCAPTURE, META_SCRIPT_RUN:
				pptr++
				label = glCheckGroup

			case META_QUERY, META_QUERY_PLUS, META_QUERY_QUERY:
				min, max = 0, 1
				label = glRepetition

			case META_MINMAX, META_MINMAX_PLUS, META_MINMAX_QUERY:
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
					*errcodeptr = ERR15
					return -1
				}
				if group == 0 {
					*errcodeptr = ERR25
					return -1
				}
				gptr := 0
				for ; pp[gptr] != META_END; gptr++ {
					if META_CODE(pp[gptr]) == META_BIGVALUE {
						gptr++
					} else if pp[gptr] == (META_CAPTURE | group) {
						break
					}
				}
				gptrend := parsed_skip(pp, gptr+1, PSKIP_KET)
				if gptrend < 0 {
					*errcodeptr = ERR90
					return -1
				}
				if pptr > gptr && pptr < gptrend {
					*errcodeptr = ERR25
					return -1
				}
				var r *parsed_recurse_check
				for r = recurses; r != nil; r = r.prev {
					if r.groupptr == gptr {
						break
					}
				}
				if r != nil {
					*errcodeptr = ERR25
					return -1
				}
				thisRecurse := parsed_recurse_check{prev: recurses, groupptr: gptr}
				gptr++
				var groupminlength int
				grouplength := get_grouplength(&gptr, &groupminlength, false, errcodeptr,
					lcptr, int(group), &thisRecurse, cb)
				if grouplength < 0 {
					if *errcodeptr == 0 {
						*errcodeptr = ERR25
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
				if max != REPEAT_UNLIMITED {
					if lastitemlength != 0 && max != 0 &&
						uint32((intMax-branchlength))/lastitemlength < max-1 {
						*errcodeptr = ERR87
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
				*errcodeptr = ERR25
				return -1

			case glNotFixed:
				*errcodeptr = ERR25
				return -1
			}
		}

		if intMax-branchlength < int(int32(itemlength)) {
			*errcodeptr = ERR87
			return -1
		}
		branchlength += int(int32(itemlength))
		if branchlength > LOOKBEHIND_MAX {
			*errcodeptr = ERR87
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

	offset := READPLUSOFFSET(pp, bptr)
	*pptrptr += SIZEOFFSET

	for {
		*pptrptr += 1
		var branchminlength int
		branchlength := get_branchlength(pptrptr, &branchminlength, errcodeptr, lcptr, recurses, cb)
		if branchlength < 0 {
			if *errcodeptr == 0 {
				*errcodeptr = ERR25
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
		if META_CODE(pp[bptr]) != META_ALT {
			break
		}
	}

	if variable {
		pp[gbptr+1] = uint32(minlength)
		if uint32(maxlength) > cb.maxVarlookbehind {
			*errcodeptr = ERR100
			cb.erroroffset = offset
			return false
		}
	} else {
		pp[gbptr+1] = LOOKBEHIND_MAX
	}
	// pcre2_compile.c:9935 repeats the assignment.
	if variable {
		pp[gbptr+1] = uint32(minlength)
	} else {
		pp[gbptr+1] = LOOKBEHIND_MAX
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

	for ; pp[pptr] != META_END; pptr++ {
		if pp[pptr] < META_END {
			continue
		}
		switch META_CODE(pp[pptr]) {
		default:
			return ERR70

		case META_ESCAPE:
			if pp[pptr]-META_ESCAPE == ESC_P || pp[pptr]-META_ESCAPE == ESC_p {
				pptr += 1
			}

		case META_KET:
			nestlevel--
			if nestlevel < 0 {
				if retptr != nil {
					*retptr = pptr
				}
				return 0
			}

		case META_ATOMIC, META_CAPTURE, META_COND_ASSERT, META_LOOKAHEAD,
			META_LOOKAHEADNOT, META_LOOKAHEAD_NA, META_NOCAPTURE, META_SCRIPT_RUN:
			nestlevel++

		case META_ACCEPT, META_ALT, META_ASTERISK, META_ASTERISK_PLUS,
			META_ASTERISK_QUERY, META_BACKREF, META_CIRCUMFLEX, META_CLASS,
			META_CLASS_EMPTY, META_CLASS_EMPTY_NOT, META_CLASS_END, META_CLASS_NOT,
			META_COMMIT, META_DOLLAR, META_DOT, META_FAIL, META_PLUS, META_PLUS_PLUS,
			META_PLUS_QUERY, META_PRUNE, META_QUERY, META_QUERY_PLUS, META_QUERY_QUERY,
			META_RANGE_ESCAPED, META_RANGE_LITERAL, META_SKIP, META_THEN:

		case META_RECURSE:
			pptr += SIZEOFFSET

		case META_BACKREF_BYNAME, META_RECURSE_BYNAME:
			pptr += 1 + SIZEOFFSET

		case META_COND_DEFINE:
			pptr += SIZEOFFSET
			nestlevel++

		case META_COND_NAME, META_COND_NUMBER, META_COND_RNAME, META_COND_RNUMBER:
			pptr += 1 + SIZEOFFSET
			nestlevel++

		case META_COND_VERSION:
			pptr += 3
			nestlevel++

		case META_CALLOUT_STRING:
			pptr += 3 + SIZEOFFSET

		case META_BIGVALUE, META_POSIX, META_POSIX_NEG:
			pptr += 1

		case META_MINMAX, META_MINMAX_QUERY, META_MINMAX_PLUS, META_OPTIONS:
			pptr += 2

		case META_CALLOUT_NUMBER:
			pptr += 3

		case META_MARK, META_COMMIT_ARG, META_PRUNE_ARG, META_SKIP_ARG, META_THEN_ARG:
			pptr += 1 + int(pp[pptr+1])

		case META_LOOKBEHIND, META_LOOKBEHINDNOT, META_LOOKBEHIND_NA:
			if !set_lookbehind_lengths(&pptr, &errorcode, lcptr, recurses, cb) {
				return errorcode
			}
		}
	}
	return 0
}
