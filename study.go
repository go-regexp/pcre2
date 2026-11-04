// Port of pcre2_study.c: scanning a compiled pattern and collecting data (the
// minimum matching length and the set of possible starting code units). C
// pointers into the opcodes are an index into the slice returned by
// re.startCode() (the offsets inside compiled code are relative to it, so
// C's "startcode" is index 0); NULL is -1.
package pcre2

// MAX_CACHE_BACKREF is the maximum remembered capturing brackets minimum
// (pcre2_study.c:53).
const MAX_CACHE_BACKREF = 128

const uint16Max = 0xffff // UINT16_MAX

// Returns from set_start_bits() (pcre2_study.c:61).
const (
	SSB_FAIL = iota
	SSB_DONE
	SSB_CONTINUE
	SSB_UNKNOWN
	SSB_TOODEEP
)

// studyRecurseCheck is recurse_check (pcre2_intmodedep.h:684-687): a chain used
// to catch mutual recursion; group is an index into the code.
type studyRecurseCheck struct {
	prev  *studyRecurseCheck
	group int
}

// SET_BIT sets a bit in the starting code unit bit map. (pcre2_study.c:57)
func (re *Code) setBit(c uint32) {
	re.startBitmap[c/8] |= 1 << (c & 7)
}

// find_minlength scans a parenthesized group and computes the minimum length of
// subject that is needed to match it. code is the whole opcode slice and cc0
// the index of the start of the group (the bracket). It returns the minimum
// length, -1 for \C in UTF-8 mode or (*ACCEPT) or a pattern too complicated, -2
// for an internal error (missing capturing bracket), -3 for an internal error
// (opcode not listed). (pcre2_study.c:102-762)
func find_minlength(re *Code, code []byte, cc0 int, utf bool, recurses *studyRecurseCheck,
	countptr *int, backref_cache []int) int {
	length := -1
	branchlength := 0
	prev_cap_recno := -1
	prev_cap_d := 0
	prev_recurse_recno := -1
	prev_recurse_d := 0
	once_fudge := 0
	had_recurse := false
	dupcapused := re.flags&PCRE2_DUPCAPUSED != 0
	nextbranch := cc0 + GET(code, cc0+1)
	cc := cc0 + 1 + LINK_SIZE
	var this_recurse studyRecurseCheck

	// If this is a "could be empty" group, its minimum length is 0.

	if code[cc0] >= OP_SBRA && code[cc0] <= OP_SCOND {
		return 0
	}

	// Skip over capturing bracket number

	if code[cc0] == OP_CBRA || code[cc0] == OP_CBRAPOS {
		cc += IMM2_SIZE
	}

	// A large and/or complex regex can take too long to process.

	*countptr++
	if *countptr-1 > 1000 {
		return -1
	}

	// processNonCapture is the PROCESS_NON_CAPTURE label. It returns a negative
	// d to be returned by the caller.
	processNonCapture := func() int {
		d := find_minlength(re, code, cc, utf, recurses, countptr, backref_cache)
		if d < 0 {
			return d
		}
		branchlength += d
		for {
			cc += GET(code, cc+1)
			if code[cc] != OP_ALT {
				break
			}
		}
		cc += 1 + LINK_SIZE
		return 0
	}

	// repeatBackReference is the REPEAT_BACK_REFERENCE label.
	repeatBackReference := func(d int) {
		var min int
		switch code[cc] {
		case OP_CRSTAR, OP_CRMINSTAR, OP_CRQUERY, OP_CRMINQUERY,
			OP_CRPOSSTAR, OP_CRPOSQUERY:
			min = 0
			cc++

		case OP_CRPLUS, OP_CRMINPLUS, OP_CRPOSPLUS:
			min = 1
			cc++

		case OP_CRRANGE, OP_CRMINRANGE, OP_CRPOSRANGE:
			min = GET2(code, cc+1)
			cc += 1 + 2*IMM2_SIZE

		default:
			min = 1
		}

		// Take care not to overflow: (1) min and d are ints, so check that their
		// product is not greater than INT_MAX. (2) branchlength is limited to
		// UINT16_MAX (checked at the top of the loop).

		if (d > 0 && (0x7fffffff/d) < min) || uint16Max-branchlength < min*d {
			branchlength = uint16Max
		} else {
			branchlength += min * d
		}
	}

	// Scan along the opcodes for this branch. If we get to the end of the branch,
	// check the length against that of the other branches. If the accumulated
	// length passes 16-bits, reset to that value and skip the rest of the branch.

	for {
		var d, recno int

		if branchlength >= uint16Max {
			branchlength = uint16Max
			cc = nextbranch
		}

		op := code[cc]
		switch op {
		case OP_COND, OP_SCOND:
			// If there is only one branch in a condition, the implied branch has
			// zero length, so we don't add anything. This covers the DEFINE
			// "condition" automatically. If there are two branches we can treat
			// it the same as any other non-capturing subpattern.

			cs := cc + GET(code, cc+1)
			if code[cs] != OP_ALT {
				cc = cs + 1 + LINK_SIZE
				break
			}
			if d = processNonCapture(); d < 0 {
				return d
			}

		case OP_BRA:
			// There's a special case of OP_BRA, when it is wrapped round a
			// repeated OP_RECURSE. We'd like to process the latter at this level
			// so that remembering the value works for repeated cases. So we do
			// nothing, but set a fudge value to skip over the OP_KET after the
			// recurse.

			if code[cc+1+LINK_SIZE] == OP_RECURSE && code[cc+2*(1+LINK_SIZE)] == OP_KET {
				once_fudge = 1 + LINK_SIZE
				cc += 1 + LINK_SIZE
				break
			}
			if d = processNonCapture(); d < 0 {
				return d
			}

		case OP_ONCE, OP_SCRIPT_RUN, OP_SBRA, OP_BRAPOS, OP_SBRAPOS:
			if d = processNonCapture(); d < 0 {
				return d
			}

		// To save time for repeated capturing subpatterns, we remember the
		// length of the previous one. Unfortunately we can't do the same for
		// the unnumbered ones above. Nor can we do this if (?| is present in the
		// pattern because captures with the same number are not then identical.

		case OP_CBRA, OP_SCBRA, OP_CBRAPOS, OP_SCBRAPOS:
			recno = GET2(code, cc+1+LINK_SIZE)
			if dupcapused || recno != prev_cap_recno {
				prev_cap_recno = recno
				prev_cap_d = find_minlength(re, code, cc, utf, recurses, countptr, backref_cache)
				if prev_cap_d < 0 {
					return prev_cap_d
				}
			}
			branchlength += prev_cap_d
			for {
				cc += GET(code, cc+1)
				if code[cc] != OP_ALT {
					break
				}
			}
			cc += 1 + LINK_SIZE

		// ACCEPT makes things far too complicated; we have to give up. In fact,
		// from 10.34 onwards, if a pattern contains (*ACCEPT), this function is
		// not used. However, leave the code in place, just in case.

		case OP_ACCEPT, OP_ASSERT_ACCEPT:
			return -1

		// Reached end of a branch; if it's a ket it is the end of a nested
		// call. If it's ALT it is an alternation in a nested call. If it is END
		// it's the end of the outer call. All can be handled by the same code. If
		// the length of any branch is zero, there is no need to scan any
		// subsequent branches.

		case OP_ALT, OP_KET, OP_KETRMAX, OP_KETRMIN, OP_KETRPOS, OP_END:
			if length < 0 || (!had_recurse && branchlength < length) {
				length = branchlength
			}
			if op != OP_ALT || length == 0 {
				return length
			}
			nextbranch = cc + GET(code, cc+1)
			cc += 1 + LINK_SIZE
			branchlength = 0
			had_recurse = false

		// Skip over assertive subpatterns

		case OP_ASSERT, OP_ASSERT_NOT, OP_ASSERTBACK, OP_ASSERTBACK_NOT,
			OP_ASSERT_NA, OP_ASSERTBACK_NA:
			for {
				cc += GET(code, cc+1)
				if code[cc] != OP_ALT {
					break
				}
			}
			cc += int(OP_lengths[code[cc]])

		// Skip over things that don't match chars

		case OP_REVERSE, OP_VREVERSE, OP_CREF, OP_DNCREF, OP_RREF, OP_DNRREF,
			OP_FALSE, OP_TRUE, OP_CALLOUT, OP_SOD, OP_SOM, OP_EOD, OP_EODN,
			OP_CIRC, OP_CIRCM, OP_DOLL, OP_DOLLM, OP_NOT_WORD_BOUNDARY,
			OP_WORD_BOUNDARY, OP_NOT_UCP_WORD_BOUNDARY, OP_UCP_WORD_BOUNDARY:
			cc += int(OP_lengths[code[cc]])

		case OP_CALLOUT_STR:
			cc += GET(code, cc+1+2*LINK_SIZE)

		// Skip over a subpattern that has a {0} or {0,x} quantifier

		case OP_BRAZERO, OP_BRAMINZERO, OP_BRAPOSZERO, OP_SKIPZERO:
			cc += int(OP_lengths[code[cc]])
			for {
				cc += GET(code, cc+1)
				if code[cc] != OP_ALT {
					break
				}
			}
			cc += 1 + LINK_SIZE

		// Handle literal characters and + repetitions

		case OP_CHAR, OP_CHARI, OP_NOT, OP_NOTI, OP_PLUS, OP_PLUSI, OP_MINPLUS,
			OP_MINPLUSI, OP_POSPLUS, OP_POSPLUSI, OP_NOTPLUS, OP_NOTPLUSI,
			OP_NOTMINPLUS, OP_NOTMINPLUSI, OP_NOTPOSPLUS, OP_NOTPOSPLUSI:
			branchlength++
			cc += 2
			if utf && HAS_EXTRALEN(uint32(code[cc-1])) {
				cc += GET_EXTRALEN(uint32(code[cc-1]))
			}

		case OP_TYPEPLUS, OP_TYPEMINPLUS, OP_TYPEPOSPLUS:
			branchlength++
			if code[cc+1] == OP_PROP || code[cc+1] == OP_NOTPROP {
				cc += 4
			} else {
				cc += 2
			}

		// Handle exact repetitions. The count is already in characters, but we
		// may need to skip over a multibyte character in UTF mode.

		case OP_EXACT, OP_EXACTI, OP_NOTEXACT, OP_NOTEXACTI:
			branchlength += GET2(code, cc+1)
			cc += 2 + IMM2_SIZE
			if utf && HAS_EXTRALEN(uint32(code[cc-1])) {
				cc += GET_EXTRALEN(uint32(code[cc-1]))
			}

		case OP_TYPEEXACT:
			branchlength += GET2(code, cc+1)
			if code[cc+1+IMM2_SIZE] == OP_PROP || code[cc+1+IMM2_SIZE] == OP_NOTPROP {
				cc += 2
			}
			cc += 2 + IMM2_SIZE

		// Handle single-char non-literal matchers

		case OP_PROP, OP_NOTPROP:
			cc += 2
			branchlength++
			cc++

		case OP_NOT_DIGIT, OP_DIGIT, OP_NOT_WHITESPACE, OP_WHITESPACE,
			OP_NOT_WORDCHAR, OP_WORDCHAR, OP_ANY, OP_ALLANY, OP_EXTUNI,
			OP_HSPACE, OP_NOT_HSPACE, OP_VSPACE, OP_NOT_VSPACE:
			branchlength++
			cc++

		// "Any newline" might match two characters, but it also might match just
		// one.

		case OP_ANYNL:
			branchlength += 1
			cc++

		// The single-byte matcher means we can't proceed in UTF mode. (In
		// non-UTF mode \C will actually be turned into OP_ALLANY, so won't ever
		// appear, but leave the code, just in case.)

		case OP_ANYBYTE:
			if utf {
				return -1
			}
			branchlength++
			cc++

		// For repeated character types, we have to test for \p and \P, which have
		// an extra two bytes of parameters.

		case OP_TYPESTAR, OP_TYPEMINSTAR, OP_TYPEQUERY, OP_TYPEMINQUERY,
			OP_TYPEPOSSTAR, OP_TYPEPOSQUERY:
			if code[cc+1] == OP_PROP || code[cc+1] == OP_NOTPROP {
				cc += 2
			}
			cc += int(OP_lengths[op])

		case OP_TYPEUPTO, OP_TYPEMINUPTO, OP_TYPEPOSUPTO:
			if code[cc+1+IMM2_SIZE] == OP_PROP || code[cc+1+IMM2_SIZE] == OP_NOTPROP {
				cc += 2
			}
			cc += int(OP_lengths[op])

		// Check a class for variable quantification

		case OP_CLASS, OP_NCLASS, OP_XCLASS:
			if op == OP_XCLASS {
				cc += GET(code, cc+1)
			} else {
				cc += int(OP_lengths[OP_CLASS])
			}

			switch code[cc] {
			case OP_CRPLUS, OP_CRMINPLUS, OP_CRPOSPLUS:
				branchlength++
				cc++

			case OP_CRSTAR, OP_CRMINSTAR, OP_CRQUERY, OP_CRMINQUERY,
				OP_CRPOSSTAR, OP_CRPOSQUERY:
				cc++

			case OP_CRRANGE, OP_CRMINRANGE, OP_CRPOSRANGE:
				branchlength += GET2(code, cc+1)
				cc += 1 + 2*IMM2_SIZE

			default:
				branchlength++
			}

		// Backreferences and subroutine calls (OP_RECURSE) are treated in the same
		// way: we find the minimum length for the subpattern. A recursion
		// (backreference or subroutine) causes an a flag to be set that causes the
		// length of this branch to be ignored. The logic is that a recursion can
		// only make sense if there is another alternative that stops the
		// recursing. That will provide the minimum length (when no recursion
		// happens).
		//
		// If PCRE2_MATCH_UNSET_BACKREF is set, a backreference to an unset bracket
		// matches an empty string (by default it causes a matching failure), so in
		// that case we must set the minimum length to zero.
		//
		// For backreferenes, if duplicate numbers are present in the pattern we
		// check for a reference to a duplicate. If it is, we don't know which
		// version will be referenced, so we have to set the minimum length to zero.

		// Duplicate named pattern back reference.

		case OP_DNREF, OP_DNREFI:
			if !dupcapused && re.overallOptions&PCRE2_MATCH_UNSET_BACKREF == 0 {
				count := GET2(code, cc+1+IMM2_SIZE)
				slot := GET2(code, cc+1) * int(re.nameEntrySize)

				d = 0x7fffffff // INT_MAX

				// Scan all groups with the same name; find the shortest.

				for ; count > 0; count-- {
					var dd int
					recno = GET2(re.code, slot)

					if recno <= backref_cache[0] && backref_cache[recno] >= 0 {
						dd = backref_cache[recno]
					} else {
						cs := find_bracket(code, 0, utf, recno)
						if cs < 0 {
							return -2
						}
						ce := cs
						for {
							ce += GET(code, ce+1)
							if code[ce] != OP_ALT {
								break
							}
						}

						dd = 0
						if !dupcapused || find_bracket(code, ce, utf, recno) < 0 {
							if cc > cs && cc < ce { // Simple recursion
								had_recurse = true
							} else {
								r := recurses
								for ; r != nil; r = r.prev {
									if r.group == cs {
										break
									}
								}
								if r != nil { // Mutual recursion
									had_recurse = true
								} else {
									this_recurse.prev = recurses // No recursion
									this_recurse.group = cs
									dd = find_minlength(re, code, cs, utf, &this_recurse,
										countptr, backref_cache)
									if dd < 0 {
										return dd
									}
								}
							}
						}

						backref_cache[recno] = dd
						for i := backref_cache[0] + 1; i < recno; i++ {
							backref_cache[i] = -1
						}
						backref_cache[0] = recno
					}

					if dd < d {
						d = dd
					}
					if d <= 0 {
						break // No point looking at any more
					}
					slot += int(re.nameEntrySize)
				}
			} else {
				d = 0
			}
			cc += 1 + 2*IMM2_SIZE
			repeatBackReference(d)

		// Single back reference by number. References by name are converted to by
		// number when there is no duplication.

		case OP_REF, OP_REFI:
			recno = GET2(code, cc+1)
			if recno <= backref_cache[0] && backref_cache[recno] >= 0 {
				d = backref_cache[recno]
			} else {
				d = 0

				if re.overallOptions&PCRE2_MATCH_UNSET_BACKREF == 0 {
					cs := find_bracket(code, 0, utf, recno)
					if cs < 0 {
						return -2
					}
					ce := cs
					for {
						ce += GET(code, ce+1)
						if code[ce] != OP_ALT {
							break
						}
					}

					if !dupcapused || find_bracket(code, ce, utf, recno) < 0 {
						if cc > cs && cc < ce { // Simple recursion
							had_recurse = true
						} else {
							r := recurses
							for ; r != nil; r = r.prev {
								if r.group == cs {
									break
								}
							}
							if r != nil { // Mutual recursion
								had_recurse = true
							} else { // No recursion
								this_recurse.prev = recurses
								this_recurse.group = cs
								d = find_minlength(re, code, cs, utf, &this_recurse, countptr,
									backref_cache)
								if d < 0 {
									return d
								}
							}
						}
					}
				}

				backref_cache[recno] = d
				for i := backref_cache[0] + 1; i < recno; i++ {
					backref_cache[i] = -1
				}
				backref_cache[0] = recno
			}

			cc += 1 + IMM2_SIZE

			// Handle repeated back references
			repeatBackReference(d)

		// Recursion always refers to the first occurrence of a subpattern with a
		// given number. Therefore, we can always make use of caching, even when
		// the pattern contains multiple subpatterns with the same number.

		case OP_RECURSE:
			cs := GET(code, cc+1)
			ce := cs
			recno = GET2(code, cs+1+LINK_SIZE)
			if recno == prev_recurse_recno {
				branchlength += prev_recurse_d
			} else {
				for {
					ce += GET(code, ce+1)
					if code[ce] != OP_ALT {
						break
					}
				}
				if cc > cs && cc < ce { // Simple recursion
					had_recurse = true
				} else {
					r := recurses
					for ; r != nil; r = r.prev {
						if r.group == cs {
							break
						}
					}
					if r != nil { // Mutual recursion
						had_recurse = true
					} else {
						this_recurse.prev = recurses
						this_recurse.group = cs
						prev_recurse_d = find_minlength(re, code, cs, utf, &this_recurse,
							countptr, backref_cache)
						if prev_recurse_d < 0 {
							return prev_recurse_d
						}
						prev_recurse_recno = recno
						branchlength += prev_recurse_d
					}
				}
			}
			cc += 1 + LINK_SIZE + once_fudge
			once_fudge = 0

		// Anything else does not or need not match a character. We can get the
		// item's length from the table, but for those that can match zero
		// occurrences of a character, we must take special action for UTF-8
		// characters. As it happens, the "NOT" versions of these opcodes are used
		// at present only for ASCII characters, so they could be omitted from this
		// list. However, in future that may change, so we include them here so as
		// not to leave a gotcha for a future maintainer.

		case OP_UPTO, OP_UPTOI, OP_NOTUPTO, OP_NOTUPTOI, OP_MINUPTO, OP_MINUPTOI,
			OP_NOTMINUPTO, OP_NOTMINUPTOI, OP_POSUPTO, OP_POSUPTOI, OP_NOTPOSUPTO,
			OP_NOTPOSUPTOI,

			OP_STAR, OP_STARI, OP_NOTSTAR, OP_NOTSTARI, OP_MINSTAR, OP_MINSTARI,
			OP_NOTMINSTAR, OP_NOTMINSTARI, OP_POSSTAR, OP_POSSTARI, OP_NOTPOSSTAR,
			OP_NOTPOSSTARI,

			OP_QUERY, OP_QUERYI, OP_NOTQUERY, OP_NOTQUERYI, OP_MINQUERY,
			OP_MINQUERYI, OP_NOTMINQUERY, OP_NOTMINQUERYI, OP_POSQUERY,
			OP_POSQUERYI, OP_NOTPOSQUERY, OP_NOTPOSQUERYI:
			cc += int(OP_lengths[op])
			if utf && HAS_EXTRALEN(uint32(code[cc-1])) {
				cc += GET_EXTRALEN(uint32(code[cc-1]))
			}

		// Skip these, but we need to add in the name length.

		case OP_MARK, OP_COMMIT_ARG, OP_PRUNE_ARG, OP_SKIP_ARG, OP_THEN_ARG:
			cc += int(OP_lengths[op]) + int(code[cc+1])

		// The remaining opcodes are just skipped over.

		case OP_CLOSE, OP_COMMIT, OP_FAIL, OP_PRUNE, OP_SET_SOM, OP_SKIP, OP_THEN:
			cc += int(OP_lengths[op])

		// This should not occur: we list all opcodes explicitly so that when
		// new ones get added they are properly considered.

		default:
			return -3
		}
	}
}

// set_table_bit sets a bit for the first code unit of the character at
// code[p], and also the corresponding bit for the other version of a letter if
// caseless. It returns the index after the character. (pcre2_study.c:783-845)
func set_table_bit(re *Code, code []byte, p int, caseless, utf, ucp bool) int {
	c := uint32(code[p]) // First code unit
	p++

	re.setBit(c)

	// In UTF-8 mode, pick up the remaining code units in order to find the end
	// of the character, even when caseless.

	if utf {
		if c >= 0xc0 {
			c, p = GETCHARINC(code, p-1)
		}
	}

	// If caseless, handle the other case of the character.

	if caseless {
		if utf || ucp {
			c = UCD_OTHERCASE(c)
			if utf {
				var buff [6]byte
				ord2utf(c, buff[:])
				re.setBit(uint32(buff[0]))
			} else if c < 256 {
				re.setBit(c)
			}
		} else if c <= 255 { // Not UTF or UCP: MAX_255(c)
			re.setBit(uint32(re.charTables()[fcc_offset+c]))
		}
	}

	return p
}

// set_type_bits sets starting bits for a positive character type. In UTF-8
// mode, we can only do a direct setting for bytes less than 128, as otherwise
// there can be confusion with bytes in the middle of UTF-8 characters.
// tableLimit is 32 for non-UTF-8, 16 for UTF-8. (pcre2_study.c:868-886)
func set_type_bits(re *Code, cbit_type int, table_limit uint32) {
	t := re.charTables()
	for c := uint32(0); c < table_limit; c++ {
		re.startBitmap[c] |= t[int(c)+cbits_offset+cbit_type]
	}
	if table_limit == 32 {
		return
	}
	for c := uint32(128); c < 256; c++ {
		if t[cbits_offset+int(c/8)]&(1<<(c&7)) != 0 {
			var buff [6]byte
			ord2utf(c, buff[:])
			re.setBit(uint32(buff[0]))
		}
	}
}

// set_nottype_bits sets starting bits for a negative character type such as \D.
// In UTF-8 mode, we have to set the bits for all high-valued characters.
// (pcre2_study.c:909-918)
func set_nottype_bits(re *Code, cbit_type int, table_limit uint32) {
	t := re.charTables()
	for c := uint32(0); c < table_limit; c++ {
		re.startBitmap[c] |= ^t[int(c)+cbits_offset+cbit_type]
	}
	if table_limit != 32 {
		for c := 24; c < 32; c++ {
			re.startBitmap[c] = 0xff
		}
	}
}

// ssbHSpace sets the bits of the first code units of horizontal space
// characters (the HSPACE blocks of pcre2_study.c:1348-1379 and 1487-1518).
func ssbHSpace(re *Code, utf bool) {
	re.setBit(CHAR_HT)
	re.setBit(CHAR_SPACE)

	// For the 8-bit library in UTF-8 mode, set the bits for the first code
	// units of horizontal space characters.
	if utf {
		re.setBit(0xC2) // For U+00A0
		re.setBit(0xE1) // For U+1680, U+180E
		re.setBit(0xE2) // For U+2000 - U+200A, U+202F, U+205F
		re.setBit(0xE3) // For U+3000
	} else {
		// For the 8-bit library not in UTF-8 mode, set the bit for 0xA0.
		re.setBit(0xA0)
	}
}

// ssbVSpace is the same for vertical space and \R (pcre2_study.c:1384-1413 and
// 1521-1550).
func ssbVSpace(re *Code, utf bool) {
	re.setBit(CHAR_LF)
	re.setBit(CHAR_VT)
	re.setBit(CHAR_FF)
	re.setBit(CHAR_CR)

	if utf {
		re.setBit(0xC2) // For U+0085 (NEL)
		re.setBit(0xE2) // For U+2028, U+2029
	} else {
		re.setBit(CHAR_NEL)
	}
}

// ssbClassTail is the code from HANDLE_CLASSMAP to the end of the class
// handling case of set_start_bits (pcre2_study.c:1679-1732). It returns the
// new tcode and try_next.
func ssbClassTail(re *Code, code []byte, tcode int, classmap []byte, utf bool) (int, bool) {
	// When wide characters are supported, classmap may be NULL. In UTF-8
	// (sic) mode, the bits in a class bit map correspond to character values,
	// not to byte values. However, the bit map we are constructing is for byte
	// values. So we have to do a conversion for characters whose code point is
	// greater than 127. In fact, there are only two possible starting bytes for
	// characters in the range 128 - 255.

	if classmap != nil {
		if utf {
			for c := 0; c < 16; c++ {
				re.startBitmap[c] |= classmap[c]
			}
			for c := uint32(128); c < 256; c++ {
				if classmap[c/8]&(1<<(c&7)) != 0 {
					d := (c >> 6) | 0xc0 // Set bit for this starter
					re.startBitmap[d/8] |= 1 << (d & 7)
					// and then skip on to the next relevant character.
					c = (c & 0xc0) + 0x40 - 1
				}
			}
		} else {
			// In all modes except UTF-8, the two bit maps are compatible.
			for c := 0; c < 32; c++ {
				re.startBitmap[c] |= classmap[c]
			}
		}
	}

	// Act on what follows the class. For a zero minimum repeat, continue;
	// otherwise stop processing.

	switch code[tcode] {
	case OP_CRSTAR, OP_CRMINSTAR, OP_CRQUERY, OP_CRMINQUERY, OP_CRPOSSTAR, OP_CRPOSQUERY:
		return tcode + 1, true

	case OP_CRRANGE, OP_CRMINRANGE, OP_CRPOSRANGE:
		if GET2(code, tcode+1) == 0 {
			return tcode + 1 + 2*IMM2_SIZE, true
		}
		return tcode, false
	}
	return tcode, false
}

// set_start_bits scans a compiled unanchored expression recursively and
// attempts to build a bitmap of the set of possible starting code units whose
// values are less than 256. code[pos] is the start of an expression. It returns
// SSB_FAIL (no starting code units found), SSB_DONE (mandatory starting code
// units found), SSB_CONTINUE (optional ones found), SSB_UNKNOWN (unrecognized
// opcode) or SSB_TOODEEP (recursion too deep). (pcre2_study.c:955-1741)
func set_start_bits(re *Code, code []byte, pos int, utf, ucp bool, depthptr *int) int {
	var c uint32
	yield := SSB_DONE

	table_limit := uint32(32)
	if utf {
		table_limit = 16
	}

	*depthptr++
	if *depthptr > 1000 {
		return SSB_TOODEEP
	}

	for {
		try_next := true
		tcode := pos + 1 + LINK_SIZE

		if code[pos] == OP_CBRA || code[pos] == OP_SCBRA ||
			code[pos] == OP_CBRAPOS || code[pos] == OP_SCBRAPOS {
			tcode += IMM2_SIZE
		}

		for try_next { // Loop for items in this branch
			var rc int
			var classmap []byte

			switch code[tcode] {
			// If we reach something we don't understand, it means a new opcode
			// has been created that hasn't been added to this function.
			// Hopefully this problem will be discovered during testing.

			default:
				return SSB_UNKNOWN

			// Fail for a valid opcode that implies no starting bits.

			case OP_ACCEPT, OP_ASSERT_ACCEPT, OP_ALLANY, OP_ANY, OP_ANYBYTE,
				OP_CIRCM, OP_CLOSE, OP_COMMIT, OP_COMMIT_ARG, OP_COND, OP_CREF,
				OP_FALSE, OP_TRUE, OP_DNCREF, OP_DNREF, OP_DNREFI, OP_DNRREF,
				OP_DOLL, OP_DOLLM, OP_END, OP_EOD, OP_EODN, OP_EXTUNI, OP_FAIL,
				OP_MARK, OP_NOT, OP_NOTEXACT, OP_NOTEXACTI, OP_NOTI,
				OP_NOTMINPLUS, OP_NOTMINPLUSI, OP_NOTMINQUERY, OP_NOTMINQUERYI,
				OP_NOTMINSTAR, OP_NOTMINSTARI, OP_NOTMINUPTO, OP_NOTMINUPTOI,
				OP_NOTPLUS, OP_NOTPLUSI, OP_NOTPOSPLUS, OP_NOTPOSPLUSI,
				OP_NOTPOSQUERY, OP_NOTPOSQUERYI, OP_NOTPOSSTAR, OP_NOTPOSSTARI,
				OP_NOTPOSUPTO, OP_NOTPOSUPTOI, OP_NOTPROP, OP_NOTQUERY,
				OP_NOTQUERYI, OP_NOTSTAR, OP_NOTSTARI, OP_NOTUPTO, OP_NOTUPTOI,
				OP_NOT_HSPACE, OP_NOT_VSPACE, OP_PRUNE, OP_PRUNE_ARG, OP_RECURSE,
				OP_REF, OP_REFI, OP_REVERSE, OP_VREVERSE, OP_RREF, OP_SCOND,
				OP_SET_SOM, OP_SKIP, OP_SKIP_ARG, OP_SOD, OP_SOM, OP_THEN,
				OP_THEN_ARG:
				return SSB_FAIL

			// OP_CIRC happens only at the start of an anchored branch (multiline
			// ^ uses OP_CIRCM). Skip over it.

			case OP_CIRC:
				tcode += int(OP_lengths[OP_CIRC])

			// A "real" property test implies no starting bits, but the fake
			// property PT_CLIST identifies a list of characters. These lists are
			// short, as they are used for characters with more than one "other
			// case", so there is no point in recognizing them for OP_NOTPROP.

			case OP_PROP:
				if code[tcode+1] != PT_CLIST {
					return SSB_FAIL
				}
				{
					p := int(code[tcode+2])
					for {
						c = ucd_caseless_sets[p]
						p++
						if c >= NOTACHAR {
							break
						}
						if utf {
							var buff [6]byte
							ord2utf(c, buff[:])
							c = uint32(buff[0])
						}
						if c > 0xff {
							re.setBit(0xff)
						} else {
							re.setBit(c)
						}
					}
				}
				try_next = false

			// We can ignore word boundary tests.

			case OP_WORD_BOUNDARY, OP_NOT_WORD_BOUNDARY, OP_UCP_WORD_BOUNDARY,
				OP_NOT_UCP_WORD_BOUNDARY:
				tcode++

			// For a positive lookahead assertion, inspect what immediately
			// follows, ignoring intermediate assertions and callouts. If the next
			// item is one that sets a mandatory character, skip this assertion.
			// Otherwise, treat it the same as other bracket groups.

			case OP_ASSERT, OP_ASSERT_NA:
				ncode := tcode + GET(code, tcode+1)
				for code[ncode] == OP_ALT {
					ncode += GET(code, ncode+1)
				}
				ncode += 1 + LINK_SIZE

				// Skip irrelevant items

				for done := false; !done; {
					switch code[ncode] {
					case OP_ASSERT, OP_ASSERT_NOT, OP_ASSERTBACK, OP_ASSERTBACK_NOT,
						OP_ASSERT_NA, OP_ASSERTBACK_NA:
						ncode += GET(code, ncode+1)
						for code[ncode] == OP_ALT {
							ncode += GET(code, ncode+1)
						}
						ncode += 1 + LINK_SIZE

					case OP_WORD_BOUNDARY, OP_NOT_WORD_BOUNDARY, OP_UCP_WORD_BOUNDARY,
						OP_NOT_UCP_WORD_BOUNDARY:
						ncode++

					case OP_CALLOUT:
						ncode += int(OP_lengths[OP_CALLOUT])

					case OP_CALLOUT_STR:
						ncode += GET(code, ncode+1+2*LINK_SIZE)

					default:
						done = true
					}
				}

				// Now check the next significant item.

				switch code[ncode] {
				case OP_PROP:
					if code[ncode+1] == PT_CLIST {
						tcode = ncode
						continue // With the following significant opcode
					}

				case OP_ANYNL, OP_CHAR, OP_CHARI, OP_EXACT, OP_EXACTI, OP_HSPACE,
					OP_MINPLUS, OP_MINPLUSI, OP_PLUS, OP_PLUSI, OP_POSPLUS,
					OP_POSPLUSI, OP_VSPACE,
					// Note that these types will only be present in non-UCP mode.
					OP_DIGIT, OP_NOT_DIGIT, OP_WORDCHAR, OP_NOT_WORDCHAR,
					OP_WHITESPACE, OP_NOT_WHITESPACE:
					tcode = ncode
					continue // With the following significant opcode
				}
				fallthrough

			// For a group bracket or a positive assertion without an immediately
			// following mandatory setting, recurse to set bits from within the
			// subpattern. If it can't find anything, we have to give up. If it
			// finds some mandatory character(s), we are done for this branch.
			// Otherwise, carry on scanning after the subpattern.

			case OP_BRA, OP_SBRA, OP_CBRA, OP_SCBRA, OP_BRAPOS, OP_SBRAPOS,
				OP_CBRAPOS, OP_SCBRAPOS, OP_ONCE, OP_SCRIPT_RUN:
				rc = set_start_bits(re, code, tcode, utf, ucp, depthptr)
				if rc == SSB_DONE {
					try_next = false
				} else if rc == SSB_CONTINUE {
					for {
						tcode += GET(code, tcode+1)
						if code[tcode] != OP_ALT {
							break
						}
					}
					tcode += 1 + LINK_SIZE
				} else {
					return rc // FAIL, UNKNOWN, or TOODEEP
				}

			// If we hit ALT or KET, it means we haven't found anything mandatory
			// in this branch, though we might have found something optional. For
			// ALT, we continue with the next alternative, but we have to arrange
			// that the final result from subpattern is SSB_CONTINUE rather than
			// SSB_DONE. For KET, return SSB_CONTINUE: if this is the top level,
			// that indicates failure, but after a nested subpattern, it causes
			// scanning to continue.

			case OP_ALT:
				yield = SSB_CONTINUE
				try_next = false

			case OP_KET, OP_KETRMAX, OP_KETRMIN, OP_KETRPOS:
				return SSB_CONTINUE

			// Skip over callout

			case OP_CALLOUT:
				tcode += int(OP_lengths[OP_CALLOUT])

			case OP_CALLOUT_STR:
				tcode += GET(code, tcode+1+2*LINK_SIZE)

			// Skip over lookbehind and negative lookahead assertions

			case OP_ASSERT_NOT, OP_ASSERTBACK, OP_ASSERTBACK_NOT, OP_ASSERTBACK_NA:
				for {
					tcode += GET(code, tcode+1)
					if code[tcode] != OP_ALT {
						break
					}
				}
				tcode += 1 + LINK_SIZE

			// BRAZERO does the bracket, but carries on.

			case OP_BRAZERO, OP_BRAMINZERO, OP_BRAPOSZERO:
				tcode++
				rc = set_start_bits(re, code, tcode, utf, ucp, depthptr)
				if rc == SSB_FAIL || rc == SSB_UNKNOWN || rc == SSB_TOODEEP {
					return rc
				}
				for {
					tcode += GET(code, tcode+1)
					if code[tcode] != OP_ALT {
						break
					}
				}
				tcode += 1 + LINK_SIZE

			// SKIPZERO skips the bracket.

			case OP_SKIPZERO:
				tcode++
				for {
					tcode += GET(code, tcode+1)
					if code[tcode] != OP_ALT {
						break
					}
				}
				tcode += 1 + LINK_SIZE

			// Single-char * or ? sets the bit and tries the next item

			case OP_STAR, OP_MINSTAR, OP_POSSTAR, OP_QUERY, OP_MINQUERY, OP_POSQUERY:
				tcode = set_table_bit(re, code, tcode+1, false, utf, ucp)

			case OP_STARI, OP_MINSTARI, OP_POSSTARI, OP_QUERYI, OP_MINQUERYI, OP_POSQUERYI:
				tcode = set_table_bit(re, code, tcode+1, true, utf, ucp)

			// Single-char upto sets the bit and tries the next

			case OP_UPTO, OP_MINUPTO, OP_POSUPTO:
				tcode = set_table_bit(re, code, tcode+1+IMM2_SIZE, false, utf, ucp)

			case OP_UPTOI, OP_MINUPTOI, OP_POSUPTOI:
				tcode = set_table_bit(re, code, tcode+1+IMM2_SIZE, true, utf, ucp)

			// At least one single char sets the bit and stops

			case OP_EXACT:
				tcode += IMM2_SIZE
				fallthrough

			case OP_CHAR, OP_PLUS, OP_MINPLUS, OP_POSPLUS:
				set_table_bit(re, code, tcode+1, false, utf, ucp)
				try_next = false

			case OP_EXACTI:
				tcode += IMM2_SIZE
				fallthrough

			case OP_CHARI, OP_PLUSI, OP_MINPLUSI, OP_POSPLUSI:
				set_table_bit(re, code, tcode+1, true, utf, ucp)
				try_next = false

			// Special spacing and line-terminating items. These recognize specific
			// lists of characters. The difference between VSPACE and ANYNL is that
			// the latter can match the two-character CRLF sequence, but that is not
			// relevant for finding the first character, so their code here is
			// identical.

			case OP_HSPACE:
				ssbHSpace(re, utf)
				try_next = false

			case OP_ANYNL, OP_VSPACE:
				ssbVSpace(re, utf)
				try_next = false

			// Single character types set the bits and stop. Note that if PCRE2_UCP
			// is set, we do not see these opcodes because \d etc are converted to
			// properties. Therefore, these apply in the case when only characters
			// less than 256 are recognized to match the types.

			case OP_NOT_DIGIT:
				set_nottype_bits(re, cbit_digit, table_limit)
				try_next = false

			case OP_DIGIT:
				set_type_bits(re, cbit_digit, table_limit)
				try_next = false

			case OP_NOT_WHITESPACE:
				set_nottype_bits(re, cbit_space, table_limit)
				try_next = false

			case OP_WHITESPACE:
				set_type_bits(re, cbit_space, table_limit)
				try_next = false

			case OP_NOT_WORDCHAR:
				set_nottype_bits(re, cbit_word, table_limit)
				try_next = false

			case OP_WORDCHAR:
				set_type_bits(re, cbit_word, table_limit)
				try_next = false

			// One or more character type fudges the pointer and restarts, knowing
			// it will hit a single character type and stop there.

			case OP_TYPEPLUS, OP_TYPEMINPLUS, OP_TYPEPOSPLUS:
				tcode++

			case OP_TYPEEXACT:
				tcode += 1 + IMM2_SIZE

			// Zero or more repeats of character types set the bits and then
			// try again.

			case OP_TYPEUPTO, OP_TYPEMINUPTO, OP_TYPEPOSUPTO:
				tcode += IMM2_SIZE
				fallthrough

			case OP_TYPESTAR, OP_TYPEMINSTAR, OP_TYPEPOSSTAR, OP_TYPEQUERY,
				OP_TYPEMINQUERY, OP_TYPEPOSQUERY:
				switch code[tcode+1] {
				default:
					return SSB_FAIL

				case OP_ANY, OP_ALLANY:
					return SSB_FAIL

				case OP_HSPACE:
					ssbHSpace(re, utf)

				case OP_ANYNL, OP_VSPACE:
					ssbVSpace(re, utf)

				case OP_NOT_DIGIT:
					set_nottype_bits(re, cbit_digit, table_limit)

				case OP_DIGIT:
					set_type_bits(re, cbit_digit, table_limit)

				case OP_NOT_WHITESPACE:
					set_nottype_bits(re, cbit_space, table_limit)

				case OP_WHITESPACE:
					set_type_bits(re, cbit_space, table_limit)

				case OP_NOT_WORDCHAR:
					set_nottype_bits(re, cbit_word, table_limit)

				case OP_WORDCHAR:
					set_type_bits(re, cbit_word, table_limit)
				}

				tcode += 2

			// Extended class: if there are any property checks, or if this is a
			// negative XCLASS without a map, give up. If there are no property
			// checks, there must be wide characters on the XCLASS list, because
			// otherwise an XCLASS would not have been created. This means that code
			// points >= 255 are potential starters. In the UTF-8 case we can scan
			// them and set bits for the relevant leading bytes.

			case OP_XCLASS:
				xclassflags := code[tcode+1+LINK_SIZE]
				if xclassflags&XCL_HASPROP != 0 ||
					xclassflags&(XCL_MAP|XCL_NOT) == XCL_NOT {
					return SSB_FAIL
				}

				// We have a positive XCLASS or a negative one without a map. Set up
				// the map pointer if there is one, and fall through.

				if xclassflags&XCL_MAP != 0 {
					classmap = code[tcode+1+LINK_SIZE+1 : tcode+1+LINK_SIZE+1+32]
				}

				// In UTF-8 mode, scan the character list and set bits for leading
				// bytes, then jump to handle the map.

				if utf && xclassflags&XCL_NOT == 0 {
					p := tcode + 1 + LINK_SIZE + 1
					if classmap != nil {
						p += 32
					}
					tcode += GET(code, tcode+1)

				scan:
					for {
						k := code[p]
						p++
						switch k {
						case XCL_SINGLE:
							b := code[p]
							p++
							for code[p]&0xc0 == 0x80 {
								p++
							}
							re.startBitmap[b/8] |= 1 << (b & 7)

						case XCL_RANGE:
							b := code[p]
							p++
							for code[p]&0xc0 == 0x80 {
								p++
							}
							e := code[p]
							p++
							for code[p]&0xc0 == 0x80 {
								p++
							}
							// C: for (; b <= e; b++) with an 8-bit b
							for {
								if b > e {
									break
								}
								re.startBitmap[b/8] |= 1 << (b & 7)
								b++
								if b == 0 {
									break // 8-bit wrap-around, as in C when e == 255
								}
							}

						case XCL_END:
							break scan // goto HANDLE_CLASSMAP

						default:
							return SSB_UNKNOWN // Internal error, should not occur
						}
					}
					tcode, try_next = ssbClassTail(re, code, tcode, classmap, utf)
					break
				}

				// Fall through to the negative non-XCLASS case.
				if utf {
					re.startBitmap[24] |= 0xf0 // Bits for 0xc4 - 0xc8
					for i := 25; i < 32; i++ { // Bits for 0xc9 - 0xff
						re.startBitmap[i] = 0xff
					}
				}
				tcode += GET(code, tcode+1)
				tcode, try_next = ssbClassTail(re, code, tcode, classmap, utf)

			// Enter here for a negative non-XCLASS. In the 8-bit library, if we
			// are in UTF mode, any byte with a value >= 0xc4 is a potentially
			// valid starter because it starts a character with a value > 255. In
			// 8-bit non-UTF mode, there is no difference between CLASS and NCLASS.

			case OP_NCLASS:
				if utf {
					re.startBitmap[24] |= 0xf0 // Bits for 0xc4 - 0xc8
					for i := 25; i < 32; i++ { // Bits for 0xc9 - 0xff
						re.startBitmap[i] = 0xff
					}
				}
				fallthrough

			// Enter here for a positive non-XCLASS. If we have fallen through from
			// an XCLASS, classmap will already be set; just advance the code
			// pointer. Otherwise, set up classmap for a a non-XCLASS and advance
			// past it.

			case OP_CLASS:
				tcode++
				classmap = code[tcode : tcode+32]
				tcode += 32
				tcode, try_next = ssbClassTail(re, code, tcode, classmap, utf)
			}
		}

		pos += GET(code, pos+1) // Advance to next branch
		if code[pos] != OP_ALT {
			break
		}
	}

	return yield
}

// study studies a compiled expression to produce information that will speed
// up the matching. It returns 0 normally; 1 for an unknown opcode in
// set_start_bits, 2 for a missing capturing bracket, 3 for an unknown opcode in
// find_minlength. (PRIV(study), pcre2_study.c:1761-1913)
func study(re *Code) int {
	count := 0
	utf := re.overallOptions&PCRE2_UTF != 0
	ucp := re.overallOptions&PCRE2_UCP != 0

	// Find start of compiled code

	code := re.startCode()

	// For a pattern that has a first code unit, or a multiline pattern that
	// matches only at "line start", there is no point in seeking a list of
	// starting code units.

	if re.flags&(PCRE2_FIRSTSET|PCRE2_STARTLINE) == 0 {
		depth := 0
		rc := set_start_bits(re, code, 0, utf, ucp, &depth)
		if rc == SSB_UNKNOWN {
			return 1
		}

		// If a list of starting code units was set up, scan the list to see if
		// only one or two were listed. Having only one listed is rare because
		// usually a single starting code unit will have been recognized and
		// PCRE2_FIRSTSET set. If two are listed, see if they are caseless
		// versions of the same character; if so we can replace the list with a
		// caseless first code unit. This gives better performance and is
		// plausibly worth doing for patterns such as [Ww]ord or (word|WORD).

		if rc == SSB_DONE {
			a := -1
			b := -1
			flags := uint32(PCRE2_FIRSTMAPSET)

			func() {
				for i := 0; i < 256; i += 8 {
					x := re.startBitmap[i/8]
					if x != 0 {
						y := x & (^x + 1) // Least significant bit
						if y != x {
							return // More than one bit set: DONE
						}

						// Compute the character value

						c := i
						switch x {
						case 1:
						case 2:
							c += 1
						case 4:
							c += 2
						case 8:
							c += 3
						case 16:
							c += 4
						case 32:
							c += 5
						case 64:
							c += 6
						case 128:
							c += 7
						}

						// c contains the code unit value, in the range 0-255. In
						// 8-bit UTF mode, only values < 128 can be used. In all
						// the other cases, c is a character value.

						if utf && c > 127 {
							return
						}
						if a < 0 {
							a = c // First one found, save in a
						} else if b < 0 { // Second one found
							d := int(re.charTables()[fcc_offset+c])

							if utf || ucp {
								if UCD_CASESET(uint32(c)) != 0 {
									return // Multiple case set
								}
								if c > 127 {
									d = int(UCD_OTHERCASE(uint32(c)))
								}
							}

							if d != a {
								return // Not the other case of a
							}
							b = c // Save second in b
						} else {
							return // More than two characters found
						}
					}
				}

				// Replace the start code unit bits with a first code unit, but
				// only if it is not the same as a required later code unit. This
				// is because a search for a required code unit starts after an
				// explicit first code unit, but at a code unit found from the
				// bitmap. Patterns such as /a*a/ don't work if both the start unit
				// and required unit are the same.

				if a >= 0 &&
					(re.flags&PCRE2_LASTSET == 0 ||
						(re.lastCodeunit != uint32(a) &&
							(b < 0 || re.lastCodeunit != uint32(b)))) {
					re.firstCodeunit = uint32(a)
					flags = PCRE2_FIRSTSET
					if b >= 0 {
						flags |= PCRE2_FIRSTCASELESS
					}
				}
			}()

			re.flags |= flags
		}
	}

	// Find the minimum length of subject string. If the pattern can match an
	// empty string, the minimum length is already known. If the pattern contains
	// (*ACCEPT) all bets are off, and we don't even try to find a minimum length.
	// If there are more back references than the size of the vector we are going
	// to cache them in, do nothing. A pattern that complicated will probably take
	// a long time to analyze and may in any case turn out to be too complicated.
	// Note that back reference minima are held as 16-bit numbers.

	if re.flags&(PCRE2_MATCH_EMPTY|PCRE2_HASACCEPT) == 0 &&
		re.topBackref <= MAX_CACHE_BACKREF {
		var backref_cache [MAX_CACHE_BACKREF + 1]int
		backref_cache[0] = 0 // Highest one that is set
		min := find_minlength(re, code, 0, utf, nil, &count, backref_cache[:])
		switch min {
		case -1: // \C in UTF mode or over-complex regex
			// Leave minlength unchanged (will be zero)

		case -2:
			return 2 // missing capturing bracket

		case -3:
			return 3 // unrecognized opcode

		default:
			if min > uint16Max {
				re.minlength = uint16Max
			} else {
				re.minlength = uint16(min)
			}
		}
	}

	return 0
}
