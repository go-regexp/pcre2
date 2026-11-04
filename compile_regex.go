// Port of pcre2_compile.c: compile_regex, is_anchored, is_startline,
// find_recurse, find_firstassertedcu and add_name_to_table
// (pcre2_compile.c:8345-9220).
//
// Conventions: code pointers are (code []byte, index int); parsed pattern
// pointers are int indices into cb.parsedPattern; PCRE2_SIZE is uint64.
package pcre2

// compile_regex is compile_regex() (pcre2_compile.c:8377): a sequence of
// alternatives. On entry *pptrptr points past the bracket meta; on return it
// points to the closing bracket or META_END. code[*codeptr] holds the BRA
// operator. lengthptr is nil in the real compile phase.
//
// Returns 0 on error, +1 if the group must match at least one character, -1
// if it may match an empty string.
func compile_regex(options uint32, xoptions uint32, code []byte, codeptr *int,
	pptrptr *int, errorcodeptr *int, skipunits uint32, firstcuptr *uint32,
	firstcuflagsptr *uint32, reqcuptr *uint32, reqcuflagsptr *uint32,
	bcptr *branch_chain, open_caps *open_capitem, cb *compile_block,
	lengthptr *uint64) int {
	cc := *codeptr
	lastBranch := cc
	startBracket := cc
	var lookbehind bool
	var capitem open_capitem
	capnumber := 0
	okreturn := 1
	pptr := *pptrptr
	var firstcu, reqcu uint32
	var lookbehindlength uint32
	var lookbehindminlength uint32
	var firstcuflags, reqcuflags uint32
	var branchfirstcu, branchreqcu uint32
	var branchfirstcuflags, branchreqcuflags uint32
	var length uint64
	var bc branch_chain

	pp := cb.parsedPattern

	// If set, call the external function that checks for stack availability.
	if cb.cx.stackGuard != nil &&
		cb.cx.stackGuard(uint32(cb.parensDepth), cb.cx.stackGuardData) != 0 {
		*errorcodeptr = ERR33
		return 0
	}

	// Miscellaneous initialization
	bc.outer = bcptr
	bc.currentBranch = cc

	firstcu, reqcu = 0, 0
	firstcuflags, reqcuflags = REQ_UNSET, REQ_UNSET

	// Accumulate the length for use in the pre-compile phase.
	length = 2 + 2*LINK_SIZE + uint64(skipunits)

	// Remember if this is a lookbehind assertion, and if it is, save its length
	// and skip over the pattern offset.
	lookbehind = code[cc] == OP_ASSERTBACK ||
		code[cc] == OP_ASSERTBACK_NOT ||
		code[cc] == OP_ASSERTBACK_NA

	if lookbehind {
		lookbehindlength = META_DATA(pp[pptr-1])
		lookbehindminlength = pp[pptr]
		pptr += SIZEOFFSET
	} else {
		lookbehindlength, lookbehindminlength = 0, 0
	}

	// If this is a capturing subpattern, add to the chain of open capturing
	// items so that we can detect them if (*ACCEPT) is encountered.
	if code[cc] == OP_CBRA {
		capnumber = GET2(code, cc+1+LINK_SIZE)
		capitem.number = uint16(capnumber)
		capitem.next = open_caps
		capitem.assertDepth = cb.assertDepth
		open_caps = &capitem
	}

	// Offset is set zero to mark that this bracket is still open
	PUT(code, cc+1, 0)
	cc += 1 + LINK_SIZE + int(skipunits)

	// Loop for each alternative branch
	for {
		var branchReturn int

		// Insert OP_REVERSE or OP_VREVERSE if this is a lookbehind assertion.
		if lookbehind && lookbehindlength > 0 {
			if lookbehindminlength == LOOKBEHIND_MAX ||
				lookbehindminlength == lookbehindlength {
				code[cc] = OP_REVERSE
				cc++
				cc = PUT2INC(code, cc, int(lookbehindlength))
				length += 1 + IMM2_SIZE
			} else {
				code[cc] = OP_VREVERSE
				cc++
				cc = PUT2INC(code, cc, int(lookbehindminlength))
				cc = PUT2INC(code, cc, int(lookbehindlength))
				length += 1 + 2*IMM2_SIZE
			}
		}

		// Now compile the branch; in the pre-compile phase its length gets
		// added into the length.
		var lp *uint64
		if lengthptr != nil {
			lp = &length
		}
		branchReturn = compile_branch(&options, &xoptions, code, &cc, &pptr, errorcodeptr,
			&branchfirstcu, &branchfirstcuflags, &branchreqcu, &branchreqcuflags,
			&bc, open_caps, cb, lp)
		if branchReturn == 0 {
			return 0
		}

		// If a branch can match an empty string, so can the whole group.
		if branchReturn < 0 {
			okreturn = -1
		}

		// In the real compile phase, there is some post-processing to be done.
		if lengthptr == nil {
			// If this is the first branch, the firstcu and reqcu values for
			// the branch become the values for the regex.
			if code[lastBranch] != OP_ALT {
				firstcu = branchfirstcu
				firstcuflags = branchfirstcuflags
				reqcu = branchreqcu
				reqcuflags = branchreqcuflags
			} else {
				// If this is not the first branch, the first char and reqcu
				// have to match the values from all the previous branches.
				if firstcuflags != branchfirstcuflags || firstcu != branchfirstcu {
					if firstcuflags < REQ_NONE {
						if reqcuflags >= REQ_NONE {
							reqcu = firstcu
							reqcuflags = firstcuflags
						}
					}
					firstcuflags = REQ_NONE
				}

				// If we (now or from before) have no firstcu, a firstcu from
				// the branch becomes a reqcu if there isn't a branch reqcu.
				if firstcuflags >= REQ_NONE && branchfirstcuflags < REQ_NONE &&
					branchreqcuflags >= REQ_NONE {
					branchreqcu = branchfirstcu
					branchreqcuflags = branchfirstcuflags
				}

				// Now ensure that the reqcus match
				if (reqcuflags&^REQ_VARY) != (branchreqcuflags&^REQ_VARY) ||
					reqcu != branchreqcu {
					reqcuflags = REQ_NONE
				} else {
					reqcu = branchreqcu
					reqcuflags |= branchreqcuflags // To "or" REQ_VARY if present
				}
			}
		}

		// Handle reaching the end of the expression, either ')' or end of
		// pattern.
		if META_CODE(pp[pptr]) != META_ALT {
			if lengthptr == nil {
				branchLength := uint64(cc - lastBranch)
				for {
					prevLength := uint64(GET(code, lastBranch+1))
					PUT(code, lastBranch+1, int(branchLength))
					branchLength = prevLength
					lastBranch -= int(branchLength)
					if branchLength == 0 {
						break
					}
				}
			}

			// Fill in the ket
			code[cc] = OP_KET
			PUT(code, cc+1, cc-startBracket)
			cc += 1 + LINK_SIZE

			// Set values to pass back
			*codeptr = cc
			*pptrptr = pptr
			*firstcuptr = firstcu
			*firstcuflagsptr = firstcuflags
			*reqcuptr = reqcu
			*reqcuflagsptr = reqcuflags
			if lengthptr != nil {
				if uint64(OFLOW_MAX)-*lengthptr < length {
					*errorcodeptr = ERR20
					return 0
				}
				*lengthptr += length
			}
			return okreturn
		}

		// Another branch follows. In the pre-compile phase, we can move the
		// code pointer back to where it was for the start of the first branch.
		// In the real compile phase, insert an ALT node.
		if lengthptr != nil {
			cc = *codeptr + 1 + LINK_SIZE + int(skipunits)
			length += 1 + LINK_SIZE
		} else {
			code[cc] = OP_ALT
			PUT(code, cc+1, cc-lastBranch)
			lastBranch = cc
			bc.currentBranch = cc
			cc += 1 + LINK_SIZE
		}

		// Set the maximum lookbehind length for the next branch (if not in a
		// lookbehind the value will be zero) and then advance past the bar.
		lookbehindlength = META_DATA(pp[pptr])
		pptr++
	}
}

// is_anchored is is_anchored() (pcre2_compile.c:8692): tries to find out if
// this is an anchored regular expression.
func is_anchored(code []byte, cc int, bracketMap uint32, cb *compile_block,
	atomcount int, inassert bool) bool {
	for {
		scode := first_significant_code(code, cc+int(OP_lengths[code[cc]]), false)
		op := int(code[scode])

		switch {
		// Non-capturing brackets
		case op == OP_BRA || op == OP_BRAPOS || op == OP_SBRA || op == OP_SBRAPOS:
			if !is_anchored(code, scode, bracketMap, cb, atomcount, inassert) {
				return false
			}

		// Capturing brackets
		case op == OP_CBRA || op == OP_CBRAPOS || op == OP_SCBRA || op == OP_SCBRAPOS:
			n := GET2(code, scode+1+LINK_SIZE)
			newMap := bracketMap
			if n < 32 {
				newMap |= 1 << uint(n)
			} else {
				newMap |= 1
			}
			if !is_anchored(code, scode, newMap, cb, atomcount, inassert) {
				return false
			}

		// Positive forward assertion
		case op == OP_ASSERT || op == OP_ASSERT_NA:
			if !is_anchored(code, scode, bracketMap, cb, atomcount, true) {
				return false
			}

		// Condition. If there is no second branch, it can't be anchored.
		case op == OP_COND || op == OP_SCOND:
			if code[scode+GET(code, scode+1)] != OP_ALT {
				return false
			}
			if !is_anchored(code, scode, bracketMap, cb, atomcount, inassert) {
				return false
			}

		// Atomic groups
		case op == OP_ONCE:
			if !is_anchored(code, scode, bracketMap, cb, atomcount+1, inassert) {
				return false
			}

		// .* is not anchored unless DOTALL is set (OP_ALLANY) and ...
		case op == OP_TYPESTAR || op == OP_TYPEMINSTAR || op == OP_TYPEPOSSTAR:
			if code[scode+1] != OP_ALLANY || (bracketMap&cb.backrefMap) != 0 ||
				atomcount > 0 || cb.hadPruneorskip || inassert ||
				(cb.externalOptions&PCRE2_NO_DOTSTAR_ANCHOR) != 0 {
				return false
			}

		// Check for explicit anchoring
		case op != OP_SOD && op != OP_SOM && op != OP_CIRC:
			return false
		}

		cc += GET(code, cc+1)
		if code[cc] != OP_ALT { // Loop for each alternative
			break
		}
	}
	return true
}

// is_startline is is_startline() (pcre2_compile.c:8797): finds out whether
// every branch starts with ^ or .*.
func is_startline(code []byte, cc int, bracketMap uint32, cb *compile_block,
	atomcount int, inassert bool) bool {
	for {
		scode := first_significant_code(code, cc+int(OP_lengths[code[cc]]), false)
		op := int(code[scode])

		// If we are at the start of a conditional assertion group, *both* the
		// conditional assertion *and* what follows the condition must satisfy
		// the test for start of line. Other kinds of condition fail.
		if op == OP_COND {
			scode += 1 + LINK_SIZE

			if code[scode] == OP_CALLOUT {
				scode += int(OP_lengths[OP_CALLOUT])
			} else if code[scode] == OP_CALLOUT_STR {
				scode += GET(code, scode+1+2*LINK_SIZE)
			}

			switch code[scode] {
			case OP_CREF, OP_DNCREF, OP_RREF, OP_DNRREF, OP_FAIL, OP_FALSE, OP_TRUE:
				return false

			default: // Assertion
				if !is_startline(code, scode, bracketMap, cb, atomcount, true) {
					return false
				}
				for {
					scode += GET(code, scode+1)
					if code[scode] != OP_ALT {
						break
					}
				}
				scode += 1 + LINK_SIZE
			}
			scode = first_significant_code(code, scode, false)
			op = int(code[scode])
		}

		switch {
		// Non-capturing brackets
		case op == OP_BRA || op == OP_BRAPOS || op == OP_SBRA || op == OP_SBRAPOS:
			if !is_startline(code, scode, bracketMap, cb, atomcount, inassert) {
				return false
			}

		// Capturing brackets
		case op == OP_CBRA || op == OP_CBRAPOS || op == OP_SCBRA || op == OP_SCBRAPOS:
			n := GET2(code, scode+1+LINK_SIZE)
			newMap := bracketMap
			if n < 32 {
				newMap |= 1 << uint(n)
			} else {
				newMap |= 1
			}
			if !is_startline(code, scode, newMap, cb, atomcount, inassert) {
				return false
			}

		// Positive forward assertions
		case op == OP_ASSERT || op == OP_ASSERT_NA:
			if !is_startline(code, scode, bracketMap, cb, atomcount, true) {
				return false
			}

		// Atomic brackets
		case op == OP_ONCE:
			if !is_startline(code, scode, bracketMap, cb, atomcount+1, inassert) {
				return false
			}

		// .* means "start at start or after \n" if ...
		case op == OP_TYPESTAR || op == OP_TYPEMINSTAR || op == OP_TYPEPOSSTAR:
			if code[scode+1] != OP_ANY || (bracketMap&cb.backrefMap) != 0 ||
				atomcount > 0 || cb.hadPruneorskip || inassert ||
				(cb.externalOptions&PCRE2_NO_DOTSTAR_ANCHOR) != 0 {
				return false
			}

		// Check for explicit circumflex; anything else gives a FALSE result.
		case op != OP_CIRC && op != OP_CIRCM:
			return false
		}

		// Move on to the next alternative
		cc += GET(code, cc+1)
		if code[cc] != OP_ALT {
			break
		}
	}
	return true
}

// find_recurse is find_recurse() (pcre2_compile.c:8919): scans a compiled
// pattern until it finds an OP_RECURSE; returns its index, or -1 (NULL).
func find_recurse(code []byte, cc int, utf bool) int {
	for {
		c := code[cc]
		if c == OP_END {
			return -1
		}
		if c == OP_RECURSE {
			return cc
		}

		// XCLASS and CALLOUT_STR have a zero table length; the actual length
		// is stored in the compiled code.
		if c == OP_XCLASS {
			cc += GET(code, cc+1)
		} else if c == OP_CALLOUT_STR {
			cc += GET(code, cc+1+2*LINK_SIZE)
		} else {
			// Otherwise, take the item's length from the table, except that for
			// repeated character types, we have to test for \p and \P, and for
			// MARK/PRUNE/SKIP/THEN with an argument we add in its length.
			switch c {
			case OP_TYPESTAR, OP_TYPEMINSTAR, OP_TYPEPLUS, OP_TYPEMINPLUS,
				OP_TYPEQUERY, OP_TYPEMINQUERY, OP_TYPEPOSSTAR, OP_TYPEPOSPLUS,
				OP_TYPEPOSQUERY:
				if code[cc+1] == OP_PROP || code[cc+1] == OP_NOTPROP {
					cc += 2
				}

			case OP_TYPEPOSUPTO, OP_TYPEUPTO, OP_TYPEMINUPTO, OP_TYPEEXACT:
				if code[cc+1+IMM2_SIZE] == OP_PROP || code[cc+1+IMM2_SIZE] == OP_NOTPROP {
					cc += 2
				}

			case OP_MARK, OP_COMMIT_ARG, OP_PRUNE_ARG, OP_SKIP_ARG, OP_THEN_ARG:
				cc += int(code[cc+1])
			}

			// Add in the fixed length from the table
			cc += int(OP_lengths[c])

			// In UTF-8 mode, opcodes that are followed by a character may be
			// followed by a multi-unit character. The table length is a
			// minimum, so we have to skip the extra units.
			if utf {
				switch c {
				case OP_CHAR, OP_CHARI, OP_NOT, OP_NOTI, OP_EXACT, OP_EXACTI,
					OP_NOTEXACT, OP_NOTEXACTI, OP_UPTO, OP_UPTOI, OP_NOTUPTO,
					OP_NOTUPTOI, OP_MINUPTO, OP_MINUPTOI, OP_NOTMINUPTO,
					OP_NOTMINUPTOI, OP_POSUPTO, OP_POSUPTOI, OP_NOTPOSUPTO,
					OP_NOTPOSUPTOI, OP_STAR, OP_STARI, OP_NOTSTAR, OP_NOTSTARI,
					OP_MINSTAR, OP_MINSTARI, OP_NOTMINSTAR, OP_NOTMINSTARI,
					OP_POSSTAR, OP_POSSTARI, OP_NOTPOSSTAR, OP_NOTPOSSTARI,
					OP_PLUS, OP_PLUSI, OP_NOTPLUS, OP_NOTPLUSI, OP_MINPLUS,
					OP_MINPLUSI, OP_NOTMINPLUS, OP_NOTMINPLUSI, OP_POSPLUS,
					OP_POSPLUSI, OP_NOTPOSPLUS, OP_NOTPOSPLUSI, OP_QUERY,
					OP_QUERYI, OP_NOTQUERY, OP_NOTQUERYI, OP_MINQUERY,
					OP_MINQUERYI, OP_NOTMINQUERY, OP_NOTMINQUERYI, OP_POSQUERY,
					OP_POSQUERYI, OP_NOTPOSQUERY, OP_NOTPOSQUERYI:
					if HAS_EXTRALEN(uint32(code[cc-1])) {
						cc += GET_EXTRALEN(uint32(code[cc-1]))
					}
				}
			}
		}
	}
}

// find_firstassertedcu is find_firstassertedcu() (pcre2_compile.c:9075): it
// returns the fixed first code unit asserted by all branches, with *flags set
// to 0 or REQ_CASELESS; otherwise 0 with REQ_NONE in *flags.
func find_firstassertedcu(code []byte, cc int, flags *uint32, inassert uint32) uint32 {
	var c uint32
	cflags := uint32(REQ_NONE)

	*flags = REQ_NONE
	for {
		var d, dflags uint32
		xl := 0
		if code[cc] == OP_CBRA || code[cc] == OP_SCBRA ||
			code[cc] == OP_CBRAPOS || code[cc] == OP_SCBRAPOS {
			xl = IMM2_SIZE
		}
		scode := first_significant_code(code, cc+1+LINK_SIZE+xl, true)
		op := code[scode]

		switch op {
		default:
			return 0

		case OP_BRA, OP_BRAPOS, OP_CBRA, OP_SCBRA, OP_CBRAPOS, OP_SCBRAPOS,
			OP_ASSERT, OP_ASSERT_NA, OP_ONCE, OP_SCRIPT_RUN:
			add := uint32(0)
			if op == OP_ASSERT || op == OP_ASSERT_NA {
				add = 1
			}
			d = find_firstassertedcu(code, scode, &dflags, inassert+add)
			if dflags >= REQ_NONE {
				return 0
			}
			if cflags >= REQ_NONE {
				c = d
				cflags = dflags
			} else if c != d || cflags != dflags {
				return 0
			}

		case OP_EXACT, OP_CHAR, OP_PLUS, OP_MINPLUS, OP_POSPLUS:
			if op == OP_EXACT {
				scode += IMM2_SIZE
			}
			if inassert == 0 {
				return 0
			}
			if cflags >= REQ_NONE {
				c = uint32(code[scode+1])
				cflags = 0
			} else if c != uint32(code[scode+1]) {
				return 0
			}

		case OP_EXACTI, OP_CHARI, OP_PLUSI, OP_MINPLUSI, OP_POSPLUSI:
			if op == OP_EXACTI {
				scode += IMM2_SIZE
			}
			if inassert == 0 {
				return 0
			}

			// If the character is more than one code unit long, we cannot set
			// its first code unit when matching caselessly.
			if code[scode+1] >= 0x80 {
				return 0
			}

			if cflags >= REQ_NONE {
				c = uint32(code[scode+1])
				cflags = REQ_CASELESS
			} else if c != uint32(code[scode+1]) {
				return 0
			}
		}

		cc += GET(code, cc+1)
		if code[cc] != OP_ALT {
			break
		}
	}

	*flags = cflags
	return c
}

// add_name_to_table is add_name_to_table() (pcre2_compile.c:9180): adds an
// entry to the name/number table, maintaining alphabetical order. name is the
// index in pat of the name.
func add_name_to_table(cb *compile_block, pat []byte, name int, length int,
	groupno uint, tablecount uint32) {
	var i uint32
	nt := cb.nameTable
	slot := 0
	entry := int(cb.nameEntrySize)

	for i = 0; i < tablecount; i++ {
		// memcmp(name, slot+IMM2_SIZE, length)
		crc := 0
		for k := 0; k < length; k++ {
			a, b := pat[name+k], nt[slot+IMM2_SIZE+k]
			if a != b {
				if a < b {
					crc = -1
				} else {
					crc = 1
				}
				break
			}
		}
		if crc == 0 && nt[slot+IMM2_SIZE+length] != 0 {
			crc = -1 // Current name is a substring
		}

		// Make space in the table and break the loop for an earlier name. For
		// a duplicate or later name, carry on.
		if crc < 0 {
			copy(nt[slot+entry:slot+entry+(int(tablecount-i))*entry], nt[slot:slot+(int(tablecount-i))*entry])
			break
		}

		// Continue the loop for a later or duplicate name
		slot += entry
	}

	PUT2(nt, slot, int(groupno))
	copy(nt[slot+IMM2_SIZE:], pat[name:name+length])

	// Add a terminating zero and fill the rest of the slot with zeroes.
	for k := slot + IMM2_SIZE + length; k < slot+entry; k++ {
		nt[k] = 0
	}
}
