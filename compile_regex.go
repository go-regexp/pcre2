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
		*errorcodeptr = xERR33
		return 0
	}

	// Miscellaneous initialization
	bc.outer = bcptr
	bc.currentBranch = cc

	firstcu, reqcu = 0, 0
	firstcuflags, reqcuflags = xREQ_UNSET, xREQ_UNSET

	// Accumulate the length for use in the pre-compile phase.
	length = 2 + 2*xLINK_SIZE + uint64(skipunits)

	// Remember if this is a lookbehind assertion, and if it is, save its length
	// and skip over the pattern offset.
	lookbehind = code[cc] == xOP_ASSERTBACK ||
		code[cc] == xOP_ASSERTBACK_NOT ||
		code[cc] == xOP_ASSERTBACK_NA

	if lookbehind {
		lookbehindlength = xMETA_DATA(pp[pptr-1])
		lookbehindminlength = pp[pptr]
		pptr += xSIZEOFFSET
	} else {
		lookbehindlength, lookbehindminlength = 0, 0
	}

	// If this is a capturing subpattern, add to the chain of open capturing
	// items so that we can detect them if (*ACCEPT) is encountered.
	if code[cc] == xOP_CBRA {
		capnumber = xGET2(code, cc+1+xLINK_SIZE)
		capitem.number = uint16(capnumber)
		capitem.next = open_caps
		capitem.assertDepth = cb.assertDepth
		open_caps = &capitem
	}

	// Offset is set zero to mark that this bracket is still open
	xPUT(code, cc+1, 0)
	cc += 1 + xLINK_SIZE + int(skipunits)

	// Loop for each alternative branch
	for {
		var branchReturn int

		// Insert OP_REVERSE or OP_VREVERSE if this is a lookbehind assertion.
		if lookbehind && lookbehindlength > 0 {
			if lookbehindminlength == xLOOKBEHIND_MAX ||
				lookbehindminlength == lookbehindlength {
				code[cc] = xOP_REVERSE
				cc++
				cc = xPUT2INC(code, cc, int(lookbehindlength))
				length += 1 + xIMM2_SIZE
			} else {
				code[cc] = xOP_VREVERSE
				cc++
				cc = xPUT2INC(code, cc, int(lookbehindminlength))
				cc = xPUT2INC(code, cc, int(lookbehindlength))
				length += 1 + 2*xIMM2_SIZE
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
			if code[lastBranch] != xOP_ALT {
				firstcu = branchfirstcu
				firstcuflags = branchfirstcuflags
				reqcu = branchreqcu
				reqcuflags = branchreqcuflags
			} else {
				// If this is not the first branch, the first char and reqcu
				// have to match the values from all the previous branches.
				if firstcuflags != branchfirstcuflags || firstcu != branchfirstcu {
					if firstcuflags < xREQ_NONE {
						if reqcuflags >= xREQ_NONE {
							reqcu = firstcu
							reqcuflags = firstcuflags
						}
					}
					firstcuflags = xREQ_NONE
				}

				// If we (now or from before) have no firstcu, a firstcu from
				// the branch becomes a reqcu if there isn't a branch reqcu.
				if firstcuflags >= xREQ_NONE && branchfirstcuflags < xREQ_NONE &&
					branchreqcuflags >= xREQ_NONE {
					branchreqcu = branchfirstcu
					branchreqcuflags = branchfirstcuflags
				}

				// Now ensure that the reqcus match
				if (reqcuflags&^xREQ_VARY) != (branchreqcuflags&^xREQ_VARY) ||
					reqcu != branchreqcu {
					reqcuflags = xREQ_NONE
				} else {
					reqcu = branchreqcu
					reqcuflags |= branchreqcuflags // To "or" REQ_VARY if present
				}
			}
		}

		// Handle reaching the end of the expression, either ')' or end of
		// pattern.
		if xMETA_CODE(pp[pptr]) != xMETA_ALT {
			if lengthptr == nil {
				branchLength := uint64(cc - lastBranch)
				for {
					prevLength := uint64(xGET(code, lastBranch+1))
					xPUT(code, lastBranch+1, int(branchLength))
					branchLength = prevLength
					lastBranch -= int(branchLength)
					if branchLength == 0 {
						break
					}
				}
			}

			// Fill in the ket
			code[cc] = xOP_KET
			xPUT(code, cc+1, cc-startBracket)
			cc += 1 + xLINK_SIZE

			// Set values to pass back
			*codeptr = cc
			*pptrptr = pptr
			*firstcuptr = firstcu
			*firstcuflagsptr = firstcuflags
			*reqcuptr = reqcu
			*reqcuflagsptr = reqcuflags
			if lengthptr != nil {
				if uint64(xOFLOW_MAX)-*lengthptr < length {
					*errorcodeptr = xERR20
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
			cc = *codeptr + 1 + xLINK_SIZE + int(skipunits)
			length += 1 + xLINK_SIZE
		} else {
			code[cc] = xOP_ALT
			xPUT(code, cc+1, cc-lastBranch)
			lastBranch = cc
			bc.currentBranch = cc
			cc += 1 + xLINK_SIZE
		}

		// Set the maximum lookbehind length for the next branch (if not in a
		// lookbehind the value will be zero) and then advance past the bar.
		lookbehindlength = xMETA_DATA(pp[pptr])
		pptr++
	}
}

// is_anchored is is_anchored() (pcre2_compile.c:8692): tries to find out if
// this is an anchored regular expression.
func is_anchored(code []byte, cc int, bracketMap uint32, cb *compile_block,
	atomcount int, inassert bool) bool {
	for {
		scode := first_significant_code(code, cc+int(xOP_lengths[code[cc]]), false)
		op := int(code[scode])

		switch {
		// Non-capturing brackets
		case op == xOP_BRA || op == xOP_BRAPOS || op == xOP_SBRA || op == xOP_SBRAPOS:
			if !is_anchored(code, scode, bracketMap, cb, atomcount, inassert) {
				return false
			}

		// Capturing brackets
		case op == xOP_CBRA || op == xOP_CBRAPOS || op == xOP_SCBRA || op == xOP_SCBRAPOS:
			n := xGET2(code, scode+1+xLINK_SIZE)
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
		case op == xOP_ASSERT || op == xOP_ASSERT_NA:
			if !is_anchored(code, scode, bracketMap, cb, atomcount, true) {
				return false
			}

		// Condition. If there is no second branch, it can't be anchored.
		case op == xOP_COND || op == xOP_SCOND:
			if code[scode+xGET(code, scode+1)] != xOP_ALT {
				return false
			}
			if !is_anchored(code, scode, bracketMap, cb, atomcount, inassert) {
				return false
			}

		// Atomic groups
		case op == xOP_ONCE:
			if !is_anchored(code, scode, bracketMap, cb, atomcount+1, inassert) {
				return false
			}

		// .* is not anchored unless DOTALL is set (OP_ALLANY) and ...
		case op == xOP_TYPESTAR || op == xOP_TYPEMINSTAR || op == xOP_TYPEPOSSTAR:
			if code[scode+1] != xOP_ALLANY || (bracketMap&cb.backrefMap) != 0 ||
				atomcount > 0 || cb.hadPruneorskip || inassert ||
				(cb.externalOptions&PCRE2_NO_DOTSTAR_ANCHOR) != 0 {
				return false
			}

		// Check for explicit anchoring
		case op != xOP_SOD && op != xOP_SOM && op != xOP_CIRC:
			return false
		}

		cc += xGET(code, cc+1)
		if code[cc] != xOP_ALT { // Loop for each alternative
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
		scode := first_significant_code(code, cc+int(xOP_lengths[code[cc]]), false)
		op := int(code[scode])

		// If we are at the start of a conditional assertion group, *both* the
		// conditional assertion *and* what follows the condition must satisfy
		// the test for start of line. Other kinds of condition fail.
		if op == xOP_COND {
			scode += 1 + xLINK_SIZE

			if code[scode] == xOP_CALLOUT {
				scode += int(xOP_lengths[xOP_CALLOUT])
			} else if code[scode] == xOP_CALLOUT_STR {
				scode += xGET(code, scode+1+2*xLINK_SIZE)
			}

			switch code[scode] {
			case xOP_CREF, xOP_DNCREF, xOP_RREF, xOP_DNRREF, xOP_FAIL, xOP_FALSE, xOP_TRUE:
				return false

			default: // Assertion
				if !is_startline(code, scode, bracketMap, cb, atomcount, true) {
					return false
				}
				for {
					scode += xGET(code, scode+1)
					if code[scode] != xOP_ALT {
						break
					}
				}
				scode += 1 + xLINK_SIZE
			}
			scode = first_significant_code(code, scode, false)
			op = int(code[scode])
		}

		switch {
		// Non-capturing brackets
		case op == xOP_BRA || op == xOP_BRAPOS || op == xOP_SBRA || op == xOP_SBRAPOS:
			if !is_startline(code, scode, bracketMap, cb, atomcount, inassert) {
				return false
			}

		// Capturing brackets
		case op == xOP_CBRA || op == xOP_CBRAPOS || op == xOP_SCBRA || op == xOP_SCBRAPOS:
			n := xGET2(code, scode+1+xLINK_SIZE)
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
		case op == xOP_ASSERT || op == xOP_ASSERT_NA:
			if !is_startline(code, scode, bracketMap, cb, atomcount, true) {
				return false
			}

		// Atomic brackets
		case op == xOP_ONCE:
			if !is_startline(code, scode, bracketMap, cb, atomcount+1, inassert) {
				return false
			}

		// .* means "start at start or after \n" if ...
		case op == xOP_TYPESTAR || op == xOP_TYPEMINSTAR || op == xOP_TYPEPOSSTAR:
			if code[scode+1] != xOP_ANY || (bracketMap&cb.backrefMap) != 0 ||
				atomcount > 0 || cb.hadPruneorskip || inassert ||
				(cb.externalOptions&PCRE2_NO_DOTSTAR_ANCHOR) != 0 {
				return false
			}

		// Check for explicit circumflex; anything else gives a FALSE result.
		case op != xOP_CIRC && op != xOP_CIRCM:
			return false
		}

		// Move on to the next alternative
		cc += xGET(code, cc+1)
		if code[cc] != xOP_ALT {
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
		if c == xOP_END {
			return -1
		}
		if c == xOP_RECURSE {
			return cc
		}

		// XCLASS and CALLOUT_STR have a zero table length; the actual length
		// is stored in the compiled code.
		if c == xOP_XCLASS {
			cc += xGET(code, cc+1)
		} else if c == xOP_CALLOUT_STR {
			cc += xGET(code, cc+1+2*xLINK_SIZE)
		} else {
			// Otherwise, take the item's length from the table, except that for
			// repeated character types, we have to test for \p and \P, and for
			// MARK/PRUNE/SKIP/THEN with an argument we add in its length.
			switch c {
			case xOP_TYPESTAR, xOP_TYPEMINSTAR, xOP_TYPEPLUS, xOP_TYPEMINPLUS,
				xOP_TYPEQUERY, xOP_TYPEMINQUERY, xOP_TYPEPOSSTAR, xOP_TYPEPOSPLUS,
				xOP_TYPEPOSQUERY:
				if code[cc+1] == xOP_PROP || code[cc+1] == xOP_NOTPROP {
					cc += 2
				}

			case xOP_TYPEPOSUPTO, xOP_TYPEUPTO, xOP_TYPEMINUPTO, xOP_TYPEEXACT:
				if code[cc+1+xIMM2_SIZE] == xOP_PROP || code[cc+1+xIMM2_SIZE] == xOP_NOTPROP {
					cc += 2
				}

			case xOP_MARK, xOP_COMMIT_ARG, xOP_PRUNE_ARG, xOP_SKIP_ARG, xOP_THEN_ARG:
				cc += int(code[cc+1])
			}

			// Add in the fixed length from the table
			cc += int(xOP_lengths[c])

			// In UTF-8 mode, opcodes that are followed by a character may be
			// followed by a multi-unit character. The table length is a
			// minimum, so we have to skip the extra units.
			if utf {
				switch c {
				case xOP_CHAR, xOP_CHARI, xOP_NOT, xOP_NOTI, xOP_EXACT, xOP_EXACTI,
					xOP_NOTEXACT, xOP_NOTEXACTI, xOP_UPTO, xOP_UPTOI, xOP_NOTUPTO,
					xOP_NOTUPTOI, xOP_MINUPTO, xOP_MINUPTOI, xOP_NOTMINUPTO,
					xOP_NOTMINUPTOI, xOP_POSUPTO, xOP_POSUPTOI, xOP_NOTPOSUPTO,
					xOP_NOTPOSUPTOI, xOP_STAR, xOP_STARI, xOP_NOTSTAR, xOP_NOTSTARI,
					xOP_MINSTAR, xOP_MINSTARI, xOP_NOTMINSTAR, xOP_NOTMINSTARI,
					xOP_POSSTAR, xOP_POSSTARI, xOP_NOTPOSSTAR, xOP_NOTPOSSTARI,
					xOP_PLUS, xOP_PLUSI, xOP_NOTPLUS, xOP_NOTPLUSI, xOP_MINPLUS,
					xOP_MINPLUSI, xOP_NOTMINPLUS, xOP_NOTMINPLUSI, xOP_POSPLUS,
					xOP_POSPLUSI, xOP_NOTPOSPLUS, xOP_NOTPOSPLUSI, xOP_QUERY,
					xOP_QUERYI, xOP_NOTQUERY, xOP_NOTQUERYI, xOP_MINQUERY,
					xOP_MINQUERYI, xOP_NOTMINQUERY, xOP_NOTMINQUERYI, xOP_POSQUERY,
					xOP_POSQUERYI, xOP_NOTPOSQUERY, xOP_NOTPOSQUERYI:
					if xHAS_EXTRALEN(uint32(code[cc-1])) {
						cc += xGET_EXTRALEN(uint32(code[cc-1]))
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
	cflags := uint32(xREQ_NONE)

	*flags = xREQ_NONE
	for {
		var d, dflags uint32
		xl := 0
		if code[cc] == xOP_CBRA || code[cc] == xOP_SCBRA ||
			code[cc] == xOP_CBRAPOS || code[cc] == xOP_SCBRAPOS {
			xl = xIMM2_SIZE
		}
		scode := first_significant_code(code, cc+1+xLINK_SIZE+xl, true)
		op := code[scode]

		switch op {
		default:
			return 0

		case xOP_BRA, xOP_BRAPOS, xOP_CBRA, xOP_SCBRA, xOP_CBRAPOS, xOP_SCBRAPOS,
			xOP_ASSERT, xOP_ASSERT_NA, xOP_ONCE, xOP_SCRIPT_RUN:
			add := uint32(0)
			if op == xOP_ASSERT || op == xOP_ASSERT_NA {
				add = 1
			}
			d = find_firstassertedcu(code, scode, &dflags, inassert+add)
			if dflags >= xREQ_NONE {
				return 0
			}
			if cflags >= xREQ_NONE {
				c = d
				cflags = dflags
			} else if c != d || cflags != dflags {
				return 0
			}

		case xOP_EXACT, xOP_CHAR, xOP_PLUS, xOP_MINPLUS, xOP_POSPLUS:
			if op == xOP_EXACT {
				scode += xIMM2_SIZE
			}
			if inassert == 0 {
				return 0
			}
			if cflags >= xREQ_NONE {
				c = uint32(code[scode+1])
				cflags = 0
			} else if c != uint32(code[scode+1]) {
				return 0
			}

		case xOP_EXACTI, xOP_CHARI, xOP_PLUSI, xOP_MINPLUSI, xOP_POSPLUSI:
			if op == xOP_EXACTI {
				scode += xIMM2_SIZE
			}
			if inassert == 0 {
				return 0
			}

			// If the character is more than one code unit long, we cannot set
			// its first code unit when matching caselessly.
			if code[scode+1] >= 0x80 {
				return 0
			}

			if cflags >= xREQ_NONE {
				c = uint32(code[scode+1])
				cflags = xREQ_CASELESS
			} else if c != uint32(code[scode+1]) {
				return 0
			}
		}

		cc += xGET(code, cc+1)
		if code[cc] != xOP_ALT {
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
			a, b := pat[name+k], nt[slot+xIMM2_SIZE+k]
			if a != b {
				if a < b {
					crc = -1
				} else {
					crc = 1
				}
				break
			}
		}
		if crc == 0 && nt[slot+xIMM2_SIZE+length] != 0 {
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

	xPUT2(nt, slot, int(groupno))
	copy(nt[slot+xIMM2_SIZE:], pat[name:name+length])

	// Add a terminating zero and fill the rest of the slot with zeroes.
	for k := slot + xIMM2_SIZE + length; k < slot+entry; k++ {
		nt[k] = 0
	}
}
