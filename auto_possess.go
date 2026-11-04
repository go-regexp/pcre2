// Port of pcre2_auto_possess.c: scan a compiled pattern and change repeats
// into possessive repeats where possible. C pointers into the byte code are
// modelled as a slice (the whole code, starting at the first opcode) plus an int
// index; NULL is -1.
package pcre2

// APTROWS and APTCOLS (pcre2_auto_possess.c:70-71).
const (
	xAPTROWS = xLAST_AUTOTAB_LEFT_OP - xFIRST_AUTOTAB_OP + 1
	xAPTCOLS = xLAST_AUTOTAB_RIGHT_OP - xFIRST_AUTOTAB_OP + 1
)

// autoposstab: whether auto-possessification is possible between adjacent
// character-type opcodes; row = left (repeated) opcode, column = right opcode.
// (pcre2_auto_possess.c:73-92)
var autoposstab = [xAPTROWS][xAPTCOLS]uint8{
	/* \D \d \S \s \W \w  . .+ \C \P \p \R \H \h \V \v \X \Z \z  $ $M */
	{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0}, /* \D */
	{1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1}, /* \d */
	{0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1}, /* \S */
	{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0}, /* \s */
	{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0}, /* \W */
	{0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1}, /* \w */
	{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0}, /* .  */
	{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0}, /* .+ */
	{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0}, /* \C */
	{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, /* \P */
	{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, /* \p */
	{0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0}, /* \R */
	{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0}, /* \H */
	{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0}, /* \h */
	{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0}, /* \V */
	{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0}, /* \v */
	{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0}, /* \X */
}

// propposstab: adjacent Unicode property opcodes (see the value legend at
// pcre2_auto_possess.c:98-123). (pcre2_auto_possess.c:125-141)
var propposstab = [xPT_TABSIZE][xPT_TABSIZE]uint8{
	/* ANY LAMP GC  PC  SC  SCX ALNUM SPACE PXSPACE WORD CLIST UCNC BIDICL BOOL */
	{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},     /* PT_ANY */
	{0, 3, 0, 0, 0, 0, 3, 1, 1, 0, 0, 0, 0, 0},     /* PT_LAMP */
	{0, 0, 2, 4, 0, 0, 9, 10, 10, 11, 0, 0, 0, 0},  /* PT_GC */
	{0, 0, 5, 2, 0, 0, 15, 16, 16, 17, 0, 0, 0, 0}, /* PT_PC */
	{0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0},     /* PT_SC */
	{0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0},     /* PT_SCX */
	{0, 3, 6, 12, 0, 0, 3, 1, 1, 0, 0, 0, 0, 0},    /* PT_ALNUM */
	{0, 1, 7, 13, 0, 0, 1, 3, 3, 1, 0, 0, 0, 0},    /* PT_SPACE */
	{0, 1, 7, 13, 0, 0, 1, 3, 3, 1, 0, 0, 0, 0},    /* PT_PXSPACE */
	{0, 0, 8, 14, 0, 0, 0, 1, 1, 3, 0, 0, 0, 0},    /* PT_WORD */
	{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},     /* PT_CLIST */
	{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0},     /* PT_UCNC */
	{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},     /* PT_BIDICL */
	{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},     /* PT_BOOL */
}

// catposstab: general category (row) against particular category (column);
// 1 if the particular category is not part of the general one.
// (pcre2_auto_possess.c:150-159)
var catposstab = [7][30]uint8{
	/* Cc Cf Cn Co Cs Ll Lm Lo Lt Lu Mc Me Mn Nd Nl No Pc Pd Pe Pf Pi Po Ps Sc Sk Sm So Zl Zp Zs */
	{0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, /* C */
	{1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, /* L */
	{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, /* M */
	{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, /* N */
	{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1}, /* P */
	{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1}, /* S */
	{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0}, /* Z */
}

// posspropstab: the properties of the ALNUM, (PX)SPACE and WORD sets.
// (pcre2_auto_possess.c:172-176)
var posspropstab = [3][4]uint8{
	{ucp_L, ucp_N, ucp_N, ucp_Nl}, /* ALNUM, 3rd and 4th values redundant */
	{ucp_Z, ucp_Z, ucp_C, ucp_Cc}, /* SPACE and PXSPACE, 2nd value redundant */
	{ucp_L, ucp_N, ucp_P, ucp_Po}, /* WORD */
}

// apIsHspace is HSPACE_CASES (pcre2_internal.h, Unicode variant).
func apIsHspace(c uint32) bool {
	switch c {
	case xCHAR_HT, xCHAR_SPACE, xCHAR_NBSP, 0x1680, 0x180e,
		0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007,
		0x2008, 0x2009, 0x200A, 0x202f, 0x205f, 0x3000:
		return true
	}
	return false
}

// apIsVspace is VSPACE_CASES (pcre2_internal.h, Unicode variant).
func apIsVspace(c uint32) bool {
	switch c {
	case xCHAR_LF, xCHAR_VT, xCHAR_FF, xCHAR_CR, xCHAR_NEL, 0x2028, 0x2029:
		return true
	}
	return false
}

// check_char_prop checks a character and a property; called by
// compare_opcodes() when a property item is adjacent to a fixed character. It
// returns true if auto-possessifying is OK. (pcre2_auto_possess.c:198-274)
func check_char_prop(c uint32, ptype, pdata uint32, negated bool) bool {
	prop := xGET_UCD(c)

	switch ptype {
	case xPT_LAMP:
		return (prop.chartype == ucp_Lu || prop.chartype == ucp_Ll ||
			prop.chartype == ucp_Lt) == negated

	case xPT_GC:
		return (pdata == ucp_gentype[prop.chartype]) == negated

	case xPT_PC:
		return (pdata == uint32(prop.chartype)) == negated

	case xPT_SC:
		return (pdata == uint32(prop.script)) == negated

	case xPT_SCX:
		ok := pdata == uint32(prop.script) ||
			xMAPBIT(ucd_script_sets[xUCD_SCRIPTX_PROP(prop):], pdata)
		return ok == negated

	// These are specials

	case xPT_ALNUM:
		return (ucp_gentype[prop.chartype] == ucp_L ||
			ucp_gentype[prop.chartype] == ucp_N) == negated

	// Perl space used to exclude VT, but from Perl 5.18 it is included, which
	// means that Perl space and POSIX space are now identical.
	case xPT_SPACE, xPT_PXSPACE:
		if apIsHspace(c) || apIsVspace(c) {
			return negated
		}
		return (ucp_gentype[prop.chartype] == ucp_Z) == negated

	case xPT_WORD:
		return (ucp_gentype[prop.chartype] == ucp_L ||
			ucp_gentype[prop.chartype] == ucp_N ||
			c == xCHAR_UNDERSCORE) == negated

	case xPT_CLIST:
		p := int(prop.caseset)
		for {
			if c < ucd_caseless_sets[p] {
				return !negated
			}
			v := ucd_caseless_sets[p]
			p++
			if c == v {
				return negated
			}
		}

	// Haven't yet thought these through.
	case xPT_BIDICL:
		return false

	case xPT_BOOL:
		return false
	}

	return false
}

// get_repeat_base returns the base opcode for repeated single character type
// opcodes; other opcodes are returned unchanged. (pcre2_auto_possess.c:290-299)
func get_repeat_base(c byte) byte {
	switch {
	case c > xOP_TYPEPOSUPTO:
		return c
	case c >= xOP_TYPESTAR:
		return xOP_TYPESTAR
	case c >= xOP_NOTSTARI:
		return xOP_NOTSTARI
	case c >= xOP_NOTSTAR:
		return xOP_NOTSTAR
	case c >= xOP_STARI:
		return xOP_STARI
	}
	return xOP_STAR
}

func boolU32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

// get_chr_property_list checks whether code[pos] is an opcode that can take
// part in auto-possessification and, if so, fills list with its properties
// (list[0] the opcode, list[1] non-zero if it can match an empty string,
// list[2..7] depends on the opcode). It returns the index of the next opcode,
// or -1 (C: NULL) if the opcode is not accepted. (pcre2_auto_possess.c:324-512)
func get_chr_property_list(code []byte, pos int, utf, ucp bool, fcc []byte, list []uint32) int {
	c := code[pos]
	var base byte

	list[0] = uint32(c)
	list[1] = xFALSE
	pos++

	if c >= xOP_STAR && c <= xOP_TYPEPOSUPTO {
		base = get_repeat_base(c)
		c -= base - xOP_STAR

		if c == xOP_UPTO || c == xOP_MINUPTO || c == xOP_EXACT || c == xOP_POSUPTO {
			pos += xIMM2_SIZE
		}

		list[1] = boolU32(c != xOP_PLUS && c != xOP_MINPLUS && c != xOP_EXACT &&
			c != xOP_POSPLUS)

		switch base {
		case xOP_STAR:
			list[0] = xOP_CHAR

		case xOP_STARI:
			list[0] = xOP_CHARI

		case xOP_NOTSTAR:
			list[0] = xOP_NOT

		case xOP_NOTSTARI:
			list[0] = xOP_NOTI

		case xOP_TYPESTAR:
			list[0] = uint32(code[pos])
			pos++
		}
		c = byte(list[0])
	}

	switch c {
	case xOP_NOT_DIGIT, xOP_DIGIT, xOP_NOT_WHITESPACE, xOP_WHITESPACE,
		xOP_NOT_WORDCHAR, xOP_WORDCHAR, xOP_ANY, xOP_ALLANY, xOP_ANYNL,
		xOP_NOT_HSPACE, xOP_HSPACE, xOP_NOT_VSPACE, xOP_VSPACE, xOP_EXTUNI,
		xOP_EODN, xOP_EOD, xOP_DOLL, xOP_DOLLM:
		return pos

	case xOP_CHAR, xOP_NOT:
		var chr uint32
		chr, pos = xGETCHARINCTEST(utf, code, pos)
		list[2] = chr
		list[3] = xNOTACHAR
		return pos

	case xOP_CHARI, xOP_NOTI:
		if c == xOP_CHARI {
			list[0] = xOP_CHAR
		} else {
			list[0] = xOP_NOT
		}
		var chr uint32
		chr, pos = xGETCHARINCTEST(utf, code, pos)
		list[2] = chr

		// SUPPORT_UNICODE
		if chr < 128 || (chr < 256 && !utf && !ucp) {
			list[3] = uint32(fcc[chr])
		} else {
			list[3] = xUCD_OTHERCASE(chr)
		}

		// The othercase might be the same value.
		if chr == list[3] {
			list[3] = xNOTACHAR
		} else {
			list[4] = xNOTACHAR
		}
		return pos

	case xOP_PROP, xOP_NOTPROP:
		if code[pos] != xPT_CLIST {
			list[2] = uint32(code[pos])
			list[3] = uint32(code[pos+1])
			return pos + 2
		}

		// Convert only if we have enough space.
		src := int(code[pos+1])
		dest := 2
		pos += 2

		for {
			if dest >= 8 {
				// Early return if there is not enough space. This should never
				// happen, since all clists are shorter than 5 character now.
				list[2] = uint32(code[pos])
				list[3] = uint32(code[pos+1])
				return pos
			}
			list[dest] = ucd_caseless_sets[src]
			dest++
			v := ucd_caseless_sets[src]
			src++
			if v == xNOTACHAR {
				break
			}
		}

		// All characters are stored. The terminating NOTACHAR is copied from the
		// clist itself.
		if c == xOP_PROP {
			list[0] = xOP_CHAR
		} else {
			list[0] = xOP_NOT
		}
		return pos

	case xOP_NCLASS, xOP_CLASS, xOP_XCLASS:
		var end int
		if c == xOP_XCLASS {
			end = pos + xGET(code, pos) - 1
		} else {
			end = pos + 32
		}

		switch code[end] {
		case xOP_CRSTAR, xOP_CRMINSTAR, xOP_CRQUERY, xOP_CRMINQUERY,
			xOP_CRPOSSTAR, xOP_CRPOSQUERY:
			list[1] = xTRUE
			end++

		case xOP_CRPLUS, xOP_CRMINPLUS, xOP_CRPOSPLUS:
			end++

		case xOP_CRRANGE, xOP_CRMINRANGE, xOP_CRPOSRANGE:
			list[1] = boolU32(xGET2(code, end+1) == 0)
			end += 1 + 2*xIMM2_SIZE
		}
		list[2] = uint32(end - pos)
		return end
	}

	return -1 // Opcode not accepted
}

// compare_opcodes checks whether the base and the current opcode have a common
// character, in which case the base cannot be possessified. code is the byte
// code, pos where to scan from; baseList is the data list of the base opcode,
// baseEnd the (index of the) end of the base opcode. It returns true if the
// auto-possessification is possible. (pcre2_auto_possess.c:535-1114)
func compare_opcodes(code []byte, pos int, utf, ucp bool, cb *compile_block,
	baseList []uint32, baseEnd int, recLimit *int) bool {
	var listArr [8]uint32
	list := listArr[:]
	enteredAGroup := false

	*recLimit--
	if *recLimit <= 0 {
		return false // Recursion has gone too deep
	}

	// Note: the base_list[1] contains whether the current opcode has a greedy
	// (represented by a non-zero value) quantifier. This is a different from
	// other character type lists, which store here that the character iterator
	// matches to an empty string (also represented by a non-zero value).

	for {
		// All operations move the code pointer forward.
		// Therefore infinite recursions are not possible.

		c := code[pos]

		// Skip over callouts

		if c == xOP_CALLOUT {
			pos += int(xOP_lengths[c])
			continue
		}

		if c == xOP_CALLOUT_STR {
			pos += xGET(code, pos+1+2*xLINK_SIZE)
			continue
		}

		// At the end of a branch, skip to the end of the group.

		if c == xOP_ALT {
			for {
				pos += xGET(code, pos+1)
				if code[pos] != xOP_ALT {
					break
				}
			}
			c = code[pos]
		}

		// Inspect the next opcode.

		switch c {
		// We can always possessify a greedy iterator at the end of the pattern,
		// which is reached after skipping over the final OP_KET. A non-greedy
		// iterator must never be possessified.

		case xOP_END:
			return baseList[1] != 0

		// When an iterator is at the end of certain kinds of group we can inspect
		// what follows the group by skipping over the closing ket. Note that this
		// does not apply to OP_KETRMAX or OP_KETRMIN because what follows any
		// given iteration is variable. As these two opcodes are not listed in the
		// next switch, they will end up as the next code to inspect, and return
		// FALSE by virtue of being unsupported.

		case xOP_KET, xOP_KETRPOS:
			// The non-greedy case cannot be converted to a possessive form.

			if baseList[1] == 0 {
				return false
			}

			// If the bracket is capturing it might be referenced by an
			// OP_RECURSE so its last iterator can never be possessified if the
			// pattern contains recursions.

			bracode := pos - xGET(code, pos+1)
			switch code[bracode] {
			case xOP_CBRA, xOP_SCBRA, xOP_CBRAPOS, xOP_SCBRAPOS:
				if cb.hadRecurse {
					return false
				}

			// A script run might have to backtrack if the iterated item can
			// match characters from more than one script. So give up unless
			// repeating an explicit character.

			case xOP_SCRIPT_RUN:
				if baseList[0] != xOP_CHAR && baseList[0] != xOP_CHARI {
					return false
				}

			// Atomic sub-patterns and assertions can always auto-possessify their
			// last iterator except for variable length lookbehinds. However, if
			// the group was entered as a result of checking a previous iterator,
			// this is not possible.

			case xOP_ASSERT, xOP_ASSERT_NOT, xOP_ONCE:
				return !enteredAGroup

			case xOP_ASSERTBACK, xOP_ASSERTBACK_NOT:
				if code[bracode+1+xLINK_SIZE] == xOP_VREVERSE {
					return false
				}
				return !enteredAGroup

			// Non-atomic assertions - don't possessify last iterator.

			case xOP_ASSERT_NA, xOP_ASSERTBACK_NA:
				return false
			}

			// Skip over the bracket and inspect what comes next.

			pos += int(xOP_lengths[c])
			continue

		// Handle cases where the next item is a group.

		case xOP_ONCE, xOP_BRA, xOP_CBRA:
			nextCode := pos + xGET(code, pos+1)
			pos += int(xOP_lengths[c])

			// Check each branch. We have to recurse a level for all but the last
			// branch.

			for code[nextCode] == xOP_ALT {
				if !compare_opcodes(code, pos, utf, ucp, cb, baseList, baseEnd, recLimit) {
					return false
				}
				pos = nextCode + 1 + xLINK_SIZE
				nextCode += xGET(code, nextCode+1)
			}

			enteredAGroup = true
			continue

		case xOP_BRAZERO, xOP_BRAMINZERO:
			nextCode := pos + 1
			if code[nextCode] != xOP_BRA && code[nextCode] != xOP_CBRA &&
				code[nextCode] != xOP_ONCE {
				return false
			}

			for {
				nextCode += xGET(code, nextCode+1)
				if code[nextCode] != xOP_ALT {
					break
				}
			}

			// The bracket content will be checked by the OP_BRA/OP_CBRA case above.

			nextCode += 1 + xLINK_SIZE
			if !compare_opcodes(code, nextCode, utf, ucp, cb, baseList, baseEnd, recLimit) {
				return false
			}

			pos += int(xOP_lengths[c])
			continue

		// The next opcode does not need special handling; fall through and use
		// it to see if the base can be possessified.

		default:
		}

		// We now have the next appropriate opcode to compare with the base. Check
		// for a supported opcode, and load its properties.

		pos = get_chr_property_list(code, pos, utf, ucp, cb.fcc, list)
		if pos < 0 {
			return false // Unsupported
		}

		// If either opcode is a small character list, set pointers for comparing
		// characters from that list with another list, or with a property.

		var chrPtr, listPtr []uint32
		listPtrIsList := false
		if baseList[0] == xOP_CHAR {
			chrPtr = baseList[2:]
			listPtr = list
			listPtrIsList = true
		} else if list[0] == xOP_CHAR {
			chrPtr = list[2:]
			listPtr = baseList
		} else if baseList[0] == xOP_CLASS || list[0] == xOP_CLASS ||
			// In 8 bit, non-UTF mode, OP_CLASS and OP_NCLASS are the same.
			(!utf && (baseList[0] == xOP_NCLASS || list[0] == xOP_NCLASS)) {
			// Character bitsets can also be compared to certain opcodes.
			var set1, set2 []byte
			if baseList[0] == xOP_CLASS || (!utf && baseList[0] == xOP_NCLASS) {
				s := baseEnd - int(baseList[2])
				set1 = code[s : s+32]
				listPtr = list
				listPtrIsList = true
			} else {
				s := pos - int(list[2])
				set1 = code[s : s+32]
				listPtr = baseList
			}

			invertBits := false
			ref := baseEnd
			if listPtrIsList {
				ref = pos
			}
			switch listPtr[0] {
			case xOP_CLASS, xOP_NCLASS:
				s := ref - int(listPtr[2])
				set2 = code[s : s+32]

			case xOP_XCLASS:
				xclassFlags := ref - int(listPtr[2]) + xLINK_SIZE
				if code[xclassFlags]&xXCL_HASPROP != 0 {
					return false
				}
				if code[xclassFlags]&xXCL_MAP == 0 {
					// No bits are set for characters < 256.
					if list[1] == 0 {
						return code[xclassFlags]&xXCL_NOT == 0
					}
					// Might be an empty repeat.
					continue
				}
				set2 = code[xclassFlags+1 : xclassFlags+33]

			case xOP_NOT_DIGIT:
				invertBits = true
				set2 = cb.cbits[cbit_digit:]
			case xOP_DIGIT:
				set2 = cb.cbits[cbit_digit:]

			case xOP_NOT_WHITESPACE:
				invertBits = true
				set2 = cb.cbits[cbit_space:]
			case xOP_WHITESPACE:
				set2 = cb.cbits[cbit_space:]

			case xOP_NOT_WORDCHAR:
				invertBits = true
				set2 = cb.cbits[cbit_word:]
			case xOP_WORDCHAR:
				set2 = cb.cbits[cbit_word:]

			default:
				return false
			}

			// Because the bit sets are unaligned bytes, we need to perform byte
			// comparison here.

			if invertBits {
				for i := 0; i < 32; i++ {
					if set1[i]&^set2[i] != 0 {
						return false
					}
				}
			} else {
				for i := 0; i < 32; i++ {
					if set1[i]&set2[i] != 0 {
						return false
					}
				}
			}

			if list[1] == 0 {
				return true
			}
			// Might be an empty repeat.
			continue
		} else {
			// Some property combinations also acceptable. Unicode property
			// opcodes are processed specially; the rest can be handled with a
			// lookup table.

			leftop := baseList[0]
			rightop := list[0]

			accepted := false
			if leftop == xOP_PROP || leftop == xOP_NOTPROP {
				if rightop == xOP_EOD {
					accepted = true
				} else if rightop == xOP_PROP || rightop == xOP_NOTPROP {
					same := leftop == rightop
					lisprop := leftop == xOP_PROP
					risprop := rightop == xOP_PROP
					bothprop := lisprop && risprop

					// There's a table that specifies how each combination is to be
					// processed (see the legend of propposstab).

					n := propposstab[baseList[2]][list[2]]
					switch n {
					case 0:
					case 1:
						accepted = bothprop
					case 2:
						accepted = (baseList[3] == list[3]) != same
					case 3:
						accepted = !same

					case 4: // Left general category, right particular category
						accepted = risprop && (catposstab[baseList[3]][list[3]] == 1) == same

					case 5: // Right general category, left particular category
						accepted = lisprop && (catposstab[list[3]][baseList[3]] == 1) == same

					// This code is logically tricky. Think hard before fiddling
					// with it. See pcre2_auto_possess.c:885-902.

					case 6, 7, 8: // Left alphanum/space/word vs right general category
						p := &posspropstab[n-6]
						accepted = risprop && lisprop ==
							(list[3] != uint32(p[0]) &&
								list[3] != uint32(p[1]) &&
								(list[3] != uint32(p[2]) || !lisprop))

					case 9, 10, 11: // Right alphanum/space/word vs left general category
						p := &posspropstab[n-9]
						accepted = lisprop && risprop ==
							(baseList[3] != uint32(p[0]) &&
								baseList[3] != uint32(p[1]) &&
								(baseList[3] != uint32(p[2]) || !risprop))

					case 12, 13, 14: // Left alphanum/space/word vs right particular category
						p := &posspropstab[n-12]
						accepted = risprop && lisprop ==
							(catposstab[p[0]][list[3]] != 0 &&
								catposstab[p[1]][list[3]] != 0 &&
								(list[3] != uint32(p[3]) || !lisprop))

					case 15, 16, 17: // Right alphanum/space/word vs left particular category
						p := &posspropstab[n-15]
						accepted = lisprop && risprop ==
							(catposstab[p[0]][baseList[3]] != 0 &&
								catposstab[p[1]][baseList[3]] != 0 &&
								(baseList[3] != uint32(p[3]) || !risprop))
					}
				}
			} else {
				accepted = leftop >= xFIRST_AUTOTAB_OP && leftop <= xLAST_AUTOTAB_LEFT_OP &&
					rightop >= xFIRST_AUTOTAB_OP && rightop <= xLAST_AUTOTAB_RIGHT_OP &&
					autoposstab[leftop-xFIRST_AUTOTAB_OP][rightop-xFIRST_AUTOTAB_OP] != 0
			}

			if !accepted {
				return false
			}

			if list[1] == 0 {
				return true
			}
			// Might be an empty repeat.
			continue
		}

		// Control reaches here only if one of the items is a small character
		// list. All characters are checked against the other side.

		ref := baseEnd
		if listPtrIsList {
			ref = pos
		}
		ci := 0
		for {
			chr := chrPtr[ci]

			switch listPtr[0] {
			case xOP_CHAR:
				oi := 2
				for {
					if chr == listPtr[oi] {
						return false
					}
					oi++
					if listPtr[oi] == xNOTACHAR {
						break
					}
				}

			case xOP_NOT:
				oi := 2
				for {
					if chr == listPtr[oi] {
						break
					}
					oi++
					if listPtr[oi] == xNOTACHAR {
						break
					}
				}
				if listPtr[oi] == xNOTACHAR {
					return false // Not found
				}

			// Note that OP_DIGIT etc. are generated only when PCRE2_UCP is *not*
			// set. When it is set, \d etc. are converted into OP_(NOT_)PROP codes.

			case xOP_DIGIT:
				if chr < 256 && cb.ctypes[chr]&ctype_digit != 0 {
					return false
				}

			case xOP_NOT_DIGIT:
				if chr > 255 || cb.ctypes[chr]&ctype_digit == 0 {
					return false
				}

			case xOP_WHITESPACE:
				if chr < 256 && cb.ctypes[chr]&ctype_space != 0 {
					return false
				}

			case xOP_NOT_WHITESPACE:
				if chr > 255 || cb.ctypes[chr]&ctype_space == 0 {
					return false
				}

			case xOP_WORDCHAR:
				if chr < 255 && cb.ctypes[chr]&ctype_word != 0 {
					return false
				}

			case xOP_NOT_WORDCHAR:
				if chr > 255 || cb.ctypes[chr]&ctype_word == 0 {
					return false
				}

			case xOP_HSPACE:
				if apIsHspace(chr) {
					return false
				}

			case xOP_NOT_HSPACE:
				if !apIsHspace(chr) {
					return false
				}

			case xOP_ANYNL, xOP_VSPACE:
				if apIsVspace(chr) {
					return false
				}

			case xOP_NOT_VSPACE:
				if !apIsVspace(chr) {
					return false
				}

			case xOP_DOLL, xOP_EODN:
				switch chr {
				case xCHAR_CR, xCHAR_LF, xCHAR_VT, xCHAR_FF, xCHAR_NEL, 0x2028, 0x2029:
					return false
				}

			case xOP_EOD: // Can always possessify before \z

			case xOP_PROP, xOP_NOTPROP:
				if !check_char_prop(chr, listPtr[2], listPtr[3], listPtr[0] == xOP_NOTPROP) {
					return false
				}

			case xOP_NCLASS, xOP_CLASS:
				if listPtr[0] == xOP_NCLASS && chr > 255 {
					return false
				}
				// Fall through
				if chr > 255 {
					break
				}
				s := ref - int(listPtr[2])
				if code[s:][chr>>3]&(1<<(chr&7)) != 0 {
					return false
				}

			case xOP_XCLASS:
				if xclass(chr, code[ref-int(listPtr[2])+xLINK_SIZE:], utf) {
					return false
				}

			default:
				return false
			}

			ci++
			if chrPtr[ci] == xNOTACHAR {
				break
			}
		}

		// At least one character must be matched from this opcode.

		if list[1] == 0 {
			return true
		}
	}
}

// auto_possessify replaces single character iterations with their possessive
// alternatives if appropriate. This function modifies the compiled opcode! code
// is the byte code from its first opcode. It returns 0 for success, -1 if a
// non-existent opcode is encountered. The rec_limit catches overly complicated
// or large patterns; the check then just stops, leaving the remainder of the
// pattern unpossessified. (pcre2_auto_possess.c:1137-1369)
func auto_possessify(code []byte, cb *compile_block) int {
	var listArr [8]uint32
	list := listArr[:]
	recLimit := 1000 // Was 10,000 but clang+ASAN uses a lot of stack.
	utf := cb.externalOptions&PCRE2_UTF != 0
	ucp := cb.externalOptions&PCRE2_UCP != 0
	pos := 0

	for {
		c := code[pos]

		if c >= xOP_TABLE_LENGTH {
			return -1 // Something gone wrong
		}

		if c >= xOP_STAR && c <= xOP_TYPEPOSUPTO {
			c -= get_repeat_base(c) - xOP_STAR
			end := -1
			if c <= xOP_MINUPTO {
				end = get_chr_property_list(code, pos, utf, ucp, cb.fcc, list)
			}
			list[1] = boolU32(c == xOP_STAR || c == xOP_PLUS || c == xOP_QUERY || c == xOP_UPTO)

			if end >= 0 && compare_opcodes(code, end, utf, ucp, cb, list, end, &recLimit) {
				switch c {
				case xOP_STAR:
					code[pos] += xOP_POSSTAR - xOP_STAR

				case xOP_MINSTAR:
					code[pos] += xOP_POSSTAR - xOP_MINSTAR

				case xOP_PLUS:
					code[pos] += xOP_POSPLUS - xOP_PLUS

				case xOP_MINPLUS:
					code[pos] += xOP_POSPLUS - xOP_MINPLUS

				case xOP_QUERY:
					code[pos] += xOP_POSQUERY - xOP_QUERY

				case xOP_MINQUERY:
					code[pos] += xOP_POSQUERY - xOP_MINQUERY

				case xOP_UPTO:
					code[pos] += xOP_POSUPTO - xOP_UPTO

				case xOP_MINUPTO:
					code[pos] += xOP_POSUPTO - xOP_MINUPTO
				}
			}
			c = code[pos]
		} else if c == xOP_CLASS || c == xOP_NCLASS || c == xOP_XCLASS {
			var repeatOpcode int
			if c == xOP_XCLASS {
				repeatOpcode = pos + xGET(code, pos+1)
			} else {
				repeatOpcode = pos + 1 + 32
			}

			c = code[repeatOpcode]
			if c >= xOP_CRSTAR && c <= xOP_CRMINRANGE {
				end := get_chr_property_list(code, pos, utf, ucp, cb.fcc, list)
				list[1] = boolU32(c&1 == 0)

				if end >= 0 && compare_opcodes(code, end, utf, ucp, cb, list, end, &recLimit) {
					switch c {
					case xOP_CRSTAR, xOP_CRMINSTAR:
						code[repeatOpcode] = xOP_CRPOSSTAR

					case xOP_CRPLUS, xOP_CRMINPLUS:
						code[repeatOpcode] = xOP_CRPOSPLUS

					case xOP_CRQUERY, xOP_CRMINQUERY:
						code[repeatOpcode] = xOP_CRPOSQUERY

					case xOP_CRRANGE, xOP_CRMINRANGE:
						code[repeatOpcode] = xOP_CRPOSRANGE
					}
				}
			}
			c = code[pos]
		}

		switch c {
		case xOP_END:
			return 0

		case xOP_TYPESTAR, xOP_TYPEMINSTAR, xOP_TYPEPLUS, xOP_TYPEMINPLUS,
			xOP_TYPEQUERY, xOP_TYPEMINQUERY, xOP_TYPEPOSSTAR, xOP_TYPEPOSPLUS,
			xOP_TYPEPOSQUERY:
			if code[pos+1] == xOP_PROP || code[pos+1] == xOP_NOTPROP {
				pos += 2
			}

		case xOP_TYPEUPTO, xOP_TYPEMINUPTO, xOP_TYPEEXACT, xOP_TYPEPOSUPTO:
			if code[pos+1+xIMM2_SIZE] == xOP_PROP || code[pos+1+xIMM2_SIZE] == xOP_NOTPROP {
				pos += 2
			}

		case xOP_CALLOUT_STR:
			pos += xGET(code, pos+1+2*xLINK_SIZE)

		case xOP_XCLASS:
			pos += xGET(code, pos+1)

		case xOP_MARK, xOP_COMMIT_ARG, xOP_PRUNE_ARG, xOP_SKIP_ARG, xOP_THEN_ARG:
			pos += int(code[pos+1])
		}

		// Add in the fixed length from the table

		pos += int(xOP_lengths[c])

		// In UTF-8 mode, opcodes that are followed by a character may be
		// followed by a multi-byte character. The length in the table is a
		// minimum, so we have to arrange to skip the extra code units.

		if utf {
			switch c {
			case xOP_CHAR, xOP_CHARI, xOP_NOT, xOP_NOTI,
				xOP_STAR, xOP_MINSTAR, xOP_PLUS, xOP_MINPLUS, xOP_QUERY, xOP_MINQUERY,
				xOP_UPTO, xOP_MINUPTO, xOP_EXACT, xOP_POSSTAR, xOP_POSPLUS,
				xOP_POSQUERY, xOP_POSUPTO,
				xOP_STARI, xOP_MINSTARI, xOP_PLUSI, xOP_MINPLUSI, xOP_QUERYI,
				xOP_MINQUERYI, xOP_UPTOI, xOP_MINUPTOI, xOP_EXACTI, xOP_POSSTARI,
				xOP_POSPLUSI, xOP_POSQUERYI, xOP_POSUPTOI,
				xOP_NOTSTAR, xOP_NOTMINSTAR, xOP_NOTPLUS, xOP_NOTMINPLUS,
				xOP_NOTQUERY, xOP_NOTMINQUERY, xOP_NOTUPTO, xOP_NOTMINUPTO,
				xOP_NOTEXACT, xOP_NOTPOSSTAR, xOP_NOTPOSPLUS, xOP_NOTPOSQUERY,
				xOP_NOTPOSUPTO,
				xOP_NOTSTARI, xOP_NOTMINSTARI, xOP_NOTPLUSI, xOP_NOTMINPLUSI,
				xOP_NOTQUERYI, xOP_NOTMINQUERYI, xOP_NOTUPTOI, xOP_NOTMINUPTOI,
				xOP_NOTEXACTI, xOP_NOTPOSSTARI, xOP_NOTPOSPLUSI, xOP_NOTPOSQUERYI,
				xOP_NOTPOSUPTOI:
				if xHAS_EXTRALEN(uint32(code[pos-1])) {
					pos += xGET_EXTRALEN(uint32(code[pos-1]))
				}
			}
		}
	}
}
