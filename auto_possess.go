// Port of pcre2_auto_possess.c: scan a compiled pattern and change repeats
// into possessive repeats where possible. C pointers into the byte code are
// modelled as a slice (the whole code, starting at the first opcode) plus an int
// index; NULL is -1.
package pcre2

// APTROWS and APTCOLS (pcre2_auto_possess.c:70-71).
const (
	APTROWS = LAST_AUTOTAB_LEFT_OP - FIRST_AUTOTAB_OP + 1
	APTCOLS = LAST_AUTOTAB_RIGHT_OP - FIRST_AUTOTAB_OP + 1
)

// autoposstab: whether auto-possessification is possible between adjacent
// character-type opcodes; row = left (repeated) opcode, column = right opcode.
// (pcre2_auto_possess.c:73-92)
var autoposstab = [APTROWS][APTCOLS]uint8{
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
var propposstab = [PT_TABSIZE][PT_TABSIZE]uint8{
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
	case CHAR_HT, CHAR_SPACE, CHAR_NBSP, 0x1680, 0x180e,
		0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007,
		0x2008, 0x2009, 0x200A, 0x202f, 0x205f, 0x3000:
		return true
	}
	return false
}

// apIsVspace is VSPACE_CASES (pcre2_internal.h, Unicode variant).
func apIsVspace(c uint32) bool {
	switch c {
	case CHAR_LF, CHAR_VT, CHAR_FF, CHAR_CR, CHAR_NEL, 0x2028, 0x2029:
		return true
	}
	return false
}

// check_char_prop checks a character and a property; called by
// compare_opcodes() when a property item is adjacent to a fixed character. It
// returns true if auto-possessifying is OK. (pcre2_auto_possess.c:198-274)
func check_char_prop(c uint32, ptype, pdata uint32, negated bool) bool {
	prop := GET_UCD(c)

	switch ptype {
	case PT_LAMP:
		return (prop.chartype == ucp_Lu || prop.chartype == ucp_Ll ||
			prop.chartype == ucp_Lt) == negated

	case PT_GC:
		return (pdata == ucp_gentype[prop.chartype]) == negated

	case PT_PC:
		return (pdata == uint32(prop.chartype)) == negated

	case PT_SC:
		return (pdata == uint32(prop.script)) == negated

	case PT_SCX:
		ok := pdata == uint32(prop.script) ||
			MAPBIT(ucd_script_sets[UCD_SCRIPTX_PROP(prop):], pdata)
		return ok == negated

	// These are specials

	case PT_ALNUM:
		return (ucp_gentype[prop.chartype] == ucp_L ||
			ucp_gentype[prop.chartype] == ucp_N) == negated

	// Perl space used to exclude VT, but from Perl 5.18 it is included, which
	// means that Perl space and POSIX space are now identical.
	case PT_SPACE, PT_PXSPACE:
		if apIsHspace(c) || apIsVspace(c) {
			return negated
		}
		return (ucp_gentype[prop.chartype] == ucp_Z) == negated

	case PT_WORD:
		return (ucp_gentype[prop.chartype] == ucp_L ||
			ucp_gentype[prop.chartype] == ucp_N ||
			c == CHAR_UNDERSCORE) == negated

	case PT_CLIST:
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
	case PT_BIDICL:
		return false

	case PT_BOOL:
		return false
	}

	return false
}

// get_repeat_base returns the base opcode for repeated single character type
// opcodes; other opcodes are returned unchanged. (pcre2_auto_possess.c:290-299)
func get_repeat_base(c byte) byte {
	switch {
	case c > OP_TYPEPOSUPTO:
		return c
	case c >= OP_TYPESTAR:
		return OP_TYPESTAR
	case c >= OP_NOTSTARI:
		return OP_NOTSTARI
	case c >= OP_NOTSTAR:
		return OP_NOTSTAR
	case c >= OP_STARI:
		return OP_STARI
	}
	return OP_STAR
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
	list[1] = FALSE
	pos++

	if c >= OP_STAR && c <= OP_TYPEPOSUPTO {
		base = get_repeat_base(c)
		c -= base - OP_STAR

		if c == OP_UPTO || c == OP_MINUPTO || c == OP_EXACT || c == OP_POSUPTO {
			pos += IMM2_SIZE
		}

		list[1] = boolU32(c != OP_PLUS && c != OP_MINPLUS && c != OP_EXACT &&
			c != OP_POSPLUS)

		switch base {
		case OP_STAR:
			list[0] = OP_CHAR

		case OP_STARI:
			list[0] = OP_CHARI

		case OP_NOTSTAR:
			list[0] = OP_NOT

		case OP_NOTSTARI:
			list[0] = OP_NOTI

		case OP_TYPESTAR:
			list[0] = uint32(code[pos])
			pos++
		}
		c = byte(list[0])
	}

	switch c {
	case OP_NOT_DIGIT, OP_DIGIT, OP_NOT_WHITESPACE, OP_WHITESPACE,
		OP_NOT_WORDCHAR, OP_WORDCHAR, OP_ANY, OP_ALLANY, OP_ANYNL,
		OP_NOT_HSPACE, OP_HSPACE, OP_NOT_VSPACE, OP_VSPACE, OP_EXTUNI,
		OP_EODN, OP_EOD, OP_DOLL, OP_DOLLM:
		return pos

	case OP_CHAR, OP_NOT:
		var chr uint32
		chr, pos = GETCHARINCTEST(utf, code, pos)
		list[2] = chr
		list[3] = NOTACHAR
		return pos

	case OP_CHARI, OP_NOTI:
		if c == OP_CHARI {
			list[0] = OP_CHAR
		} else {
			list[0] = OP_NOT
		}
		var chr uint32
		chr, pos = GETCHARINCTEST(utf, code, pos)
		list[2] = chr

		// SUPPORT_UNICODE
		if chr < 128 || (chr < 256 && !utf && !ucp) {
			list[3] = uint32(fcc[chr])
		} else {
			list[3] = UCD_OTHERCASE(chr)
		}

		// The othercase might be the same value.
		if chr == list[3] {
			list[3] = NOTACHAR
		} else {
			list[4] = NOTACHAR
		}
		return pos

	case OP_PROP, OP_NOTPROP:
		if code[pos] != PT_CLIST {
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
			if v == NOTACHAR {
				break
			}
		}

		// All characters are stored. The terminating NOTACHAR is copied from the
		// clist itself.
		if c == OP_PROP {
			list[0] = OP_CHAR
		} else {
			list[0] = OP_NOT
		}
		return pos

	case OP_NCLASS, OP_CLASS, OP_XCLASS:
		var end int
		if c == OP_XCLASS {
			end = pos + GET(code, pos) - 1
		} else {
			end = pos + 32
		}

		switch code[end] {
		case OP_CRSTAR, OP_CRMINSTAR, OP_CRQUERY, OP_CRMINQUERY,
			OP_CRPOSSTAR, OP_CRPOSQUERY:
			list[1] = TRUE
			end++

		case OP_CRPLUS, OP_CRMINPLUS, OP_CRPOSPLUS:
			end++

		case OP_CRRANGE, OP_CRMINRANGE, OP_CRPOSRANGE:
			list[1] = boolU32(GET2(code, end+1) == 0)
			end += 1 + 2*IMM2_SIZE
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

		if c == OP_CALLOUT {
			pos += int(OP_lengths[c])
			continue
		}

		if c == OP_CALLOUT_STR {
			pos += GET(code, pos+1+2*LINK_SIZE)
			continue
		}

		// At the end of a branch, skip to the end of the group.

		if c == OP_ALT {
			for {
				pos += GET(code, pos+1)
				if code[pos] != OP_ALT {
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

		case OP_END:
			return baseList[1] != 0

		// When an iterator is at the end of certain kinds of group we can inspect
		// what follows the group by skipping over the closing ket. Note that this
		// does not apply to OP_KETRMAX or OP_KETRMIN because what follows any
		// given iteration is variable. As these two opcodes are not listed in the
		// next switch, they will end up as the next code to inspect, and return
		// FALSE by virtue of being unsupported.

		case OP_KET, OP_KETRPOS:
			// The non-greedy case cannot be converted to a possessive form.

			if baseList[1] == 0 {
				return false
			}

			// If the bracket is capturing it might be referenced by an
			// OP_RECURSE so its last iterator can never be possessified if the
			// pattern contains recursions.

			bracode := pos - GET(code, pos+1)
			switch code[bracode] {
			case OP_CBRA, OP_SCBRA, OP_CBRAPOS, OP_SCBRAPOS:
				if cb.hadRecurse {
					return false
				}

			// A script run might have to backtrack if the iterated item can
			// match characters from more than one script. So give up unless
			// repeating an explicit character.

			case OP_SCRIPT_RUN:
				if baseList[0] != OP_CHAR && baseList[0] != OP_CHARI {
					return false
				}

			// Atomic sub-patterns and assertions can always auto-possessify their
			// last iterator except for variable length lookbehinds. However, if
			// the group was entered as a result of checking a previous iterator,
			// this is not possible.

			case OP_ASSERT, OP_ASSERT_NOT, OP_ONCE:
				return !enteredAGroup

			case OP_ASSERTBACK, OP_ASSERTBACK_NOT:
				if code[bracode+1+LINK_SIZE] == OP_VREVERSE {
					return false
				}
				return !enteredAGroup

			// Non-atomic assertions - don't possessify last iterator.

			case OP_ASSERT_NA, OP_ASSERTBACK_NA:
				return false
			}

			// Skip over the bracket and inspect what comes next.

			pos += int(OP_lengths[c])
			continue

		// Handle cases where the next item is a group.

		case OP_ONCE, OP_BRA, OP_CBRA:
			nextCode := pos + GET(code, pos+1)
			pos += int(OP_lengths[c])

			// Check each branch. We have to recurse a level for all but the last
			// branch.

			for code[nextCode] == OP_ALT {
				if !compare_opcodes(code, pos, utf, ucp, cb, baseList, baseEnd, recLimit) {
					return false
				}
				pos = nextCode + 1 + LINK_SIZE
				nextCode += GET(code, nextCode+1)
			}

			enteredAGroup = true
			continue

		case OP_BRAZERO, OP_BRAMINZERO:
			nextCode := pos + 1
			if code[nextCode] != OP_BRA && code[nextCode] != OP_CBRA &&
				code[nextCode] != OP_ONCE {
				return false
			}

			for {
				nextCode += GET(code, nextCode+1)
				if code[nextCode] != OP_ALT {
					break
				}
			}

			// The bracket content will be checked by the OP_BRA/OP_CBRA case above.

			nextCode += 1 + LINK_SIZE
			if !compare_opcodes(code, nextCode, utf, ucp, cb, baseList, baseEnd, recLimit) {
				return false
			}

			pos += int(OP_lengths[c])
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
		if baseList[0] == OP_CHAR {
			chrPtr = baseList[2:]
			listPtr = list
			listPtrIsList = true
		} else if list[0] == OP_CHAR {
			chrPtr = list[2:]
			listPtr = baseList
		} else if baseList[0] == OP_CLASS || list[0] == OP_CLASS ||
			// In 8 bit, non-UTF mode, OP_CLASS and OP_NCLASS are the same.
			(!utf && (baseList[0] == OP_NCLASS || list[0] == OP_NCLASS)) {
			// Character bitsets can also be compared to certain opcodes.
			var set1, set2 []byte
			if baseList[0] == OP_CLASS || (!utf && baseList[0] == OP_NCLASS) {
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
			case OP_CLASS, OP_NCLASS:
				s := ref - int(listPtr[2])
				set2 = code[s : s+32]

			case OP_XCLASS:
				xclassFlags := ref - int(listPtr[2]) + LINK_SIZE
				if code[xclassFlags]&XCL_HASPROP != 0 {
					return false
				}
				if code[xclassFlags]&XCL_MAP == 0 {
					// No bits are set for characters < 256.
					if list[1] == 0 {
						return code[xclassFlags]&XCL_NOT == 0
					}
					// Might be an empty repeat.
					continue
				}
				set2 = code[xclassFlags+1 : xclassFlags+33]

			case OP_NOT_DIGIT:
				invertBits = true
				set2 = cb.cbits[cbit_digit:]
			case OP_DIGIT:
				set2 = cb.cbits[cbit_digit:]

			case OP_NOT_WHITESPACE:
				invertBits = true
				set2 = cb.cbits[cbit_space:]
			case OP_WHITESPACE:
				set2 = cb.cbits[cbit_space:]

			case OP_NOT_WORDCHAR:
				invertBits = true
				set2 = cb.cbits[cbit_word:]
			case OP_WORDCHAR:
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
			if leftop == OP_PROP || leftop == OP_NOTPROP {
				if rightop == OP_EOD {
					accepted = true
				} else if rightop == OP_PROP || rightop == OP_NOTPROP {
					same := leftop == rightop
					lisprop := leftop == OP_PROP
					risprop := rightop == OP_PROP
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
				accepted = leftop >= FIRST_AUTOTAB_OP && leftop <= LAST_AUTOTAB_LEFT_OP &&
					rightop >= FIRST_AUTOTAB_OP && rightop <= LAST_AUTOTAB_RIGHT_OP &&
					autoposstab[leftop-FIRST_AUTOTAB_OP][rightop-FIRST_AUTOTAB_OP] != 0
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
			case OP_CHAR:
				oi := 2
				for {
					if chr == listPtr[oi] {
						return false
					}
					oi++
					if listPtr[oi] == NOTACHAR {
						break
					}
				}

			case OP_NOT:
				oi := 2
				for {
					if chr == listPtr[oi] {
						break
					}
					oi++
					if listPtr[oi] == NOTACHAR {
						break
					}
				}
				if listPtr[oi] == NOTACHAR {
					return false // Not found
				}

			// Note that OP_DIGIT etc. are generated only when PCRE2_UCP is *not*
			// set. When it is set, \d etc. are converted into OP_(NOT_)PROP codes.

			case OP_DIGIT:
				if chr < 256 && cb.ctypes[chr]&ctype_digit != 0 {
					return false
				}

			case OP_NOT_DIGIT:
				if chr > 255 || cb.ctypes[chr]&ctype_digit == 0 {
					return false
				}

			case OP_WHITESPACE:
				if chr < 256 && cb.ctypes[chr]&ctype_space != 0 {
					return false
				}

			case OP_NOT_WHITESPACE:
				if chr > 255 || cb.ctypes[chr]&ctype_space == 0 {
					return false
				}

			case OP_WORDCHAR:
				if chr < 255 && cb.ctypes[chr]&ctype_word != 0 {
					return false
				}

			case OP_NOT_WORDCHAR:
				if chr > 255 || cb.ctypes[chr]&ctype_word == 0 {
					return false
				}

			case OP_HSPACE:
				if apIsHspace(chr) {
					return false
				}

			case OP_NOT_HSPACE:
				if !apIsHspace(chr) {
					return false
				}

			case OP_ANYNL, OP_VSPACE:
				if apIsVspace(chr) {
					return false
				}

			case OP_NOT_VSPACE:
				if !apIsVspace(chr) {
					return false
				}

			case OP_DOLL, OP_EODN:
				switch chr {
				case CHAR_CR, CHAR_LF, CHAR_VT, CHAR_FF, CHAR_NEL, 0x2028, 0x2029:
					return false
				}

			case OP_EOD: // Can always possessify before \z

			case OP_PROP, OP_NOTPROP:
				if !check_char_prop(chr, listPtr[2], listPtr[3], listPtr[0] == OP_NOTPROP) {
					return false
				}

			case OP_NCLASS, OP_CLASS:
				if listPtr[0] == OP_NCLASS && chr > 255 {
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

			case OP_XCLASS:
				if xclass(chr, code[ref-int(listPtr[2])+LINK_SIZE:], utf) {
					return false
				}

			default:
				return false
			}

			ci++
			if chrPtr[ci] == NOTACHAR {
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

		if c >= OP_TABLE_LENGTH {
			return -1 // Something gone wrong
		}

		if c >= OP_STAR && c <= OP_TYPEPOSUPTO {
			c -= get_repeat_base(c) - OP_STAR
			end := -1
			if c <= OP_MINUPTO {
				end = get_chr_property_list(code, pos, utf, ucp, cb.fcc, list)
			}
			list[1] = boolU32(c == OP_STAR || c == OP_PLUS || c == OP_QUERY || c == OP_UPTO)

			if end >= 0 && compare_opcodes(code, end, utf, ucp, cb, list, end, &recLimit) {
				switch c {
				case OP_STAR:
					code[pos] += OP_POSSTAR - OP_STAR

				case OP_MINSTAR:
					code[pos] += OP_POSSTAR - OP_MINSTAR

				case OP_PLUS:
					code[pos] += OP_POSPLUS - OP_PLUS

				case OP_MINPLUS:
					code[pos] += OP_POSPLUS - OP_MINPLUS

				case OP_QUERY:
					code[pos] += OP_POSQUERY - OP_QUERY

				case OP_MINQUERY:
					code[pos] += OP_POSQUERY - OP_MINQUERY

				case OP_UPTO:
					code[pos] += OP_POSUPTO - OP_UPTO

				case OP_MINUPTO:
					code[pos] += OP_POSUPTO - OP_MINUPTO
				}
			}
			c = code[pos]
		} else if c == OP_CLASS || c == OP_NCLASS || c == OP_XCLASS {
			var repeatOpcode int
			if c == OP_XCLASS {
				repeatOpcode = pos + GET(code, pos+1)
			} else {
				repeatOpcode = pos + 1 + 32
			}

			c = code[repeatOpcode]
			if c >= OP_CRSTAR && c <= OP_CRMINRANGE {
				end := get_chr_property_list(code, pos, utf, ucp, cb.fcc, list)
				list[1] = boolU32(c&1 == 0)

				if end >= 0 && compare_opcodes(code, end, utf, ucp, cb, list, end, &recLimit) {
					switch c {
					case OP_CRSTAR, OP_CRMINSTAR:
						code[repeatOpcode] = OP_CRPOSSTAR

					case OP_CRPLUS, OP_CRMINPLUS:
						code[repeatOpcode] = OP_CRPOSPLUS

					case OP_CRQUERY, OP_CRMINQUERY:
						code[repeatOpcode] = OP_CRPOSQUERY

					case OP_CRRANGE, OP_CRMINRANGE:
						code[repeatOpcode] = OP_CRPOSRANGE
					}
				}
			}
			c = code[pos]
		}

		switch c {
		case OP_END:
			return 0

		case OP_TYPESTAR, OP_TYPEMINSTAR, OP_TYPEPLUS, OP_TYPEMINPLUS,
			OP_TYPEQUERY, OP_TYPEMINQUERY, OP_TYPEPOSSTAR, OP_TYPEPOSPLUS,
			OP_TYPEPOSQUERY:
			if code[pos+1] == OP_PROP || code[pos+1] == OP_NOTPROP {
				pos += 2
			}

		case OP_TYPEUPTO, OP_TYPEMINUPTO, OP_TYPEEXACT, OP_TYPEPOSUPTO:
			if code[pos+1+IMM2_SIZE] == OP_PROP || code[pos+1+IMM2_SIZE] == OP_NOTPROP {
				pos += 2
			}

		case OP_CALLOUT_STR:
			pos += GET(code, pos+1+2*LINK_SIZE)

		case OP_XCLASS:
			pos += GET(code, pos+1)

		case OP_MARK, OP_COMMIT_ARG, OP_PRUNE_ARG, OP_SKIP_ARG, OP_THEN_ARG:
			pos += int(code[pos+1])
		}

		// Add in the fixed length from the table

		pos += int(OP_lengths[c])

		// In UTF-8 mode, opcodes that are followed by a character may be
		// followed by a multi-byte character. The length in the table is a
		// minimum, so we have to arrange to skip the extra code units.

		if utf {
			switch c {
			case OP_CHAR, OP_CHARI, OP_NOT, OP_NOTI,
				OP_STAR, OP_MINSTAR, OP_PLUS, OP_MINPLUS, OP_QUERY, OP_MINQUERY,
				OP_UPTO, OP_MINUPTO, OP_EXACT, OP_POSSTAR, OP_POSPLUS,
				OP_POSQUERY, OP_POSUPTO,
				OP_STARI, OP_MINSTARI, OP_PLUSI, OP_MINPLUSI, OP_QUERYI,
				OP_MINQUERYI, OP_UPTOI, OP_MINUPTOI, OP_EXACTI, OP_POSSTARI,
				OP_POSPLUSI, OP_POSQUERYI, OP_POSUPTOI,
				OP_NOTSTAR, OP_NOTMINSTAR, OP_NOTPLUS, OP_NOTMINPLUS,
				OP_NOTQUERY, OP_NOTMINQUERY, OP_NOTUPTO, OP_NOTMINUPTO,
				OP_NOTEXACT, OP_NOTPOSSTAR, OP_NOTPOSPLUS, OP_NOTPOSQUERY,
				OP_NOTPOSUPTO,
				OP_NOTSTARI, OP_NOTMINSTARI, OP_NOTPLUSI, OP_NOTMINPLUSI,
				OP_NOTQUERYI, OP_NOTMINQUERYI, OP_NOTUPTOI, OP_NOTMINUPTOI,
				OP_NOTEXACTI, OP_NOTPOSSTARI, OP_NOTPOSPLUSI, OP_NOTPOSQUERYI,
				OP_NOTPOSUPTOI:
				if HAS_EXTRALEN(uint32(code[pos-1])) {
					pos += GET_EXTRALEN(uint32(code[pos-1]))
				}
			}
		}
	}
}
