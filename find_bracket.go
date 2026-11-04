// Port of pcre2_find_bracket.c: scan compiled code for a specific bracket.
package pcre2

// find_bracket scans the compiled code starting at code[start] and returns the
// offset of the opcode for the capturing bracket numbered number (or, if number
// is negative, of the first lookbehind), or -1 (C: NULL) if not found.
// (PRIV(find_bracket), pcre2_find_bracket.c:70)
func find_bracket(code []byte, start int, utf bool, number int) int {
	p := start
	for {
		c := code[p]

		if c == xOP_END {
			return -1
		}

		// XCLASS is used for classes that cannot be represented just by a bit
		// map; CALLOUT_STR is used for callouts with string arguments. In both
		// cases the length in the table is zero; the actual length is stored in
		// the compiled code.
		if c == xOP_XCLASS {
			p += xGET(code, p+1)
		} else if c == xOP_CALLOUT_STR {
			p += xGET(code, p+1+2*xLINK_SIZE)
		} else if c == xOP_REVERSE || c == xOP_VREVERSE { // Handle lookbehind
			if number < 0 {
				return p
			}
			p += int(xOP_lengths[c])
		} else if c == xOP_CBRA || c == xOP_SCBRA || c == xOP_CBRAPOS || c == xOP_SCBRAPOS { // capturing bracket
			n := xGET2(code, p+1+xLINK_SIZE)
			if n == number {
				return p
			}
			p += int(xOP_lengths[c])
		} else {
			// Otherwise, we can get the item's length from the table, except
			// that for repeated character types, we have to test for \p and
			// \P, which have an extra two bytes of parameters, and for
			// MARK/PRUNE/SKIP/THEN with an argument, we must add in its length.
			switch c {
			case xOP_TYPESTAR, xOP_TYPEMINSTAR, xOP_TYPEPLUS, xOP_TYPEMINPLUS,
				xOP_TYPEQUERY, xOP_TYPEMINQUERY, xOP_TYPEPOSSTAR, xOP_TYPEPOSPLUS,
				xOP_TYPEPOSQUERY:
				if code[p+1] == xOP_PROP || code[p+1] == xOP_NOTPROP {
					p += 2
				}

			case xOP_TYPEUPTO, xOP_TYPEMINUPTO, xOP_TYPEEXACT, xOP_TYPEPOSUPTO:
				if code[p+1+xIMM2_SIZE] == xOP_PROP || code[p+1+xIMM2_SIZE] == xOP_NOTPROP {
					p += 2
				}

			case xOP_MARK, xOP_COMMIT_ARG, xOP_PRUNE_ARG, xOP_SKIP_ARG, xOP_THEN_ARG:
				p += int(code[p+1])
			}

			// Add in the fixed length from the table
			p += int(xOP_lengths[c])

			// In UTF-8 mode, opcodes that are followed by a character may be
			// followed by a multi-byte character. The length in the table is a
			// minimum, so we have to arrange to skip the extra bytes.
			if utf {
				switch c {
				case xOP_CHAR, xOP_CHARI, xOP_NOT, xOP_NOTI,
					xOP_EXACT, xOP_EXACTI, xOP_NOTEXACT, xOP_NOTEXACTI,
					xOP_UPTO, xOP_UPTOI, xOP_NOTUPTO, xOP_NOTUPTOI,
					xOP_MINUPTO, xOP_MINUPTOI, xOP_NOTMINUPTO, xOP_NOTMINUPTOI,
					xOP_POSUPTO, xOP_POSUPTOI, xOP_NOTPOSUPTO, xOP_NOTPOSUPTOI,
					xOP_STAR, xOP_STARI, xOP_NOTSTAR, xOP_NOTSTARI,
					xOP_MINSTAR, xOP_MINSTARI, xOP_NOTMINSTAR, xOP_NOTMINSTARI,
					xOP_POSSTAR, xOP_POSSTARI, xOP_NOTPOSSTAR, xOP_NOTPOSSTARI,
					xOP_PLUS, xOP_PLUSI, xOP_NOTPLUS, xOP_NOTPLUSI,
					xOP_MINPLUS, xOP_MINPLUSI, xOP_NOTMINPLUS, xOP_NOTMINPLUSI,
					xOP_POSPLUS, xOP_POSPLUSI, xOP_NOTPOSPLUS, xOP_NOTPOSPLUSI,
					xOP_QUERY, xOP_QUERYI, xOP_NOTQUERY, xOP_NOTQUERYI,
					xOP_MINQUERY, xOP_MINQUERYI, xOP_NOTMINQUERY, xOP_NOTMINQUERYI,
					xOP_POSQUERY, xOP_POSQUERYI, xOP_NOTPOSQUERY, xOP_NOTPOSQUERYI:
					if xHAS_EXTRALEN(uint32(code[p-1])) {
						p += xGET_EXTRALEN(uint32(code[p-1]))
					}
				}
			}
		}
	}
}
