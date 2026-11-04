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

		if c == OP_END {
			return -1
		}

		// XCLASS is used for classes that cannot be represented just by a bit
		// map; CALLOUT_STR is used for callouts with string arguments. In both
		// cases the length in the table is zero; the actual length is stored in
		// the compiled code.
		if c == OP_XCLASS {
			p += GET(code, p+1)
		} else if c == OP_CALLOUT_STR {
			p += GET(code, p+1+2*LINK_SIZE)
		} else if c == OP_REVERSE || c == OP_VREVERSE { // Handle lookbehind
			if number < 0 {
				return p
			}
			p += int(OP_lengths[c])
		} else if c == OP_CBRA || c == OP_SCBRA || c == OP_CBRAPOS || c == OP_SCBRAPOS { // capturing bracket
			n := GET2(code, p+1+LINK_SIZE)
			if n == number {
				return p
			}
			p += int(OP_lengths[c])
		} else {
			// Otherwise, we can get the item's length from the table, except
			// that for repeated character types, we have to test for \p and
			// \P, which have an extra two bytes of parameters, and for
			// MARK/PRUNE/SKIP/THEN with an argument, we must add in its length.
			switch c {
			case OP_TYPESTAR, OP_TYPEMINSTAR, OP_TYPEPLUS, OP_TYPEMINPLUS,
				OP_TYPEQUERY, OP_TYPEMINQUERY, OP_TYPEPOSSTAR, OP_TYPEPOSPLUS,
				OP_TYPEPOSQUERY:
				if code[p+1] == OP_PROP || code[p+1] == OP_NOTPROP {
					p += 2
				}

			case OP_TYPEUPTO, OP_TYPEMINUPTO, OP_TYPEEXACT, OP_TYPEPOSUPTO:
				if code[p+1+IMM2_SIZE] == OP_PROP || code[p+1+IMM2_SIZE] == OP_NOTPROP {
					p += 2
				}

			case OP_MARK, OP_COMMIT_ARG, OP_PRUNE_ARG, OP_SKIP_ARG, OP_THEN_ARG:
				p += int(code[p+1])
			}

			// Add in the fixed length from the table
			p += int(OP_lengths[c])

			// In UTF-8 mode, opcodes that are followed by a character may be
			// followed by a multi-byte character. The length in the table is a
			// minimum, so we have to arrange to skip the extra bytes.
			if utf {
				switch c {
				case OP_CHAR, OP_CHARI, OP_NOT, OP_NOTI,
					OP_EXACT, OP_EXACTI, OP_NOTEXACT, OP_NOTEXACTI,
					OP_UPTO, OP_UPTOI, OP_NOTUPTO, OP_NOTUPTOI,
					OP_MINUPTO, OP_MINUPTOI, OP_NOTMINUPTO, OP_NOTMINUPTOI,
					OP_POSUPTO, OP_POSUPTOI, OP_NOTPOSUPTO, OP_NOTPOSUPTOI,
					OP_STAR, OP_STARI, OP_NOTSTAR, OP_NOTSTARI,
					OP_MINSTAR, OP_MINSTARI, OP_NOTMINSTAR, OP_NOTMINSTARI,
					OP_POSSTAR, OP_POSSTARI, OP_NOTPOSSTAR, OP_NOTPOSSTARI,
					OP_PLUS, OP_PLUSI, OP_NOTPLUS, OP_NOTPLUSI,
					OP_MINPLUS, OP_MINPLUSI, OP_NOTMINPLUS, OP_NOTMINPLUSI,
					OP_POSPLUS, OP_POSPLUSI, OP_NOTPOSPLUS, OP_NOTPOSPLUSI,
					OP_QUERY, OP_QUERYI, OP_NOTQUERY, OP_NOTQUERYI,
					OP_MINQUERY, OP_MINQUERYI, OP_NOTMINQUERY, OP_NOTMINQUERYI,
					OP_POSQUERY, OP_POSQUERYI, OP_NOTPOSQUERY, OP_NOTPOSQUERYI:
					if HAS_EXTRALEN(uint32(code[p-1])) {
						p += GET_EXTRALEN(uint32(code[p-1]))
					}
				}
			}
		}
	}
}
