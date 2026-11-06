// Port of pcre2_compile.c:1301-2327: read_number, read_repeat_counts,
// check_escape and get_ucp.
package pcre2

// read_number reads a number, possibly signed (pcre2_compile.c:1324).
// allow_sign < 0: sign not allowed; >= 0: sign is relative to this. Returns
// true if a number was read; false with *errorcodeptr == 0 if none was found,
// and with *errorcodeptr != 0 if an error occurred.
func read_number(pat []byte, ptrptr *int, ptrend int, allow_sign int32,
	max_value uint32, max_error uint32, intptr *int, errorcodeptr *int) bool {
	sign := 0
	var n uint32
	ptr := *ptrptr
	yield := false

	*errorcodeptr = 0

	if allow_sign >= 0 && ptr < ptrend {
		if pat[ptr] == xCHAR_PLUS {
			sign = +1
			max_value -= uint32(allow_sign)
			ptr++
		} else if pat[ptr] == xCHAR_MINUS {
			sign = -1
			ptr++
		}
	}

	if ptr >= ptrend || !xIS_DIGIT(uint32(pat[ptr])) {
		return false
	}
	for ptr < ptrend && xIS_DIGIT(uint32(pat[ptr])) {
		n = n*10 + uint32(pat[ptr]) - xCHAR_0
		ptr++
		if n > max_value {
			*errorcodeptr = int(max_error)
			goto EXIT
		}
	}

	if allow_sign >= 0 && sign != 0 {
		if n == 0 {
			*errorcodeptr = xERR26 // +0 and -0 are not allowed
			goto EXIT
		}

		if sign > 0 {
			n += uint32(allow_sign)
		} else if int32(n) > allow_sign {
			*errorcodeptr = xERR15 // Non-existent subpattern
			goto EXIT
		} else {
			n = uint32(allow_sign) + 1 - n
		}
	}

	yield = true

EXIT:
	*intptr = int(int32(n))
	*ptrptr = ptr
	return yield
}

// read_repeat_counts reads an item of the form {n,m} (pcre2_compile.c:1411).
// ptrptr points after '{'. minp and maxp may be nil. Returns false if not a
// repeat quantifier (errorcode zero) or on error (errorcode non-zero); true
// on success with *ptrptr after '}'.
func read_repeat_counts(pat []byte, ptrptr *int, ptrend int, minp, maxp *uint32,
	errorcodeptr *int) bool {
	p := *ptrptr
	var pp int
	yield := false
	had_minimum := false
	min := 0
	max := int(xREPEAT_UNLIMITED) // This value is larger than MAX_REPEAT_COUNT

	*errorcodeptr = 0
	for p < ptrend && (pat[p] == xCHAR_SPACE || pat[p] == xCHAR_HT) {
		p++
	}

	// Check the syntax before interpreting.

	pp = p
	if pp < ptrend && xIS_DIGIT(uint32(pat[pp])) {
		had_minimum = true
		for {
			pp++
			if !(pp < ptrend && xIS_DIGIT(uint32(pat[pp]))) {
				break
			}
		}
	}

	for pp < ptrend && (pat[pp] == xCHAR_SPACE || pat[pp] == xCHAR_HT) {
		pp++
	}
	if pp >= ptrend {
		return false
	}

	if pat[pp] == xCHAR_RIGHT_CURLY_BRACKET {
		if !had_minimum {
			return false
		}
	} else {
		c := pat[pp]
		pp++
		if c != xCHAR_COMMA {
			return false
		}
		for pp < ptrend && (pat[pp] == xCHAR_SPACE || pat[pp] == xCHAR_HT) {
			pp++
		}
		if pp >= ptrend {
			return false
		}
		if xIS_DIGIT(uint32(pat[pp])) {
			for {
				pp++
				if !(pp < ptrend && xIS_DIGIT(uint32(pat[pp]))) {
					break
				}
			}
		} else if !had_minimum {
			return false
		}
		for pp < ptrend && (pat[pp] == xCHAR_SPACE || pat[pp] == xCHAR_HT) {
			pp++
		}
		if pp >= ptrend || pat[pp] != xCHAR_RIGHT_CURLY_BRACKET {
			return false
		}
	}

	// Now process the quantifier for real.

	if !read_number(pat, &p, ptrend, -1, xMAX_REPEAT_COUNT, xERR5, &min, errorcodeptr) {
		if *errorcodeptr != 0 {
			goto EXIT // n too big
		}
		p++ // Skip comma and subsequent spaces
		for p < ptrend && (pat[p] == xCHAR_SPACE || pat[p] == xCHAR_HT) {
			p++
		}
		if !read_number(pat, &p, ptrend, -1, xMAX_REPEAT_COUNT, xERR5, &max, errorcodeptr) {
			if *errorcodeptr != 0 {
				goto EXIT // m too big
			}
		}
	} else {
		// Have read one number. Deal with {n} or {n,} or {n,m}
		for p < ptrend && (pat[p] == xCHAR_SPACE || pat[p] == xCHAR_HT) {
			p++
		}
		if pat[p] == xCHAR_RIGHT_CURLY_BRACKET {
			max = min
		} else { // Handle {n,} or {n,m}
			p++ // Skip comma and subsequent spaces
			for p < ptrend && (pat[p] == xCHAR_SPACE || pat[p] == xCHAR_HT) {
				p++
			}
			if !read_number(pat, &p, ptrend, -1, xMAX_REPEAT_COUNT, xERR5, &max, errorcodeptr) {
				if *errorcodeptr != 0 {
					goto EXIT // m too big
				}
			}

			if max < min {
				*errorcodeptr = xERR4
				goto EXIT
			}
		}
	}

	// Valid quantifier exists

	for p < ptrend && (pat[p] == xCHAR_SPACE || pat[p] == xCHAR_HT) {
		p++
	}
	p++
	yield = true
	if minp != nil {
		*minp = uint32(min)
	}
	if maxp != nil {
		*maxp = uint32(max)
	}

	// Update the pattern pointer

EXIT:
	*ptrptr = p
	return yield
}

// check_escape handles escapes (pcre2_compile.c:1550, PRIV(check_escape)). It
// is called when a \ has been encountered; *ptrptr is at the character after
// it. cb may be nil (calls from pcre2_substitute()). It returns zero for a
// data character (placed in *chptr), a positive ESC_ value for a special
// escape, or the negated number of a back reference; on error *errorcodeptr
// is set non-zero.
func check_escape(pat []byte, ptrptr *int, ptrend int, chptr *uint32,
	errorcodeptr *int, options, xoptions uint32, isclass bool, cb *compile_block) int {
	utf := (options & PCRE2_UTF) != 0
	alt_bsux := ((options & PCRE2_ALT_BSUX) | (xoptions & PCRE2_EXTRA_ALT_BSUX)) != 0
	ptr := *ptrptr
	var c, cc uint32
	escape := 0
	var i int

	// If backslash is at the end of the string, it's an error.

	if ptr >= ptrend {
		*errorcodeptr = xERR1
		return 0
	}

	c, ptr = xGETCHARINCTEST(utf, pat, ptr) // Get character value, increment pointer
	*errorcodeptr = 0                       // Be optimistic

	// handleHexBrace is the code of "COME_FROM_NU" (pcre2_compile.c:1995): the
	// processing of \x{...} after the opening brace and optional spaces. It
	// returns when the C code executes "break" or runs off its end.
	handleHexBrace := func() {
		if ptr >= ptrend || pat[ptr] == xCHAR_RIGHT_CURLY_BRACKET {
			*errorcodeptr = xERR78
			return
		}
		c = 0
		overflow := false

		for ptr < ptrend {
			cc = xXDIGIT(pat[ptr])
			if cc == 0xff {
				break
			}
			ptr++
			if c == 0 && cc == 0 {
				continue // Leading zeroes
			}
			c = (c << 4) | cc
			if (utf && c > 0x10ffff) || (!utf && c > xMAX_NON_UTF_CHAR) {
				overflow = true
				break
			}
		}

		// Perl ignores spaces and tabs before }

		for ptr < ptrend && (pat[ptr] == xCHAR_SPACE || pat[ptr] == xCHAR_HT) {
			ptr++
		}

		// On overflow, skip remaining hex digits

		if overflow {
			for ptr < ptrend && xXDIGIT(pat[ptr]) != 0xff {
				ptr++
			}
			*errorcodeptr = xERR34
		} else if ptr < ptrend && pat[ptr] == xCHAR_RIGHT_CURLY_BRACKET {
			ptr++
			if utf && c >= 0xd800 && c <= 0xdfff &&
				(xoptions&PCRE2_EXTRA_ALLOW_SURROGATE_ESCAPES) == 0 {
				ptr--
				*errorcodeptr = xERR73
			}
		} else {
			// C: "*ptr++ == }" is short-circuited at the end of input, so only
			// then does the ptr-- of the else branch move the pointer back.
			if ptr >= ptrend {
				ptr--
			}
			*errorcodeptr = xERR67
		}
	}

	// Non-alphanumerics are literals, so we just leave the value in c.

	if c < xESCAPES_FIRST || c > xESCAPES_LAST {
		// Definitely literal
	} else if i = int(escapes[c-xESCAPES_FIRST]); i != 0 {
		if i > 0 {
			c = uint32(i)
			if c == xCHAR_CR && (xoptions&PCRE2_EXTRA_ESCAPED_CR_IS_LF) != 0 {
				c = xCHAR_LF
			}
		} else { // Negative table entry
			escape = -i // Else return a special escape
			if cb != nil && (escape == xESC_P || escape == xESC_p || escape == xESC_X) {
				cb.externalFlags |= PCRE2_HASBKPORX // Note \P, \p, or \X
			}

			// Perl supports \N{name} ... PCRE does not support \N{name}, but it
			// does support quantification such as \N{2,3}.

			if escape == xESC_N && ptr < ptrend && pat[ptr] == xCHAR_LEFT_CURLY_BRACKET {
				p := ptr + 1

				// Perl ignores spaces and tabs after {

				for p < ptrend && (pat[p] == xCHAR_SPACE || pat[p] == xCHAR_HT) {
					p++
				}

				// \N{U+ can be handled by the \x{ code.

				if ptrend-p > 1 && pat[p] == xCHAR_U && pat[p+1] == xCHAR_PLUS {
					if utf {
						ptr = p + 2
						escape = 0 // Not a fancy escape after all
						handleHexBrace()
						*ptrptr = ptr
						*chptr = c
						return escape
					}
					*errorcodeptr = xERR93
				} else {
					// Give an error if what follows is not a quantifier, but don't
					// override an error set by the quantifier reader.
					if !read_repeat_counts(pat, &p, ptrend, nil, nil, errorcodeptr) &&
						*errorcodeptr == 0 {
						*errorcodeptr = xERR37
					}
				}
			}
		}
	} else {
		// Escapes that need further processing, including those that are
		// unknown, have a zero entry in the lookup table.
		var s int
		var oldptr int
		var overflow bool

		// Filter calls from pcre2_substitute().

		if cb == nil {
			if c != xCHAR_c && c != xCHAR_o && c != xCHAR_x {
				*errorcodeptr = xERR3
				return 0
			}
			alt_bsux = false // Do not modify \x handling
		}

	sw:
		switch c {
		// A number of Perl escapes are not handled by PCRE.
		case xCHAR_F, xCHAR_l, xCHAR_L:
			*errorcodeptr = xERR37

		// \u is unrecognized when neither PCRE2_ALT_BSUX nor
		// PCRE2_EXTRA_ALT_BSUX is set.
		case xCHAR_u:
			if !alt_bsux {
				*errorcodeptr = xERR37
			} else {
				var xc uint32

				if ptr >= ptrend {
					break sw
				}
				if pat[ptr] == xCHAR_LEFT_CURLY_BRACKET &&
					(xoptions&PCRE2_EXTRA_ALT_BSUX) != 0 {
					hptr := ptr + 1

					cc = 0
					for hptr < ptrend {
						xc = xXDIGIT(pat[hptr])
						if xc == 0xff {
							break
						}
						if (cc & 0xf0000000) != 0 { // Test for 32-bit overflow
							*errorcodeptr = xERR77
							ptr = hptr // Show where
							break      // *hptr != } will cause another break below
						}
						cc = (cc << 4) | xc
						hptr++
					}

					if hptr == ptr+1 || // No hex digits
						hptr >= ptrend || // Hit end of input
						pat[hptr] != xCHAR_RIGHT_CURLY_BRACKET { // No } terminator
						escape = xESC_ub // Special return
						ptr++            // Skip {
						break sw         // Hex escape not recognized
					}

					c = cc // Accept the code point
					ptr = hptr + 1
				} else { // Must be exactly 4 hex digits
					if ptrend-ptr < 4 {
						break sw // Less than 4 chars
					}
					if cc = xXDIGIT(pat[ptr]); cc == 0xff {
						break sw // Not a hex digit
					}
					if xc = xXDIGIT(pat[ptr+1]); xc == 0xff {
						break sw // Not a hex digit
					}
					cc = (cc << 4) | xc
					if xc = xXDIGIT(pat[ptr+2]); xc == 0xff {
						break sw // Not a hex digit
					}
					cc = (cc << 4) | xc
					if xc = xXDIGIT(pat[ptr+3]); xc == 0xff {
						break sw // Not a hex digit
					}
					c = (cc << 4) | xc
					ptr += 4
				}

				if utf {
					if c > 0x10ffff {
						*errorcodeptr = xERR77
					} else if c >= 0xd800 && c <= 0xdfff &&
						(xoptions&PCRE2_EXTRA_ALLOW_SURROGATE_ESCAPES) == 0 {
						*errorcodeptr = xERR73
					}
				} else if c > xMAX_NON_UTF_CHAR {
					*errorcodeptr = xERR77
				}
			}

		// \U is unrecognized unless PCRE2_ALT_BSUX or PCRE2_EXTRA_ALT_BSUX is
		// set, in which case it is an upper case letter.
		case xCHAR_U:
			if !alt_bsux {
				*errorcodeptr = xERR37
			}

		// In a character class, \g is just a literal "g". Outside a character
		// class, \g must be followed by a number, a braced name/number, or a
		// delimited name/number for a subroutine call.
		case xCHAR_g:
			if isclass {
				break sw
			}

			if ptr >= ptrend {
				*errorcodeptr = xERR57
				break sw
			}

			if pat[ptr] == xCHAR_LESS_THAN_SIGN || pat[ptr] == xCHAR_APOSTROPHE {
				escape = xESC_g
				break sw
			}

			// If there is a brace delimiter, try to read a numerical reference.
			// If there isn't one, assume we have a name and treat it as \k.

			if pat[ptr] == xCHAR_LEFT_CURLY_BRACKET {
				p := ptr + 1

				for p < ptrend && (pat[p] == xCHAR_SPACE || pat[p] == xCHAR_HT) {
					p++
				}
				if !read_number(pat, &p, ptrend, int32(cb.bracount), xMAX_GROUP_NUMBER, xERR61,
					&s, errorcodeptr) {
					if *errorcodeptr == 0 {
						escape = xESC_k // No number found
					}
					break sw
				}
				for p < ptrend && (pat[p] == xCHAR_SPACE || pat[p] == xCHAR_HT) {
					p++
				}

				if p >= ptrend || pat[p] != xCHAR_RIGHT_CURLY_BRACKET {
					*errorcodeptr = xERR57
					break sw
				}
				ptr = p + 1
			} else { // Read an undelimited number
				if !read_number(pat, &ptr, ptrend, int32(cb.bracount), xMAX_GROUP_NUMBER, xERR61,
					&s, errorcodeptr) {
					if *errorcodeptr == 0 {
						*errorcodeptr = xERR57 // No number found
					}
					break sw
				}
			}

			if s <= 0 {
				*errorcodeptr = xERR15
				break sw
			}

			escape = -s

		// The handling of escape sequences consisting of a string of digits
		// starting with one that is not zero (pcre2_compile.c:1840).
		case xCHAR_1, xCHAR_2, xCHAR_3, xCHAR_4, xCHAR_5, xCHAR_6, xCHAR_7, xCHAR_8, xCHAR_9:
			if !isclass {
				oldptr = ptr
				ptr-- // Back to the digit

				// As we know we are at a digit, the only possible error from
				// read_number() is a number that is too large to be a group
				// number.

				if read_number(pat, &ptr, ptrend, -1, 0x7fffffff/10-1, 0, &s, errorcodeptr) &&
					(s < 10 || uint32(pat[oldptr-1]) >= xCHAR_8 || s <= int(int32(cb.bracount))) {
					if s > int(xMAX_GROUP_NUMBER) {
						*errorcodeptr = xERR61
					} else {
						escape = -s // Indicates a back reference
					}
					break sw
				}

				ptr = oldptr // Put the pointer back and fall through
			}

			// Handle a digit following \ when the number is not a back reference,
			// or we are within a character class.

			if c >= xCHAR_8 {
				break sw
			}

			// Fall through
			c -= xCHAR_0
			for {
				i++
				if !(i-1 < 2 && ptr < ptrend && uint32(pat[ptr]) >= xCHAR_0 && uint32(pat[ptr]) <= xCHAR_7) {
					break
				}
				c = c*8 + uint32(pat[ptr]) - xCHAR_0
				ptr++
			}
			if !utf && c > 0xff {
				*errorcodeptr = xERR51
			}

		// \0 always starts an octal number (up to three octal digits).
		case xCHAR_0:
			c -= xCHAR_0
			for {
				i++
				if !(i-1 < 2 && ptr < ptrend && uint32(pat[ptr]) >= xCHAR_0 && uint32(pat[ptr]) <= xCHAR_7) {
					break
				}
				c = c*8 + uint32(pat[ptr]) - xCHAR_0
				ptr++
			}
			if !utf && c > 0xff {
				*errorcodeptr = xERR51
			}

		// \o{ddd}, with optional spaces or tabs after { and before }.
		case xCHAR_o:
			if ptr >= ptrend || pat[ptr] != xCHAR_LEFT_CURLY_BRACKET {
				if ptr >= ptrend { // C: "*ptr++" is short-circuited here
					ptr--
				}
				*errorcodeptr = xERR55
				break sw
			}
			ptr++

			for ptr < ptrend && (pat[ptr] == xCHAR_SPACE || pat[ptr] == xCHAR_HT) {
				ptr++
			}
			if ptr >= ptrend || pat[ptr] == xCHAR_RIGHT_CURLY_BRACKET {
				*errorcodeptr = xERR78
				break sw
			}

			c = 0
			overflow = false
			for ptr < ptrend && uint32(pat[ptr]) >= xCHAR_0 && uint32(pat[ptr]) <= xCHAR_7 {
				cc = uint32(pat[ptr])
				ptr++
				if c == 0 && cc == xCHAR_0 {
					continue // Leading zeroes
				}
				c = (c << 3) + (cc - xCHAR_0)
				lim := uint32(0xff)
				if utf {
					lim = 0x10ffff
				}
				if c > lim {
					overflow = true
					break
				}
			}

			for ptr < ptrend && (pat[ptr] == xCHAR_SPACE || pat[ptr] == xCHAR_HT) {
				ptr++
			}

			if overflow {
				for ptr < ptrend && uint32(pat[ptr]) >= xCHAR_0 && uint32(pat[ptr]) <= xCHAR_7 {
					ptr++
				}
				*errorcodeptr = xERR34
			} else if ptr < ptrend && pat[ptr] == xCHAR_RIGHT_CURLY_BRACKET {
				ptr++
				if utf && c >= 0xd800 && c <= 0xdfff &&
					(xoptions&PCRE2_EXTRA_ALLOW_SURROGATE_ESCAPES) == 0 {
					ptr--
					*errorcodeptr = xERR73
				}
			} else {
				if ptr >= ptrend {
					ptr--
				}
				*errorcodeptr = xERR64
			}

		// When PCRE2_ALT_BSUX or PCRE2_EXTRA_ALT_BSUX is set, \x must be
		// followed by two hexadecimal digits. Otherwise it is a lowercase x.
		case xCHAR_x:
			if alt_bsux {
				var xc uint32
				if ptrend-ptr < 2 {
					break sw // Less than 2 characters
				}
				if cc = xXDIGIT(pat[ptr]); cc == 0xff {
					break sw // Not a hex digit
				}
				if xc = xXDIGIT(pat[ptr+1]); xc == 0xff {
					break sw // Not a hex digit
				}
				c = (cc << 4) | xc
				ptr += 2
			} else {
				// Handle \x in Perl's style.
				if ptr < ptrend && pat[ptr] == xCHAR_LEFT_CURLY_BRACKET {
					ptr++
					for ptr < ptrend && (pat[ptr] == xCHAR_SPACE || pat[ptr] == xCHAR_HT) {
						ptr++
					}
					handleHexBrace()
				} else { // Read a up to two hex digits after \x
					c = 0
					if ptr >= ptrend {
						break sw
					}
					if cc = xXDIGIT(pat[ptr]); cc == 0xff {
						break sw // Not a hex digit
					}
					ptr++
					c = cc
					if ptr >= ptrend {
						break sw
					}
					if cc = xXDIGIT(pat[ptr]); cc == 0xff {
						break sw // Not a hex digit
					}
					ptr++
					c = (c << 4) | cc
				}
			}

		// In an ASCII (or Unicode) environment, an error is given if the
		// character following \c is not a printable ASCII character.
		case xCHAR_c:
			if ptr >= ptrend {
				*errorcodeptr = xERR2
				break sw
			}
			c = uint32(pat[ptr])
			if c >= xCHAR_a && c <= xCHAR_z {
				c = xUPPER_CASE(c)
			}

			if c < 32 || c > 126 { // Excludes all non-printable ASCII
				*errorcodeptr = xERR68
				break sw
			}
			c ^= 0x40

			ptr++

		// Any other alphanumeric following \ is an error.
		default:
			*errorcodeptr = xERR3
			*ptrptr = ptr - 1 // Point to the character at fault
			return 0
		}
	}

	// Set the pointer to the next character before returning.

	*ptrptr = ptr
	*chptr = c
	return escape
}

// get_ucp handles \P and \p (pcre2_compile.c:2166). On entry *ptrptr points
// after the P or p; on exit after the final code unit of the sequence. It sets
// *negptr, *ptypeptr and *pdataptr and returns true if the type was found.
func get_ucp(pat []byte, ptrptr *int, negptr *bool, ptypeptr *uint16,
	pdataptr *uint16, errorcodeptr *int, cb *compile_block) bool {
	var c byte
	var i, bot, top int
	ptr := *ptrptr
	var name [50]byte
	vptr := -1 // index in name, or -1 for NULL
	ptscript := uint16(xPT_NOTSCRIPT)
	end_pattern := cb.endPattern

	if ptr >= end_pattern {
		goto ERROR_RETURN
	}
	c = pat[ptr]
	ptr++
	*negptr = false

	// \P or \p can be followed by a name in {}, optionally preceded by ^ for
	// negation.

	if c == xCHAR_LEFT_CURLY_BRACKET {
		if ptr >= end_pattern {
			goto ERROR_RETURN
		}

		if pat[ptr] == xCHAR_CIRCUMFLEX_ACCENT {
			*negptr = true
			ptr++
		}

		for i = 0; i < len(name)-1; i++ {
			if ptr >= end_pattern {
				goto ERROR_RETURN
			}
			c = pat[ptr]
			ptr++
			for c == '_' || c == '-' || cIsSpace(int(c)) {
				if ptr >= end_pattern {
					goto ERROR_RETURN
				}
				c = pat[ptr]
				ptr++
			}
			if c == xCHAR_NUL {
				goto ERROR_RETURN
			}
			if c == xCHAR_RIGHT_CURLY_BRACKET {
				break
			}
			name[i] = byte(cToLower(int(c)))
			if (c == ':' || c == '=') && vptr < 0 {
				vptr = i
			}
		}

		if c != xCHAR_RIGHT_CURLY_BRACKET {
			goto ERROR_RETURN
		}
		name[i] = 0
	} else if cb.ctypes[c]&ctype_letter != 0 {
		// If { doesn't follow \p or \P there is just one following character,
		// which must be an ASCII letter.
		name[0] = byte(cToLower(int(c)))
		name[1] = 0
	} else {
		goto ERROR_RETURN
	}

	*ptrptr = ptr

	// If the property contains ':' or '=' we have class name and value
	// separately specified.

	if vptr >= 0 {
		offset := 0
		var sname [8]byte

		name[vptr] = 0 // Terminate property name
		if strcmp_c8(name[:], "bidiclass") == 0 || strcmp_c8(name[:], "bc") == 0 {
			offset = 4
			sname[0] = xCHAR_b
			sname[1] = xCHAR_i // There is no strcpy_c8 function
			sname[2] = xCHAR_d
			sname[3] = xCHAR_i
		} else if strcmp_c8(name[:], "script") == 0 || strcmp_c8(name[:], "sc") == 0 {
			ptscript = xPT_SC
		} else if strcmp_c8(name[:], "scriptextensions") == 0 || strcmp_c8(name[:], "scx") == 0 {
			ptscript = xPT_SCX
		} else {
			*errorcodeptr = xERR47
			return false
		}

		// Adjust the string in name[] as needed (memmove handles overlap)

		copy(name[offset:], name[vptr+1:i+1])
		if offset != 0 {
			copy(name[:offset], sname[:offset])
		}
	}

	// Search for a recognized property using binary chop.

	bot = 0
	top = utt_size

	for bot < top {
		i = (bot + top) >> 1
		r := strcmp_c8(name[:], cstring(utt_names[utt[i].nameOffset:]))

		// When a matching property is found, some extra checking is needed when
		// the \p{xx:yy} syntax is used and xx is either sc or scx.

		if r == 0 {
			*pdataptr = utt[i].value
			if vptr < 0 || ptscript == xPT_NOTSCRIPT {
				*ptypeptr = utt[i].typ
				return true
			}

			switch utt[i].typ {
			case xPT_SC:
				*ptypeptr = xPT_SC
				return true

			case xPT_SCX:
				*ptypeptr = ptscript
				return true
			}

			break // Non-script found
		}

		if r > 0 {
			bot = i + 1
		} else {
			top = i
		}
	}

	*errorcodeptr = xERR47 // Unrecognized property
	return false

ERROR_RETURN: // Malformed \P or \p
	*errorcodeptr = xERR46
	*ptrptr = ptr
	return false
}

// cstring returns s up to its first NUL (the C string starting at its start).
func cstring(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			return s[:i]
		}
	}
	return s
}
