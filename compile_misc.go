// Port of pcre2_compile.c:2331-2700: check_posix_syntax, check_posix_name,
// read_name, manage_callouts and handle_escdsw.
package pcre2

// check_posix_syntax is called when "[:" or "[." or "[=" is encountered in a
// character class; ptr is at the character after the initial [ (colon, dot,
// equals). It reports whether a matching terminator follows and returns its
// index in *endptr (pcre2_compile.c:2376).
func check_posix_syntax(pat []byte, ptr int, ptrend int, endptr *int) bool {
	terminator := pat[ptr]
	ptr++

	for ; ptrend-ptr >= 2; ptr++ {
		if pat[ptr] == CHAR_BACKSLASH &&
			(pat[ptr+1] == CHAR_RIGHT_SQUARE_BRACKET || pat[ptr+1] == CHAR_BACKSLASH) {
			ptr++
		} else if (pat[ptr] == CHAR_LEFT_SQUARE_BRACKET && pat[ptr+1] == terminator) ||
			pat[ptr] == CHAR_RIGHT_SQUARE_BRACKET {
			return false
		} else if pat[ptr] == terminator && pat[ptr+1] == CHAR_RIGHT_SQUARE_BRACKET {
			*endptr = ptr
			return true
		}
	}

	return false
}

// check_posix_name checks the name given in a POSIX-style class entry such as
// [:alnum:]; ptr points to the first letter. It returns the index of the name
// in posix_names or -1 (pcre2_compile.c:2417).
func check_posix_name(pat []byte, ptr int, length int) int {
	pn := 0 // offset in posix_names
	yield := 0
	for posix_name_lengths[yield] != 0 {
		if length == int(posix_name_lengths[yield]) &&
			strncmp_c8(pat[ptr:], posix_names[pn:], uint64(length)) == 0 {
			return yield
		}
		pn += int(posix_name_lengths[yield]) + 1
		yield++
	}
	return -1
}

// read_name reads a subpattern or VERB name (pcre2_compile.c:2463). *ptrptr
// is at the preceding character; if that is '*' a verb or alpha assertion
// name is read. *offsetptr receives the offset from the start of the pattern
// (pat is the whole pattern, cb.startPattern), *nameptr the index of the name
// and *namelenptr its length. Returns true if a name was read, else false
// with *errorcodeptr set.
func read_name(pat []byte, ptrptr *int, ptrend int, utf bool, terminator uint32,
	offsetptr *uint64, nameptr *int, namelenptr *uint32, errorcodeptr *int,
	cb *compile_block) bool {
	ptr := *ptrptr
	is_group := pat[ptr] != CHAR_ASTERISK
	ptr++
	is_braced := terminator == CHAR_RIGHT_CURLY_BRACKET

	if is_braced {
		for ptr < ptrend && (pat[ptr] == CHAR_SPACE || pat[ptr] == CHAR_HT) {
			ptr++
		}
	}

	if ptr >= ptrend { // No characters in name
		if is_group {
			*errorcodeptr = ERR62 // Subpattern name expected
		} else {
			*errorcodeptr = ERR60 // Verb not recognized or malformed
		}
		goto FAILED
	}

	*nameptr = ptr
	*offsetptr = uint64(ptr) // ptr - cb->start_pattern

	// In UTF mode, a group name may contain letters and decimal digits as
	// defined by Unicode properties, and underscores, but must not start with
	// a digit.

	if utf && is_group {
		c := GETCHAR(pat, ptr)
		typ := uint32(UCD_CHARTYPE(c))

		if typ == ucp_Nd {
			*errorcodeptr = ERR44
			goto FAILED
		}

		for {
			if typ != ucp_Nd && ucp_gentype[typ] != ucp_L && c != CHAR_UNDERSCORE {
				break
			}
			ptr++
			ptr = FORWARDCHARTEST(pat, ptr, ptrend)
			if ptr >= ptrend {
				break
			}
			c = GETCHAR(pat, ptr)
			typ = uint32(UCD_CHARTYPE(c))
		}
	} else {
		// Handle non-group names and group names in non-UTF modes. A group name
		// must not start with a digit. If either of the others start with a
		// digit it just won't be recognized.
		if is_group && IS_DIGIT(uint32(pat[ptr])) {
			*errorcodeptr = ERR44
			goto FAILED
		}

		for ptr < ptrend && (cb.ctypes[pat[ptr]]&ctype_word) != 0 {
			ptr++
		}
	}

	// Check name length

	if ptr > *nameptr+MAX_NAME_SIZE {
		*errorcodeptr = ERR48
		goto FAILED
	}
	*namelenptr = uint32(ptr - *nameptr)

	// Subpattern names must not be empty, and their terminator is checked here.

	if is_group {
		if ptr == *nameptr {
			*errorcodeptr = ERR62 // Subpattern name expected
			goto FAILED
		}
		if is_braced {
			for ptr < ptrend && (pat[ptr] == CHAR_SPACE || pat[ptr] == CHAR_HT) {
				ptr++
			}
		}
		if ptr >= ptrend || pat[ptr] != byte(terminator) {
			*errorcodeptr = ERR42
			goto FAILED
		}
		ptr++
	}

	*ptrptr = ptr
	return true

FAILED:
	*ptrptr = ptr
	return false
}

// manage_callouts records the details of the previous item in a prior
// callout, and sets up an automatic callout if enabled (pcre2_compile.c:2594).
// *pcalloutptr is the index in cb.parsedPattern of the previous callout, or
// -1 (C: NULL); parsed_pattern is the current index, and the possibly updated
// one is returned. ptr is the current pattern index.
func manage_callouts(ptr int, pcalloutptr *int, auto_callout bool,
	parsed_pattern int, cb *compile_block) int {
	pp := cb.parsedPattern
	previous_callout := *pcalloutptr

	if previous_callout >= 0 {
		pp[previous_callout+2] = uint32(uint64(ptr) - uint64(pp[previous_callout+1]))
	}

	if !auto_callout {
		previous_callout = -1
	} else {
		if previous_callout < 0 ||
			previous_callout != parsed_pattern-4 ||
			pp[previous_callout+3] != 255 {
			previous_callout = parsed_pattern // Set up new automatic callout
			parsed_pattern += 4
			pp[previous_callout] = META_CALLOUT_NUMBER
			pp[previous_callout+2] = 0
			pp[previous_callout+3] = 255
		}
		pp[previous_callout+1] = uint32(ptr)
	}

	*pcalloutptr = previous_callout
	return parsed_pattern
}

// handle_escdsw handles \d, \D, \s, \S, \w, \W, which may change when Unicode
// property support is requested (pcre2_compile.c:2641). The code is added to
// pp (which is cb.parsedPattern) at index parsed_pattern; the updated index
// is returned.
func handle_escdsw(escape int, pp []uint32, parsed_pattern int, options uint32,
	xoptions uint32) int {
	var ascii_option uint32
	prop := uint32(ESC_p)

	switch escape {
	case ESC_D:
		prop = ESC_P
		ascii_option = PCRE2_EXTRA_ASCII_BSD
	case ESC_d:
		ascii_option = PCRE2_EXTRA_ASCII_BSD

	case ESC_S:
		prop = ESC_P
		ascii_option = PCRE2_EXTRA_ASCII_BSS
	case ESC_s:
		ascii_option = PCRE2_EXTRA_ASCII_BSS

	case ESC_W:
		prop = ESC_P
		ascii_option = PCRE2_EXTRA_ASCII_BSW
	case ESC_w:
		ascii_option = PCRE2_EXTRA_ASCII_BSW
	}

	if (options&PCRE2_UCP) == 0 || (xoptions&ascii_option) != 0 {
		pp[parsed_pattern] = META_ESCAPE + uint32(escape)
		parsed_pattern++
	} else {
		pp[parsed_pattern] = META_ESCAPE + prop
		parsed_pattern++
		switch escape {
		case ESC_d, ESC_D:
			pp[parsed_pattern] = (PT_PC << 16) | ucp_Nd
			parsed_pattern++

		case ESC_s, ESC_S:
			pp[parsed_pattern] = PT_SPACE << 16
			parsed_pattern++

		case ESC_w, ESC_W:
			pp[parsed_pattern] = PT_WORD << 16
			parsed_pattern++
		}
	}

	return parsed_pattern
}
