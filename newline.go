// Port of pcre2_newline.c: testing newlines when more than one kind of newline
// is recognized (NLTYPE_ANY and NLTYPE_ANYCRLF). ptr and endptr are offsets
// into s; the C out-parameter *lenptr is the second result.
package pcre2

// is_newline reports whether there is a newline at s[ptr] and its length. It is
// guaranteed by the caller that ptr < endptr. (PRIV(is_newline), pcre2_newline.c:79)
func is_newline(s []byte, ptr int, typ uint32, endptr int, utf bool) (bool, uint32) {
	var c uint32
	if utf {
		c = GETCHAR(s, ptr)
	} else {
		c = uint32(s[ptr])
	}

	if typ == NLTYPE_ANYCRLF {
		switch c {
		case CHAR_LF:
			return true, 1
		case CHAR_CR:
			if ptr < endptr-1 && s[ptr+1] == CHAR_LF {
				return true, 2
			}
			return true, 1
		default:
			return false, 0
		}
	}

	// NLTYPE_ANY
	switch c {
	case CHAR_LF, CHAR_VT, CHAR_FF:
		return true, 1
	case CHAR_CR:
		if ptr < endptr-1 && s[ptr+1] == CHAR_LF {
			return true, 2
		}
		return true, 1
	case CHAR_NEL:
		if utf {
			return true, 2
		}
		return true, 1
	case 0x2028, 0x2029: // LS, PS
		return true, 3
	}
	return false, 0
}

// was_newline reports whether a newline ends just before s[ptr] and its length.
// It is guaranteed by the caller that ptr > startptr. (PRIV(was_newline),
// pcre2_newline.c:169)
func was_newline(s []byte, ptr int, typ uint32, startptr int, utf bool) (bool, uint32) {
	var c uint32
	ptr--
	if utf {
		ptr = BACKCHAR(s, ptr)
		c = GETCHAR(s, ptr)
	} else {
		c = uint32(s[ptr])
	}

	if typ == NLTYPE_ANYCRLF {
		switch c {
		case CHAR_LF:
			if ptr > startptr && s[ptr-1] == CHAR_CR {
				return true, 2
			}
			return true, 1
		case CHAR_CR:
			return true, 1
		default:
			return false, 0
		}
	}

	// NLTYPE_ANY
	switch c {
	case CHAR_LF:
		if ptr > startptr && s[ptr-1] == CHAR_CR {
			return true, 2
		}
		return true, 1
	case CHAR_VT, CHAR_FF, CHAR_CR:
		return true, 1
	case CHAR_NEL:
		if utf {
			return true, 2
		}
		return true, 1
	case 0x2028, 0x2029: // LS, PS
		return true, 3
	}
	return false, 0
}
