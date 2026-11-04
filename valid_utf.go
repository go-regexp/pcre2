// Port of pcre2_valid_utf.c (8-bit: UTF-8 validation, RFC 3629 plus the format
// checks of 5- and 6-byte characters, as in C).
package pcre2

// valid_utf checks that str[:length] is a valid UTF-8 string. It returns 0 if
// it is, otherwise one of the PCRE2_ERROR_UTF8_ERR* codes and the offset of the
// bad character. The index p runs exactly like the C pointer p - string.
// (PRIV(valid_utf), pcre2_valid_utf.c:94)
func valid_utf(str []byte, length uint64) (rc int, erroroffset uint64) {
	var p int
	for p = 0; length > 0; p++ {
		c := uint32(str[p])
		length--

		if c < 128 { // ASCII character
			continue
		}

		if c < 0xc0 { // Isolated 10xx xxxx byte
			return PCRE2_ERROR_UTF8_ERR20, uint64(p)
		}

		if c >= 0xfe { // Invalid 0xfe or 0xff bytes
			return PCRE2_ERROR_UTF8_ERR21, uint64(p)
		}

		ab := uint64(utf8_table4[c&0x3f]) // Number of additional bytes (1-5)
		if length < ab {                  // Missing bytes
			switch ab - length {
			case 1:
				return PCRE2_ERROR_UTF8_ERR1, uint64(p)
			case 2:
				return PCRE2_ERROR_UTF8_ERR2, uint64(p)
			case 3:
				return PCRE2_ERROR_UTF8_ERR3, uint64(p)
			case 4:
				return PCRE2_ERROR_UTF8_ERR4, uint64(p)
			case 5:
				return PCRE2_ERROR_UTF8_ERR5, uint64(p)
			}
		}
		length -= ab // Length remaining

		// Check top bits in the second byte
		p++
		d := uint32(str[p])
		if d&0xc0 != 0x80 {
			return PCRE2_ERROR_UTF8_ERR6, uint64(p - 1)
		}

		// For each length, check that the remaining bytes start with the 0x80
		// bit set and not the 0x40 bit. Then check for an overlong sequence,
		// and for the excluded range 0xd800 to 0xdfff.
		switch ab {
		case 1: // 2-byte character: overlong if xx00 000x
			if c&0x3e == 0 {
				return PCRE2_ERROR_UTF8_ERR15, uint64(p - 1)
			}

		case 2: // 3-byte character
			p++
			if str[p]&0xc0 != 0x80 { // Third byte
				return PCRE2_ERROR_UTF8_ERR7, uint64(p - 2)
			}
			if c == 0xe0 && d&0x20 == 0 {
				return PCRE2_ERROR_UTF8_ERR16, uint64(p - 2)
			}
			if c == 0xed && d >= 0xa0 {
				return PCRE2_ERROR_UTF8_ERR14, uint64(p - 2)
			}

		case 3: // 4-byte character
			p++
			if str[p]&0xc0 != 0x80 { // Third byte
				return PCRE2_ERROR_UTF8_ERR7, uint64(p - 2)
			}
			p++
			if str[p]&0xc0 != 0x80 { // Fourth byte
				return PCRE2_ERROR_UTF8_ERR8, uint64(p - 3)
			}
			if c == 0xf0 && d&0x30 == 0 {
				return PCRE2_ERROR_UTF8_ERR17, uint64(p - 3)
			}
			if c > 0xf4 || (c == 0xf4 && d > 0x8f) {
				return PCRE2_ERROR_UTF8_ERR13, uint64(p - 3)
			}

		// 5-byte and 6-byte characters are not allowed by RFC 3629, and will
		// be rejected by the length test below; the tests here diagnose
		// overlong sequences.
		case 4: // 5-byte character
			p++
			if str[p]&0xc0 != 0x80 { // Third byte
				return PCRE2_ERROR_UTF8_ERR7, uint64(p - 2)
			}
			p++
			if str[p]&0xc0 != 0x80 { // Fourth byte
				return PCRE2_ERROR_UTF8_ERR8, uint64(p - 3)
			}
			p++
			if str[p]&0xc0 != 0x80 { // Fifth byte
				return PCRE2_ERROR_UTF8_ERR9, uint64(p - 4)
			}
			if c == 0xf8 && d&0x38 == 0 {
				return PCRE2_ERROR_UTF8_ERR18, uint64(p - 4)
			}

		case 5: // 6-byte character
			p++
			if str[p]&0xc0 != 0x80 { // Third byte
				return PCRE2_ERROR_UTF8_ERR7, uint64(p - 2)
			}
			p++
			if str[p]&0xc0 != 0x80 { // Fourth byte
				return PCRE2_ERROR_UTF8_ERR8, uint64(p - 3)
			}
			p++
			if str[p]&0xc0 != 0x80 { // Fifth byte
				return PCRE2_ERROR_UTF8_ERR9, uint64(p - 4)
			}
			p++
			if str[p]&0xc0 != 0x80 { // Sixth byte
				return PCRE2_ERROR_UTF8_ERR10, uint64(p - 5)
			}
			if c == 0xfc && d&0x3c == 0 {
				return PCRE2_ERROR_UTF8_ERR19, uint64(p - 5)
			}
		}

		// Character is valid under RFC 2279, but 5-byte and 6-byte characters
		// are excluded by RFC 3629. p is at the last byte of the character.
		if ab > 3 {
			if ab == 4 {
				return PCRE2_ERROR_UTF8_ERR11, uint64(p) - ab
			}
			return PCRE2_ERROR_UTF8_ERR12, uint64(p) - ab
		}
	}
	return 0, 0
}

// ValidUTF is the exported form: it reports whether s is valid UTF-8 in
// PCRE2's sense, returning 0 or a PCRE2_ERROR_UTF8_ERR* code and the offset.
func ValidUTF(s []byte) (rc int, erroroffset uint64) {
	return valid_utf(s, uint64(len(s)))
}
