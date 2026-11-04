// Port of pcre2_xclass.c: matching a character against an extended class
// (OP_XCLASS) that may contain code points above 255 and/or Unicode properties.
package pcre2

// xclass matches the character c against an extended class. data is the slice
// starting at the flag code unit of the XCLASS data (C: PCRE2_SPTR data, "points
// to the flag code unit"), that is, just after the OP_XCLASS opcode and its
// LINK_SIZE length. data[0] holds XCL_NOT/XCL_MAP/XCL_HASPROP, then comes the
// 32-byte bitmap when XCL_MAP is set, then the XCL_* items up to XCL_END.
// It returns true if the character matches, else false. (pcre2_xclass.c:69)
func xclass(c uint32, data []byte, utf bool) bool {
	var t byte
	negated := (data[0] & XCL_NOT) != 0

	// In 8 bit mode, this must always be TRUE. (pcre2_xclass.c:74-77)
	utf = true

	// Code points < 256 are matched against a bitmap, if one is present. If not,
	// we still carry on, because there may be ranges that start below 256 in the
	// additional data.
	if c < 256 {
		if (data[0] & XCL_HASPROP) == 0 {
			if (data[0] & XCL_MAP) == 0 {
				return negated
			}
			return (data[1+c/8] & (1 << (c & 7))) != 0
		}
		if (data[0]&XCL_MAP) != 0 && (data[1+c/8]&(1<<(c&7))) != 0 {
			return !negated // char found
		}
	}

	// First skip the bit map if present. Then match against the list of Unicode
	// properties or large chars or ranges that end with a large char.
	p := 1
	if (data[0] & XCL_MAP) != 0 {
		p += 32
	}

	for {
		t = data[p]
		p++
		if t == XCL_END {
			break
		}
		var x, y uint32
		if t == XCL_SINGLE {
			if utf {
				x, p = GETCHARINC(data, p)
			} else {
				x = uint32(data[p])
				p++
			}
			if c == x {
				return !negated
			}
		} else if t == XCL_RANGE {
			if utf {
				x, p = GETCHARINC(data, p)
				y, p = GETCHARINC(data, p)
			} else {
				x = uint32(data[p])
				y = uint32(data[p+1])
				p += 2
			}
			if c >= x && c <= y {
				return !negated
			}
		} else { // XCL_PROP & XCL_NOTPROP
			var chartype uint8
			prop := GET_UCD(c)
			isprop := t == XCL_PROP
			var ok bool

			switch data[p] {
			case PT_ANY:
				if isprop {
					return !negated
				}

			case PT_LAMP:
				chartype = prop.chartype
				if (chartype == ucp_Lu || chartype == ucp_Ll ||
					chartype == ucp_Lt) == isprop {
					return !negated
				}

			case PT_GC:
				if (uint32(data[p+1]) == ucp_gentype[prop.chartype]) == isprop {
					return !negated
				}

			case PT_PC:
				if (data[p+1] == prop.chartype) == isprop {
					return !negated
				}

			case PT_SC:
				if (data[p+1] == prop.script) == isprop {
					return !negated
				}

			case PT_SCX:
				ok = data[p+1] == prop.script ||
					MAPBIT(ucd_script_sets[UCD_SCRIPTX_PROP(prop):], uint32(data[p+1]))
				if ok == isprop {
					return !negated
				}

			case PT_ALNUM:
				chartype = prop.chartype
				if (ucp_gentype[chartype] == ucp_L ||
					ucp_gentype[chartype] == ucp_N) == isprop {
					return !negated
				}

			// Perl space used to exclude VT, but from Perl 5.18 it is included,
			// which means that Perl space and POSIX space are now identical. PCRE
			// was changed at release 8.34.
			case PT_SPACE, PT_PXSPACE: // Perl space, POSIX space
				if xclassHVSpace(c) { // HSPACE_CASES, VSPACE_CASES
					if isprop {
						return !negated
					}
				} else if (ucp_gentype[prop.chartype] == ucp_Z) == isprop {
					return !negated
				}

			case PT_WORD:
				chartype = prop.chartype
				if (ucp_gentype[chartype] == ucp_L ||
					ucp_gentype[chartype] == ucp_N ||
					chartype == ucp_Mn || chartype == ucp_Pc) == isprop {
					return !negated
				}

			case PT_UCNC:
				if c < 0xa0 {
					if (c == CHAR_DOLLAR_SIGN || c == CHAR_COMMERCIAL_AT ||
						c == CHAR_GRAVE_ACCENT) == isprop {
						return !negated
					}
				} else {
					if (c < 0xd800 || c > 0xdfff) == isprop {
						return !negated
					}
				}

			case PT_BIDICL:
				if (UCD_BIDICLASS_PROP(prop) == uint32(data[p+1])) == isprop {
					return !negated
				}

			case PT_BOOL:
				ok = MAPBIT(ucd_boolprop_sets[UCD_BPROPS_PROP(prop):], uint32(data[p+1]))
				if ok == isprop {
					return !negated
				}

			// The following three properties can occur only in an XCLASS, as there
			// is no \p or \P coding for them.

			// Graphic character. Implement this as not Z (space or separator) and
			// not C (other), except for Cf (format) with a few exceptions. This
			// seems to be what Perl does. The exceptional characters are:
			//
			//	U+061C           Arabic Letter Mark
			//	U+180E           Mongolian Vowel Separator
			//	U+2066 - U+2069  Various "isolate"s
			case PT_PXGRAPH:
				chartype = prop.chartype
				if (ucp_gentype[chartype] != ucp_Z &&
					(ucp_gentype[chartype] != ucp_C ||
						(chartype == ucp_Cf &&
							c != 0x061c && c != 0x180e && (c < 0x2066 || c > 0x2069)))) == isprop {
					return !negated
				}

			// Printable character: same as graphic, with the addition of Zs, i.e.
			// not Zl and not Zp, and U+180E.
			case PT_PXPRINT:
				chartype = prop.chartype
				if (chartype != ucp_Zl &&
					chartype != ucp_Zp &&
					(ucp_gentype[chartype] != ucp_C ||
						(chartype == ucp_Cf &&
							c != 0x061c && (c < 0x2066 || c > 0x2069)))) == isprop {
					return !negated
				}

			// Punctuation: all Unicode punctuation, plus ASCII characters that
			// Unicode treats as symbols rather than punctuation, for Perl
			// compatibility (these are $+<=>^`|~).
			case PT_PXPUNCT:
				chartype = prop.chartype
				if (ucp_gentype[chartype] == ucp_P ||
					(c < 128 && ucp_gentype[chartype] == ucp_S)) == isprop {
					return !negated
				}

			// Perl has two sets of hex digits
			case PT_PXXDIGIT:
				if ((c >= CHAR_0 && c <= CHAR_9) ||
					(c >= CHAR_A && c <= CHAR_F) ||
					(c >= CHAR_a && c <= CHAR_f) ||
					(c >= 0xff10 && c <= 0xff19) || // Fullwidth digits
					(c >= 0xff21 && c <= 0xff26) || // Fullwidth letters
					(c >= 0xff41 && c <= 0xff46)) == isprop {
					return !negated
				}

			// This should never occur, but compilers may mutter if there is no
			// default.
			default:
				return false
			}

			p += 2
		}
	}

	return negated // char did not match
}

// xclassHVSpace is the union of the HSPACE_CASES and VSPACE_CASES case labels
// of pcre2_internal.h:406-449 (Unicode variant).
func xclassHVSpace(c uint32) bool {
	switch c {
	case CHAR_HT, CHAR_SPACE, CHAR_NBSP, // HSPACE_BYTE_CASES
		0x1680, 0x180e, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005,
		0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x202f, 0x205f, 0x3000, // HSPACE_MULTIBYTE_CASES
		CHAR_LF, CHAR_VT, CHAR_FF, CHAR_CR, CHAR_NEL, // VSPACE_BYTE_CASES
		0x2028, 0x2029: // VSPACE_MULTIBYTE_CASES
		return true
	}
	return false
}
