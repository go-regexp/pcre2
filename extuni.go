// Port of pcre2_extuni.c: matching an extended grapheme sequence (\X).
package pcre2

// extuni matches an extended grapheme sequence. (pcre2_extuni.c:96)
//
// C's PCRE2_SPTR pointers become byte offsets into subject: c is the first
// character (already read), eptr the offset of the next character,
// start_subject and end_subject the offsets of the start and end of the
// subject. utf is true in UTF mode. xcount, when not nil, is incremented for
// every additional character (C: int *xcount, NULL if the count is not needed).
// It returns the offset after the end of the sequence.
func extuni(c uint32, subject []byte, eptr, start_subject, end_subject int, utf bool, xcount *int) int {
	was_ep_ZWJ := false
	lgb := uint32(UCD_GRAPHBREAK(c))

	for eptr < end_subject {
		var rgb uint32
		length := 1
		if !utf {
			c = uint32(subject[eptr])
		} else {
			var extra int
			c, extra = GETCHARLEN(subject, eptr)
			length += extra
		}
		rgb = uint32(UCD_GRAPHBREAK(c))
		if (ucp_gbtable[lgb] & (1 << rgb)) == 0 {
			break
		}

		// ZWJ followed by Extended Pictographic is allowed only if the ZWJ was
		// preceded by Extended Pictographic.
		if lgb == ucp_gbZWJ && rgb == ucp_gbExtended_Pictographic && !was_ep_ZWJ {
			break
		}

		// Not breaking between Regional Indicators is allowed only if there
		// are an even number of preceding RIs.
		if lgb == ucp_gbRegional_Indicator && rgb == ucp_gbRegional_Indicator {
			ricount := 0
			bptr := eptr - 1
			if utf {
				bptr = BACKCHAR(subject, bptr)
			}

			// bptr is pointing to the left-hand character
			for bptr > start_subject {
				bptr--
				if utf {
					bptr = BACKCHAR(subject, bptr)
					c = GETCHAR(subject, bptr)
				} else {
					c = uint32(subject[bptr])
				}
				if UCD_GRAPHBREAK(c) != ucp_gbRegional_Indicator {
					break
				}
				ricount++
			}
			if (ricount & 1) != 0 {
				break // Grapheme break required
			}
		}

		// Set a flag when ZWJ follows Extended Pictographic (with optional Extend in
		// between; see next statement).
		was_ep_ZWJ = lgb == ucp_gbExtended_Pictographic && rgb == ucp_gbZWJ

		// If Extend follows Extended_Pictographic, do not update lgb; this allows
		// any number of them before a following ZWJ.
		if rgb != ucp_gbExtend || lgb != ucp_gbExtended_Pictographic {
			lgb = rgb
		}

		eptr += length
		if xcount != nil {
			*xcount++
		}
	}

	return eptr
}
