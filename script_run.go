// Port of pcre2_script_run.c: checking that a string is a Unicode script run.
package pcre2

// States in the checking process. (pcre2_script_run.c:73-79)
const (
	xSCRIPT_UNSET       = iota // Requirement as yet unknown
	xSCRIPT_MAP                // Bitmap contains acceptable scripts
	xSCRIPT_HANPENDING         // Have had only Han characters
	xSCRIPT_HANHIRAKATA        // Expect Han or Hirikata
	xSCRIPT_HANBOPOMOFO        // Expect Han or Bopomofo
	xSCRIPT_HANHANGUL          // Expect Han or Hangul
)

const (
	xUCD_MAPSIZE  = ucp_Unknown/32 + 1      // pcre2_script_run.c:81
	xFULL_MAPSIZE = ucp_Script_Count/32 + 1 // pcre2_script_run.c:82
)

// Flags of the Han complications. (pcre2_script_run.c:199-202)
const (
	xFOUND_BOPOMOFO = 1
	xFOUND_HIRAGANA = 2
	xFOUND_KATAKANA = 4
	xFOUND_HANGUL   = 8
)

// script_run checks a script run: the characters of subject[ptr:endptr] (ptr is
// C's "pointer to the first character", endptr the offset after the last one;
// utf is true in UTF mode). It returns true if this is a valid script run.
// (pcre2_script_run.c:85)
func script_run(subject []byte, ptr, endptr int, utf bool) bool {
	require_state := uint32(xSCRIPT_UNSET)
	var require_map [xFULL_MAPSIZE]uint32
	var m [xFULL_MAPSIZE]uint32
	require_digitset := uint32(0)
	var c uint32

	// Any string containing fewer than 2 characters is a valid script run.
	if ptr >= endptr {
		return true
	}
	c, ptr = xGETCHARINCTEST(utf, subject, ptr)
	if ptr >= endptr {
		return true
	}

	// Initialize the require map. This is a full-size bitmap that has a bit for
	// every script, as opposed to the maps in ucd_script_sets, which only have
	// bits for scripts less than ucp_Unknown - those that appear in script
	// extension lists. (the Go arrays are zeroed at declaration)

	// Scan strings of two or more characters, checking the Unicode
	// characteristics of each code point. There is special code for scripts that
	// can be combined with characters from the Han Chinese script. This may be
	// used in conjunction with four other scripts in these combinations:
	//
	//  . Han with Hiragana and Katakana is allowed (for Japanese).
	//  . Han with Bopomofo is allowed (for Taiwanese Mandarin).
	//  . Han with Hangul is allowed (for Korean).
	//
	// If the first significant character's script is one of the four, the required
	// script type is immediately known. However, if the first significant
	// character's script is Han, we have to keep checking for a non-Han character.
	// Hence the SCRIPT_HANPENDING state.
	for {
		ucd := xGET_UCD(c)
		script := uint32(ucd.script)

		// If the script is Unknown, the string is not a valid script run. Such
		// characters can only form script runs of length one (see test above).
		if script == ucp_Unknown {
			return false
		}

		// A character without any script extensions whose script is Inherited or
		// Common is always accepted with any script. If there are extensions, the
		// following processing happens for all scripts.
		if xUCD_SCRIPTX_PROP(ucd) != 0 || (script != ucp_Inherited && script != ucp_Common) {
			var OK bool

			// Set up a full-sized map for this character that can include bits for
			// all scripts. Copy the scriptx map for this character (which covers
			// those scripts that appear in script extension lists), set the
			// remaining values to zero, and then, except for Common or Inherited,
			// add this script's bit to the map.
			copy(m[:xUCD_MAPSIZE], ucd_script_sets[xUCD_SCRIPTX_PROP(ucd):])
			for i := xUCD_MAPSIZE; i < xFULL_MAPSIZE; i++ {
				m[i] = 0
			}
			if script != ucp_Common && script != ucp_Inherited {
				xMAPSET(m[:], script)
			}

			// Handle the different checking states
			switch require_state {
			// First significant character - it might follow Common or Inherited
			// characters that do not have any script extensions.
			case xSCRIPT_UNSET:
				switch script {
				case ucp_Han:
					require_state = xSCRIPT_HANPENDING

				case ucp_Hiragana, ucp_Katakana:
					require_state = xSCRIPT_HANHIRAKATA

				case ucp_Bopomofo:
					require_state = xSCRIPT_HANBOPOMOFO

				case ucp_Hangul:
					require_state = xSCRIPT_HANHANGUL

				default:
					require_map = m
					require_state = xSCRIPT_MAP
				}

			// The first significant character was Han. An inspection of the Unicode
			// 11.0.0 files shows that there are the following types of Script
			// Extension list that involve the Han, Bopomofo, Hiragana, Katakana, and
			// Hangul scripts:
			//
			//  . Bopomofo + Han
			//  . Han + Hiragana + Katakana
			//  . Hiragana + Katakana
			//  . Bopopmofo + Hangul + Han + Hiragana + Katakana
			//
			// The following code tries to make sense of this.
			case xSCRIPT_HANPENDING:
				if script != ucp_Han { // Another Han does nothing
					chspecial := uint32(0)

					if xMAPBIT(m[:], ucp_Bopomofo) {
						chspecial |= xFOUND_BOPOMOFO
					}
					if xMAPBIT(m[:], ucp_Hiragana) {
						chspecial |= xFOUND_HIRAGANA
					}
					if xMAPBIT(m[:], ucp_Katakana) {
						chspecial |= xFOUND_KATAKANA
					}
					if xMAPBIT(m[:], ucp_Hangul) {
						chspecial |= xFOUND_HANGUL
					}

					if chspecial == 0 {
						return false // Not allowed with Han
					}

					if chspecial == xFOUND_BOPOMOFO {
						require_state = xSCRIPT_HANBOPOMOFO
					} else if chspecial == (xFOUND_HIRAGANA | xFOUND_KATAKANA) {
						require_state = xSCRIPT_HANHIRAKATA
					}

					// Otherwise this character must be allowed with all of them, so
					// remain in the pending state.
				}

			// Previously encountered one of the "with Han" scripts. Check that
			// this character is appropriate.
			case xSCRIPT_HANHIRAKATA:
				if !xMAPBIT(m[:], ucp_Han) && !xMAPBIT(m[:], ucp_Hiragana) &&
					!xMAPBIT(m[:], ucp_Katakana) {
					return false
				}

			case xSCRIPT_HANBOPOMOFO:
				if !xMAPBIT(m[:], ucp_Han) && !xMAPBIT(m[:], ucp_Bopomofo) {
					return false
				}

			case xSCRIPT_HANHANGUL:
				if !xMAPBIT(m[:], ucp_Han) && !xMAPBIT(m[:], ucp_Hangul) {
					return false
				}

			// Previously encountered one or more characters that are allowed with a
			// list of scripts.
			case xSCRIPT_MAP:
				OK = false

				for i := 0; i < xFULL_MAPSIZE; i++ {
					if (require_map[i] & m[i]) != 0 {
						OK = true
						break
					}
				}

				if !OK {
					return false
				}

				// The rest of the string must be in this script, but we have to
				// allow for the Han complications.
				switch script {
				case ucp_Han:
					require_state = xSCRIPT_HANPENDING

				case ucp_Hiragana, ucp_Katakana:
					require_state = xSCRIPT_HANHIRAKATA

				case ucp_Bopomofo:
					require_state = xSCRIPT_HANBOPOMOFO

				case ucp_Hangul:
					require_state = xSCRIPT_HANHANGUL

				// Compute the intersection of the required list of scripts and the
				// allowed scripts for this character.
				default:
					for i := 0; i < xFULL_MAPSIZE; i++ {
						require_map[i] &= m[i]
					}
				}
			}
		} // End checking character's script and extensions.

		// The character is in an acceptable script. We must now ensure that all
		// decimal digits in the string come from the same set. Some scripts (e.g.
		// Common, Arabic) have more than one set of decimal digits. This code does
		// not allow mixing sets, even within the same script. The vector called
		// ucd_digit_sets[] contains, in its first element, the number of
		// following elements, and then, in ascending order, the code points of the
		// '9' characters in every set of 10 digits. Each set is identified by the
		// offset in the vector of its '9' character. An initial check of the first
		// value picks up ASCII digits quickly. Otherwise, a binary chop is used.
		if ucd.chartype == ucp_Nd {
			var digitset uint32

			if c <= ucd_digit_sets[1] {
				digitset = 1
			} else {
				var mid int
				bot := 1
				top := int(ucd_digit_sets[0])
				for {
					if top <= bot+1 { // <= rather than == is paranoia
						digitset = uint32(top)
						break
					}
					mid = (top + bot) / 2
					if c <= ucd_digit_sets[mid] {
						top = mid
					} else {
						bot = mid
					}
				}
			}

			// A required value of 0 means "unset".
			if require_digitset == 0 {
				require_digitset = digitset
			} else if digitset != require_digitset {
				return false
			}
		} // End digit handling

		// If we haven't yet got to the end, pick up the next character.
		if ptr >= endptr {
			return true
		}
		c, ptr = xGETCHARINCTEST(utf, subject, ptr)
	} // End checking loop
}
