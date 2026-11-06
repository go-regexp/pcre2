// Port of pcre2_printint.c: the debugging printer of a compiled pattern used by
// pcre2test (/debug, /bincode, /fullbincode).
package pcre2

import (
	"fmt"
	"strings"
)

// OP_names is OP_NAME_LIST of pcre2_internal.h:1674-1714: textual names for all
// the opcodes, used only for debugging.
var xOP_names = [...]string{
	"End", "\\A", "\\G", "\\K", "\\B", "\\b", "\\D", "\\d",
	"\\S", "\\s", "\\W", "\\w", "Any", "AllAny", "Anybyte",
	"notprop", "prop", "\\R", "\\H", "\\h", "\\V", "\\v",
	"extuni", "\\Z", "\\z",
	"$", "$", "^", "^", "char", "chari", "not", "noti",
	"*", "*?", "+", "+?", "?", "??",
	"{", "{", "{",
	"*+", "++", "?+", "{",
	"*", "*?", "+", "+?", "?", "??",
	"{", "{", "{",
	"*+", "++", "?+", "{",
	"*", "*?", "+", "+?", "?", "??",
	"{", "{", "{",
	"*+", "++", "?+", "{",
	"*", "*?", "+", "+?", "?", "??",
	"{", "{", "{",
	"*+", "++", "?+", "{",
	"*", "*?", "+", "+?", "?", "??", "{", "{", "{",
	"*+", "++", "?+", "{",
	"*", "*?", "+", "+?", "?", "??", "{", "{",
	"*+", "++", "?+", "{",
	"class", "nclass", "xclass", "Ref", "Refi", "DnRef", "DnRefi",
	"Recurse", "Callout", "CalloutStr",
	"Alt", "Ket", "KetRmax", "KetRmin", "KetRpos",
	"Reverse", "VReverse", "Assert", "Assert not",
	"Assert back", "Assert back not",
	"Non-atomic assert", "Non-atomic assert back",
	"Once",
	"Script run",
	"Bra", "BraPos", "CBra", "CBraPos",
	"Cond",
	"SBra", "SBraPos", "SCBra", "SCBraPos",
	"SCond",
	"Cond ref", "Cond dnref", "Cond rec", "Cond dnrec",
	"Cond false", "Cond true",
	"Brazero", "Braminzero", "Braposzero",
	"*MARK", "*PRUNE", "*PRUNE", "*SKIP", "*SKIP",
	"*THEN", "*THEN", "*COMMIT", "*COMMIT", "*FAIL",
	"*ACCEPT", "*ASSERT_ACCEPT",
	"Close", "Skip zero", "Define", "\\B (ucp)", "\\b (ucp)",
}

// printable is PRINTABLE of pcre2test.c:251 (ASCII).
func printable(c uint32) bool { return c >= 32 && c < 127 }

// print_char prints one character from a string; in UTF mode the character may
// occupy more than one code unit. It returns the number of additional code
// units used. (pcre2_printint.c:91-184, 8-bit)
func print_char(f *strings.Builder, ptr []byte, utf bool) int {
	c := uint32(ptr[0])
	one_code_unit := !utf

	if utf {
		one_code_unit = c < 0x80
	}

	// Handle a valid one-code-unit character.
	if one_code_unit {
		if printable(c) {
			fmt.Fprintf(f, "%c", rune(c))
		} else if c < 0x80 {
			fmt.Fprintf(f, "\\x%02x", c)
		} else {
			fmt.Fprintf(f, "\\x{%02x}", c)
		}
		return 0
	}

	// Malformed UTF-8 should occur only if the sanity check has been turned off.
	// Rather than swallow random bytes, just stop if we hit a bad one. Print it
	// with \X instead of \x as an indication.
	if c&0xc0 != 0xc0 {
		fmt.Fprintf(f, "\\X{%x}", c) // Invalid starting byte
		return 0
	}
	a := int(utf8_table4[c&0x3f]) // Number of additional bytes
	s := 6 * a
	c = (c & uint32(utf8_table3[a])) << s
	for i := 1; i <= a; i++ {
		if i >= len(ptr) || ptr[i]&0xc0 != 0x80 {
			fmt.Fprintf(f, "\\X{%x}", c) // Invalid secondary byte
			return i - 1
		}
		s -= 6
		c |= uint32(ptr[i]&0x3f) << s
	}
	fmt.Fprintf(f, "\\x{%x}", c)
	return a
}

// print_custring prints a zero-terminated string as a list of code units.
// (pcre2_printint.c:204-212)
func print_custring(f *strings.Builder, ptr []byte) {
	for _, b := range ptr {
		if b == 0 {
			break
		}
		c := uint32(b)
		if printable(c) {
			fmt.Fprintf(f, "%c", rune(c))
		} else {
			fmt.Fprintf(f, "\\x{%x}", c)
		}
	}
}

// print_custring_bylen prints len code units. (pcre2_printint.c:214-222)
func print_custring_bylen(f *strings.Builder, ptr []byte, n int) {
	for i := 0; i < n; i++ {
		c := uint32(ptr[i])
		if printable(c) {
			fmt.Fprintf(f, "%c", rune(c))
		} else {
			fmt.Fprintf(f, "\\x{%x}", c)
		}
	}
}

// get_ucpname finds the Unicode property name: the longer of two found names,
// or a 3-character script name. (pcre2_printint.c:239-280)
func get_ucpname(ptype, pvalue uint32) string {
	count := 0
	yield := "??"
	length := 0
	ptypex := ptype
	if ptype == xPT_SC {
		ptypex = xPT_SCX
	}

	for i := utt_size - 1; i >= 0; i-- {
		u := &utt[i]

		if (ptype == uint32(u.typ) || ptypex == uint32(u.typ)) && pvalue == uint32(u.value) {
			s := utt_names[u.nameOffset:]
			s = s[:strings.IndexByte(s, 0)]
			sl := len(s)

			if sl == 3 && (u.typ == xPT_SC || u.typ == xPT_SCX) {
				yield = s
				break
			}

			if sl > length {
				yield = s
				length = sl
			}

			count++
			if count >= 2 {
				break
			}
		}
	}

	return yield
}

// upperFirst is "%c%s" of toupper(s[0]), s+1.
func upperFirst(s string) string {
	if s == "" {
		return ""
	}
	c := s[0]
	if c >= 'a' && c <= 'z' {
		c -= 'a' - 'A'
	}
	return string(c) + s[1:]
}

// print_prop prints a Unicode property value; code[0] is the OP_PROP or
// OP_NOTPROP opcode. (pcre2_printint.c:301-317)
func print_prop(f *strings.Builder, code []byte, before, after string) {
	if code[1] != xPT_CLIST {
		sc := ""
		if code[1] == xPT_SC {
			sc = "script:"
		}
		s := get_ucpname(uint32(code[1]), uint32(code[2]))
		fmt.Fprintf(f, "%s%s %s%s%s", before, xOP_names[code[0]], sc, upperFirst(s), after)
	} else {
		p := int(code[2])
		not := "not "
		if code[0] == xOP_PROP {
			not = ""
		}
		fmt.Fprintf(f, "%s%sclist", before, not)
		for ucd_caseless_sets[p] < xNOTACHAR {
			fmt.Fprintf(f, " %04x", ucd_caseless_sets[p])
			p++
		}
		fmt.Fprintf(f, "%s", after)
	}
}

// PrintInt returns the text pcre2_printint() writes for the compiled pattern,
// final line of dashes included (implements the pcre2testgo CodeDumper).
// full is print_lengths.
func (re *Code) PrintInt(full bool) string {
	var b strings.Builder
	pcre2_printint(re, &b, full)
	return b.String()
}

// pcre2_printint prints the compiled pattern. print_lengths controls whether
// offsets and lengths of items are printed. (pcre2_printint.c:337-884)
func pcre2_printint(re *Code, f *strings.Builder, print_lengths bool) {
	nesize := int(re.nameEntrySize)
	utf := re.overallOptions&PCRE2_UTF != 0

	nametable := re.nameTable()
	code := re.startCode()
	pos := 0

	for {
		flag := "  "
		extra := 0

		if print_lengths {
			fmt.Fprintf(f, "%3d ", pos)
		} else {
			fmt.Fprintf(f, "    ")
		}

		op := code[pos]
		c := code[pos:]
		var ccode int // index into code, used by the class and back reference repeats

		// classRefRepeat is the CLASS_REF_REPEAT label.
		classRefRepeat := func() {
			switch code[ccode] {
			case xOP_CRSTAR, xOP_CRMINSTAR, xOP_CRPLUS, xOP_CRMINPLUS, xOP_CRQUERY,
				xOP_CRMINQUERY, xOP_CRPOSSTAR, xOP_CRPOSPLUS, xOP_CRPOSQUERY:
				fmt.Fprintf(f, "%s", xOP_names[code[ccode]])
				extra += int(xOP_lengths[code[ccode]])

			case xOP_CRRANGE, xOP_CRMINRANGE, xOP_CRPOSRANGE:
				min := xGET2(code, ccode+1)
				max := xGET2(code, ccode+1+xIMM2_SIZE)
				if max == 0 {
					fmt.Fprintf(f, "{%d,}", min)
				} else {
					fmt.Fprintf(f, "{%d,%d}", min, max)
				}
				if code[ccode] == xOP_CRMINRANGE {
					fmt.Fprintf(f, "?")
				} else if code[ccode] == xOP_CRPOSRANGE {
					fmt.Fprintf(f, "+")
				}
				extra += int(xOP_lengths[code[ccode]])
			}
		}

		switch op {
		case xOP_END:
			fmt.Fprintf(f, "    %s\n", xOP_names[op])
			fmt.Fprintf(f, "------------------------------------------------------------------\n")
			return

		case xOP_CHAR:
			fmt.Fprintf(f, "    ")
			for {
				pos++
				pos += 1 + print_char(f, code[pos:], utf)
				if code[pos] != xOP_CHAR {
					break
				}
			}
			fmt.Fprintf(f, "\n")
			continue

		case xOP_CHARI:
			fmt.Fprintf(f, " /i ")
			for {
				pos++
				pos += 1 + print_char(f, code[pos:], utf)
				if code[pos] != xOP_CHARI {
					break
				}
			}
			fmt.Fprintf(f, "\n")
			continue

		case xOP_CBRA, xOP_CBRAPOS, xOP_SCBRA, xOP_SCBRAPOS:
			if print_lengths {
				fmt.Fprintf(f, "%3d ", xGET(c, 1))
			} else {
				fmt.Fprintf(f, "    ")
			}
			fmt.Fprintf(f, "%s %d", xOP_names[op], xGET2(c, 1+xLINK_SIZE))

		case xOP_BRA, xOP_BRAPOS, xOP_SBRA, xOP_SBRAPOS, xOP_KETRMAX, xOP_KETRMIN,
			xOP_KETRPOS, xOP_ALT, xOP_KET, xOP_ASSERT, xOP_ASSERT_NOT, xOP_ASSERTBACK,
			xOP_ASSERTBACK_NOT, xOP_ASSERT_NA, xOP_ASSERTBACK_NA, xOP_ONCE,
			xOP_SCRIPT_RUN, xOP_COND, xOP_SCOND:
			if print_lengths {
				fmt.Fprintf(f, "%3d ", xGET(c, 1))
			} else {
				fmt.Fprintf(f, "    ")
			}
			fmt.Fprintf(f, "%s", xOP_names[op])

		case xOP_REVERSE:
			if print_lengths {
				fmt.Fprintf(f, "%3d ", xGET2(c, 1))
			} else {
				fmt.Fprintf(f, "    ")
			}
			fmt.Fprintf(f, "%s", xOP_names[op])

		case xOP_VREVERSE:
			if print_lengths {
				fmt.Fprintf(f, "%3d %d ", xGET2(c, 1), xGET2(c, 1+xIMM2_SIZE))
			} else {
				fmt.Fprintf(f, "    ")
			}
			fmt.Fprintf(f, "%s", xOP_names[op])

		case xOP_CLOSE:
			fmt.Fprintf(f, "    %s %d", xOP_names[op], xGET2(c, 1))

		case xOP_CREF:
			fmt.Fprintf(f, "%3d %s", xGET2(c, 1), xOP_names[op])

		case xOP_DNCREF:
			entry := nametable[xGET2(c, 1)*nesize+xIMM2_SIZE:]
			fmt.Fprintf(f, " %s Cond ref <", flag)
			print_custring(f, entry)
			fmt.Fprintf(f, ">%d", xGET2(c, 1+xIMM2_SIZE))

		case xOP_RREF:
			cc := xGET2(c, 1)
			if cc == xRREF_ANY {
				fmt.Fprintf(f, "    Cond recurse any")
			} else {
				fmt.Fprintf(f, "    Cond recurse %d", cc)
			}

		case xOP_DNRREF:
			entry := nametable[xGET2(c, 1)*nesize+xIMM2_SIZE:]
			fmt.Fprintf(f, " %s Cond recurse <", flag)
			print_custring(f, entry)
			fmt.Fprintf(f, ">%d", xGET2(c, 1+xIMM2_SIZE))

		case xOP_FALSE:
			fmt.Fprintf(f, "    Cond false")

		case xOP_TRUE:
			fmt.Fprintf(f, "    Cond true")

		case xOP_STARI, xOP_MINSTARI, xOP_POSSTARI, xOP_PLUSI, xOP_MINPLUSI,
			xOP_POSPLUSI, xOP_QUERYI, xOP_MINQUERYI, xOP_POSQUERYI,
			xOP_STAR, xOP_MINSTAR, xOP_POSSTAR, xOP_PLUS, xOP_MINPLUS, xOP_POSPLUS,
			xOP_QUERY, xOP_MINQUERY, xOP_POSQUERY, xOP_TYPESTAR, xOP_TYPEMINSTAR,
			xOP_TYPEPOSSTAR, xOP_TYPEPLUS, xOP_TYPEMINPLUS, xOP_TYPEPOSPLUS,
			xOP_TYPEQUERY, xOP_TYPEMINQUERY, xOP_TYPEPOSQUERY:
			switch op {
			case xOP_STARI, xOP_MINSTARI, xOP_POSSTARI, xOP_PLUSI, xOP_MINPLUSI,
				xOP_POSPLUSI, xOP_QUERYI, xOP_MINQUERYI, xOP_POSQUERYI:
				flag = "/i"
			}
			fmt.Fprintf(f, " %s ", flag)

			if op >= xOP_TYPESTAR {
				if c[1] == xOP_PROP || c[1] == xOP_NOTPROP {
					print_prop(f, c[1:], "", " ")
					extra = 2
				} else {
					fmt.Fprintf(f, "%s", xOP_names[c[1]])
				}
			} else {
				extra = print_char(f, c[1:], utf)
			}
			fmt.Fprintf(f, "%s", xOP_names[op])

		case xOP_EXACTI, xOP_UPTOI, xOP_MINUPTOI, xOP_POSUPTOI,
			xOP_EXACT, xOP_UPTO, xOP_MINUPTO, xOP_POSUPTO:
			switch op {
			case xOP_EXACTI, xOP_UPTOI, xOP_MINUPTOI, xOP_POSUPTOI:
				flag = "/i"
			}
			fmt.Fprintf(f, " %s ", flag)
			extra = print_char(f, c[1+xIMM2_SIZE:], utf)
			fmt.Fprintf(f, "{")
			if op != xOP_EXACT && op != xOP_EXACTI {
				fmt.Fprintf(f, "0,")
			}
			fmt.Fprintf(f, "%d}", xGET2(c, 1))
			if op == xOP_MINUPTO || op == xOP_MINUPTOI {
				fmt.Fprintf(f, "?")
			} else if op == xOP_POSUPTO || op == xOP_POSUPTOI {
				fmt.Fprintf(f, "+")
			}

		case xOP_TYPEEXACT, xOP_TYPEUPTO, xOP_TYPEMINUPTO, xOP_TYPEPOSUPTO:
			if c[1+xIMM2_SIZE] == xOP_PROP || c[1+xIMM2_SIZE] == xOP_NOTPROP {
				print_prop(f, c[xIMM2_SIZE+1:], "    ", " ")
				extra = 2
			} else {
				fmt.Fprintf(f, "    %s", xOP_names[c[1+xIMM2_SIZE]])
			}
			fmt.Fprintf(f, "{")
			if op != xOP_TYPEEXACT {
				fmt.Fprintf(f, "0,")
			}
			fmt.Fprintf(f, "%d}", xGET2(c, 1))
			if op == xOP_TYPEMINUPTO {
				fmt.Fprintf(f, "?")
			} else if op == xOP_TYPEPOSUPTO {
				fmt.Fprintf(f, "+")
			}

		case xOP_NOTI, xOP_NOT:
			if op == xOP_NOTI {
				flag = "/i"
			}
			fmt.Fprintf(f, " %s [^", flag)
			extra = print_char(f, c[1:], utf)
			fmt.Fprintf(f, "]")

		case xOP_NOTSTARI, xOP_NOTMINSTARI, xOP_NOTPOSSTARI, xOP_NOTPLUSI,
			xOP_NOTMINPLUSI, xOP_NOTPOSPLUSI, xOP_NOTQUERYI, xOP_NOTMINQUERYI,
			xOP_NOTPOSQUERYI,
			xOP_NOTSTAR, xOP_NOTMINSTAR, xOP_NOTPOSSTAR, xOP_NOTPLUS, xOP_NOTMINPLUS,
			xOP_NOTPOSPLUS, xOP_NOTQUERY, xOP_NOTMINQUERY, xOP_NOTPOSQUERY:
			switch op {
			case xOP_NOTSTARI, xOP_NOTMINSTARI, xOP_NOTPOSSTARI, xOP_NOTPLUSI,
				xOP_NOTMINPLUSI, xOP_NOTPOSPLUSI, xOP_NOTQUERYI, xOP_NOTMINQUERYI,
				xOP_NOTPOSQUERYI:
				flag = "/i"
			}
			fmt.Fprintf(f, " %s [^", flag)
			extra = print_char(f, c[1:], utf)
			fmt.Fprintf(f, "]%s", xOP_names[op])

		case xOP_NOTEXACTI, xOP_NOTUPTOI, xOP_NOTMINUPTOI, xOP_NOTPOSUPTOI,
			xOP_NOTEXACT, xOP_NOTUPTO, xOP_NOTMINUPTO, xOP_NOTPOSUPTO:
			switch op {
			case xOP_NOTEXACTI, xOP_NOTUPTOI, xOP_NOTMINUPTOI, xOP_NOTPOSUPTOI:
				flag = "/i"
			}
			fmt.Fprintf(f, " %s [^", flag)
			extra = print_char(f, c[1+xIMM2_SIZE:], utf)
			fmt.Fprintf(f, "]{")
			if op != xOP_NOTEXACT && op != xOP_NOTEXACTI {
				fmt.Fprintf(f, "0,")
			}
			fmt.Fprintf(f, "%d}", xGET2(c, 1))
			if op == xOP_NOTMINUPTO || op == xOP_NOTMINUPTOI {
				fmt.Fprintf(f, "?")
			} else if op == xOP_NOTPOSUPTO || op == xOP_NOTPOSUPTOI {
				fmt.Fprintf(f, "+")
			}

		case xOP_RECURSE:
			if print_lengths {
				fmt.Fprintf(f, "%3d ", xGET(c, 1))
			} else {
				fmt.Fprintf(f, "    ")
			}
			fmt.Fprintf(f, "%s", xOP_names[op])

		case xOP_REFI, xOP_REF:
			if op == xOP_REFI {
				flag = "/i"
			}
			fmt.Fprintf(f, " %s \\%d", flag, xGET2(c, 1))
			ccode = pos + int(xOP_lengths[op])
			classRefRepeat()

		case xOP_DNREFI, xOP_DNREF:
			if op == xOP_DNREFI {
				flag = "/i"
			}
			entry := nametable[xGET2(c, 1)*nesize+xIMM2_SIZE:]
			fmt.Fprintf(f, " %s \\k<", flag)
			print_custring(f, entry)
			fmt.Fprintf(f, ">%d", xGET2(c, 1+xIMM2_SIZE))
			ccode = pos + int(xOP_lengths[op])
			classRefRepeat()

		case xOP_CALLOUT:
			fmt.Fprintf(f, "    %s %d %d %d", xOP_names[op], c[1+2*xLINK_SIZE],
				xGET(c, 1), xGET(c, 1+xLINK_SIZE))

		case xOP_CALLOUT_STR:
			cc := uint32(c[1+4*xLINK_SIZE])
			fmt.Fprintf(f, "    %s %c", xOP_names[op], rune(cc))
			extra = xGET(c, 1+2*xLINK_SIZE)
			print_custring_bylen(f, c[2+4*xLINK_SIZE:], extra-3-4*xLINK_SIZE)
			for i := 0; callout_start_delims[i] != 0; i++ {
				if cc == callout_start_delims[i] {
					cc = callout_end_delims[i]
					break
				}
			}
			fmt.Fprintf(f, "%c %d %d %d", rune(cc), xGET(c, 1+3*xLINK_SIZE), xGET(c, 1),
				xGET(c, 1+xLINK_SIZE))

		case xOP_PROP, xOP_NOTPROP:
			print_prop(f, c, "    ", "")

		case xOP_CLASS, xOP_NCLASS, xOP_XCLASS:
			var printmap, invertmap bool

			fmt.Fprintf(f, "    [")

			// Negative XCLASS has an inverted map whereas the original opcodes
			// have already done the inversion.

			invertmap = false
			if op == xOP_XCLASS {
				extra = xGET(c, 1)
				ccode = pos + xLINK_SIZE + 1
				printmap = code[ccode]&xXCL_MAP != 0
				if code[ccode]&xXCL_NOT != 0 {
					invertmap = code[ccode]&xXCL_HASPROP == 0
					fmt.Fprintf(f, "^")
				}
				ccode++
			} else { // CLASS or NCLASS
				printmap = true
				ccode = pos + 1
			}

			// Print a bit map

			if printmap {
				var inverted_map [32]byte
				m := code[ccode : ccode+32]

				if invertmap {
					for i := 0; i < 32; i++ {
						inverted_map[i] = 255 ^ m[i]
					}
					m = inverted_map[:]
				}

				for i := 0; i < 256; i++ {
					if m[i/8]&(1<<(i&7)) != 0 {
						j := i + 1
						for ; j < 256; j++ {
							if m[j/8]&(1<<(j&7)) == 0 {
								break
							}
						}
						if i == '-' || i == ']' {
							fmt.Fprintf(f, "\\")
						}
						if printable(uint32(i)) {
							fmt.Fprintf(f, "%c", rune(i))
						} else {
							fmt.Fprintf(f, "\\x%02x", i)
						}
						j--
						if j > i {
							if j != i+1 {
								fmt.Fprintf(f, "-")
							}
							if j == '-' || j == ']' {
								fmt.Fprintf(f, "\\")
							}
							if printable(uint32(j)) {
								fmt.Fprintf(f, "%c", rune(j))
							} else {
								fmt.Fprintf(f, "\\x%02x", j)
							}
						}
						i = j
					}
				}
				ccode += 32
			}

			// For an XCLASS there is always some additional data

			if op == xOP_XCLASS {
				for {
					ch := code[ccode]
					ccode++
					if ch == xXCL_END {
						break
					}
					notch := ""

					switch ch {
					case xXCL_NOTPROP, xXCL_PROP:
						if ch == xXCL_NOTPROP {
							notch = "^"
						}
						ptype := uint32(code[ccode])
						ccode++
						pvalue := uint32(code[ccode])
						ccode++

						switch ptype {
						case xPT_PXGRAPH:
							fmt.Fprintf(f, "[:%sgraph:]", notch)
						case xPT_PXPRINT:
							fmt.Fprintf(f, "[:%sprint:]", notch)
						case xPT_PXPUNCT:
							fmt.Fprintf(f, "[:%spunct:]", notch)
						case xPT_PXXDIGIT:
							fmt.Fprintf(f, "[:%sxdigit:]", notch)
						default:
							s := get_ucpname(ptype, pvalue)
							pc := 'p'
							if notch == "^" {
								pc = 'P'
							}
							fmt.Fprintf(f, "\\%c{%s}", pc, upperFirst(s))
						}

					default:
						ccode += 1 + print_char(f, code[ccode:], utf)
						if ch == xXCL_RANGE {
							fmt.Fprintf(f, "-")
							ccode += 1 + print_char(f, code[ccode:], utf)
						}
					}
				}
			}

			// Indicate a non-UTF class which was created by negation

			if op == xOP_NCLASS {
				fmt.Fprintf(f, "] (neg)")
			} else {
				fmt.Fprintf(f, "]")
			}

			// Handle repeats after a class or a back reference
			classRefRepeat()

		case xOP_MARK, xOP_COMMIT_ARG, xOP_PRUNE_ARG, xOP_SKIP_ARG, xOP_THEN_ARG:
			fmt.Fprintf(f, "    %s ", xOP_names[op])
			print_custring_bylen(f, c[2:], int(c[1]))
			extra += int(c[1])

		case xOP_THEN:
			fmt.Fprintf(f, "    %s", xOP_names[op])

		case xOP_CIRCM, xOP_DOLLM:
			flag = "/m"
			fmt.Fprintf(f, " %s %s", flag, xOP_names[op])

		// Anything else is just an item with no data, but possibly a flag.

		default:
			fmt.Fprintf(f, " %s %s", flag, xOP_names[op])
		}

		pos += int(xOP_lengths[op]) + extra
		fmt.Fprintf(f, "\n")
	}
}
