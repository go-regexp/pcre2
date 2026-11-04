// Port of pcre2_printint.c: the debugging printer of a compiled pattern used by
// pcre2test (/debug, /bincode, /fullbincode).
package pcre2

import (
	"fmt"
	"strings"
)

// OP_names is OP_NAME_LIST of pcre2_internal.h:1674-1714: textual names for all
// the opcodes, used only for debugging.
var OP_names = [...]string{
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
	if ptype == PT_SC {
		ptypex = PT_SCX
	}

	for i := utt_size - 1; i >= 0; i-- {
		u := &utt[i]

		if (ptype == uint32(u.typ) || ptypex == uint32(u.typ)) && pvalue == uint32(u.value) {
			s := utt_names[u.nameOffset:]
			s = s[:strings.IndexByte(s, 0)]
			sl := len(s)

			if sl == 3 && (u.typ == PT_SC || u.typ == PT_SCX) {
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
	if code[1] != PT_CLIST {
		sc := ""
		if code[1] == PT_SC {
			sc = "script:"
		}
		s := get_ucpname(uint32(code[1]), uint32(code[2]))
		fmt.Fprintf(f, "%s%s %s%s%s", before, OP_names[code[0]], sc, upperFirst(s), after)
	} else {
		p := int(code[2])
		not := "not "
		if code[0] == OP_PROP {
			not = ""
		}
		fmt.Fprintf(f, "%s%sclist", before, not)
		for ucd_caseless_sets[p] < NOTACHAR {
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
			case OP_CRSTAR, OP_CRMINSTAR, OP_CRPLUS, OP_CRMINPLUS, OP_CRQUERY,
				OP_CRMINQUERY, OP_CRPOSSTAR, OP_CRPOSPLUS, OP_CRPOSQUERY:
				fmt.Fprintf(f, "%s", OP_names[code[ccode]])
				extra += int(OP_lengths[code[ccode]])

			case OP_CRRANGE, OP_CRMINRANGE, OP_CRPOSRANGE:
				min := GET2(code, ccode+1)
				max := GET2(code, ccode+1+IMM2_SIZE)
				if max == 0 {
					fmt.Fprintf(f, "{%d,}", min)
				} else {
					fmt.Fprintf(f, "{%d,%d}", min, max)
				}
				if code[ccode] == OP_CRMINRANGE {
					fmt.Fprintf(f, "?")
				} else if code[ccode] == OP_CRPOSRANGE {
					fmt.Fprintf(f, "+")
				}
				extra += int(OP_lengths[code[ccode]])
			}
		}

		switch op {
		case OP_END:
			fmt.Fprintf(f, "    %s\n", OP_names[op])
			fmt.Fprintf(f, "------------------------------------------------------------------\n")
			return

		case OP_CHAR:
			fmt.Fprintf(f, "    ")
			for {
				pos++
				pos += 1 + print_char(f, code[pos:], utf)
				if code[pos] != OP_CHAR {
					break
				}
			}
			fmt.Fprintf(f, "\n")
			continue

		case OP_CHARI:
			fmt.Fprintf(f, " /i ")
			for {
				pos++
				pos += 1 + print_char(f, code[pos:], utf)
				if code[pos] != OP_CHARI {
					break
				}
			}
			fmt.Fprintf(f, "\n")
			continue

		case OP_CBRA, OP_CBRAPOS, OP_SCBRA, OP_SCBRAPOS:
			if print_lengths {
				fmt.Fprintf(f, "%3d ", GET(c, 1))
			} else {
				fmt.Fprintf(f, "    ")
			}
			fmt.Fprintf(f, "%s %d", OP_names[op], GET2(c, 1+LINK_SIZE))

		case OP_BRA, OP_BRAPOS, OP_SBRA, OP_SBRAPOS, OP_KETRMAX, OP_KETRMIN,
			OP_KETRPOS, OP_ALT, OP_KET, OP_ASSERT, OP_ASSERT_NOT, OP_ASSERTBACK,
			OP_ASSERTBACK_NOT, OP_ASSERT_NA, OP_ASSERTBACK_NA, OP_ONCE,
			OP_SCRIPT_RUN, OP_COND, OP_SCOND:
			if print_lengths {
				fmt.Fprintf(f, "%3d ", GET(c, 1))
			} else {
				fmt.Fprintf(f, "    ")
			}
			fmt.Fprintf(f, "%s", OP_names[op])

		case OP_REVERSE:
			if print_lengths {
				fmt.Fprintf(f, "%3d ", GET2(c, 1))
			} else {
				fmt.Fprintf(f, "    ")
			}
			fmt.Fprintf(f, "%s", OP_names[op])

		case OP_VREVERSE:
			if print_lengths {
				fmt.Fprintf(f, "%3d %d ", GET2(c, 1), GET2(c, 1+IMM2_SIZE))
			} else {
				fmt.Fprintf(f, "    ")
			}
			fmt.Fprintf(f, "%s", OP_names[op])

		case OP_CLOSE:
			fmt.Fprintf(f, "    %s %d", OP_names[op], GET2(c, 1))

		case OP_CREF:
			fmt.Fprintf(f, "%3d %s", GET2(c, 1), OP_names[op])

		case OP_DNCREF:
			entry := nametable[GET2(c, 1)*nesize+IMM2_SIZE:]
			fmt.Fprintf(f, " %s Cond ref <", flag)
			print_custring(f, entry)
			fmt.Fprintf(f, ">%d", GET2(c, 1+IMM2_SIZE))

		case OP_RREF:
			cc := GET2(c, 1)
			if cc == RREF_ANY {
				fmt.Fprintf(f, "    Cond recurse any")
			} else {
				fmt.Fprintf(f, "    Cond recurse %d", cc)
			}

		case OP_DNRREF:
			entry := nametable[GET2(c, 1)*nesize+IMM2_SIZE:]
			fmt.Fprintf(f, " %s Cond recurse <", flag)
			print_custring(f, entry)
			fmt.Fprintf(f, ">%d", GET2(c, 1+IMM2_SIZE))

		case OP_FALSE:
			fmt.Fprintf(f, "    Cond false")

		case OP_TRUE:
			fmt.Fprintf(f, "    Cond true")

		case OP_STARI, OP_MINSTARI, OP_POSSTARI, OP_PLUSI, OP_MINPLUSI,
			OP_POSPLUSI, OP_QUERYI, OP_MINQUERYI, OP_POSQUERYI,
			OP_STAR, OP_MINSTAR, OP_POSSTAR, OP_PLUS, OP_MINPLUS, OP_POSPLUS,
			OP_QUERY, OP_MINQUERY, OP_POSQUERY, OP_TYPESTAR, OP_TYPEMINSTAR,
			OP_TYPEPOSSTAR, OP_TYPEPLUS, OP_TYPEMINPLUS, OP_TYPEPOSPLUS,
			OP_TYPEQUERY, OP_TYPEMINQUERY, OP_TYPEPOSQUERY:
			switch op {
			case OP_STARI, OP_MINSTARI, OP_POSSTARI, OP_PLUSI, OP_MINPLUSI,
				OP_POSPLUSI, OP_QUERYI, OP_MINQUERYI, OP_POSQUERYI:
				flag = "/i"
			}
			fmt.Fprintf(f, " %s ", flag)

			if op >= OP_TYPESTAR {
				if c[1] == OP_PROP || c[1] == OP_NOTPROP {
					print_prop(f, c[1:], "", " ")
					extra = 2
				} else {
					fmt.Fprintf(f, "%s", OP_names[c[1]])
				}
			} else {
				extra = print_char(f, c[1:], utf)
			}
			fmt.Fprintf(f, "%s", OP_names[op])

		case OP_EXACTI, OP_UPTOI, OP_MINUPTOI, OP_POSUPTOI,
			OP_EXACT, OP_UPTO, OP_MINUPTO, OP_POSUPTO:
			switch op {
			case OP_EXACTI, OP_UPTOI, OP_MINUPTOI, OP_POSUPTOI:
				flag = "/i"
			}
			fmt.Fprintf(f, " %s ", flag)
			extra = print_char(f, c[1+IMM2_SIZE:], utf)
			fmt.Fprintf(f, "{")
			if op != OP_EXACT && op != OP_EXACTI {
				fmt.Fprintf(f, "0,")
			}
			fmt.Fprintf(f, "%d}", GET2(c, 1))
			if op == OP_MINUPTO || op == OP_MINUPTOI {
				fmt.Fprintf(f, "?")
			} else if op == OP_POSUPTO || op == OP_POSUPTOI {
				fmt.Fprintf(f, "+")
			}

		case OP_TYPEEXACT, OP_TYPEUPTO, OP_TYPEMINUPTO, OP_TYPEPOSUPTO:
			if c[1+IMM2_SIZE] == OP_PROP || c[1+IMM2_SIZE] == OP_NOTPROP {
				print_prop(f, c[IMM2_SIZE+1:], "    ", " ")
				extra = 2
			} else {
				fmt.Fprintf(f, "    %s", OP_names[c[1+IMM2_SIZE]])
			}
			fmt.Fprintf(f, "{")
			if op != OP_TYPEEXACT {
				fmt.Fprintf(f, "0,")
			}
			fmt.Fprintf(f, "%d}", GET2(c, 1))
			if op == OP_TYPEMINUPTO {
				fmt.Fprintf(f, "?")
			} else if op == OP_TYPEPOSUPTO {
				fmt.Fprintf(f, "+")
			}

		case OP_NOTI, OP_NOT:
			if op == OP_NOTI {
				flag = "/i"
			}
			fmt.Fprintf(f, " %s [^", flag)
			extra = print_char(f, c[1:], utf)
			fmt.Fprintf(f, "]")

		case OP_NOTSTARI, OP_NOTMINSTARI, OP_NOTPOSSTARI, OP_NOTPLUSI,
			OP_NOTMINPLUSI, OP_NOTPOSPLUSI, OP_NOTQUERYI, OP_NOTMINQUERYI,
			OP_NOTPOSQUERYI,
			OP_NOTSTAR, OP_NOTMINSTAR, OP_NOTPOSSTAR, OP_NOTPLUS, OP_NOTMINPLUS,
			OP_NOTPOSPLUS, OP_NOTQUERY, OP_NOTMINQUERY, OP_NOTPOSQUERY:
			switch op {
			case OP_NOTSTARI, OP_NOTMINSTARI, OP_NOTPOSSTARI, OP_NOTPLUSI,
				OP_NOTMINPLUSI, OP_NOTPOSPLUSI, OP_NOTQUERYI, OP_NOTMINQUERYI,
				OP_NOTPOSQUERYI:
				flag = "/i"
			}
			fmt.Fprintf(f, " %s [^", flag)
			extra = print_char(f, c[1:], utf)
			fmt.Fprintf(f, "]%s", OP_names[op])

		case OP_NOTEXACTI, OP_NOTUPTOI, OP_NOTMINUPTOI, OP_NOTPOSUPTOI,
			OP_NOTEXACT, OP_NOTUPTO, OP_NOTMINUPTO, OP_NOTPOSUPTO:
			switch op {
			case OP_NOTEXACTI, OP_NOTUPTOI, OP_NOTMINUPTOI, OP_NOTPOSUPTOI:
				flag = "/i"
			}
			fmt.Fprintf(f, " %s [^", flag)
			extra = print_char(f, c[1+IMM2_SIZE:], utf)
			fmt.Fprintf(f, "]{")
			if op != OP_NOTEXACT && op != OP_NOTEXACTI {
				fmt.Fprintf(f, "0,")
			}
			fmt.Fprintf(f, "%d}", GET2(c, 1))
			if op == OP_NOTMINUPTO || op == OP_NOTMINUPTOI {
				fmt.Fprintf(f, "?")
			} else if op == OP_NOTPOSUPTO || op == OP_NOTPOSUPTOI {
				fmt.Fprintf(f, "+")
			}

		case OP_RECURSE:
			if print_lengths {
				fmt.Fprintf(f, "%3d ", GET(c, 1))
			} else {
				fmt.Fprintf(f, "    ")
			}
			fmt.Fprintf(f, "%s", OP_names[op])

		case OP_REFI, OP_REF:
			if op == OP_REFI {
				flag = "/i"
			}
			fmt.Fprintf(f, " %s \\%d", flag, GET2(c, 1))
			ccode = pos + int(OP_lengths[op])
			classRefRepeat()

		case OP_DNREFI, OP_DNREF:
			if op == OP_DNREFI {
				flag = "/i"
			}
			entry := nametable[GET2(c, 1)*nesize+IMM2_SIZE:]
			fmt.Fprintf(f, " %s \\k<", flag)
			print_custring(f, entry)
			fmt.Fprintf(f, ">%d", GET2(c, 1+IMM2_SIZE))
			ccode = pos + int(OP_lengths[op])
			classRefRepeat()

		case OP_CALLOUT:
			fmt.Fprintf(f, "    %s %d %d %d", OP_names[op], c[1+2*LINK_SIZE],
				GET(c, 1), GET(c, 1+LINK_SIZE))

		case OP_CALLOUT_STR:
			cc := uint32(c[1+4*LINK_SIZE])
			fmt.Fprintf(f, "    %s %c", OP_names[op], rune(cc))
			extra = GET(c, 1+2*LINK_SIZE)
			print_custring_bylen(f, c[2+4*LINK_SIZE:], extra-3-4*LINK_SIZE)
			for i := 0; callout_start_delims[i] != 0; i++ {
				if cc == callout_start_delims[i] {
					cc = callout_end_delims[i]
					break
				}
			}
			fmt.Fprintf(f, "%c %d %d %d", rune(cc), GET(c, 1+3*LINK_SIZE), GET(c, 1),
				GET(c, 1+LINK_SIZE))

		case OP_PROP, OP_NOTPROP:
			print_prop(f, c, "    ", "")

		case OP_CLASS, OP_NCLASS, OP_XCLASS:
			var printmap, invertmap bool

			fmt.Fprintf(f, "    [")

			// Negative XCLASS has an inverted map whereas the original opcodes
			// have already done the inversion.

			invertmap = false
			if op == OP_XCLASS {
				extra = GET(c, 1)
				ccode = pos + LINK_SIZE + 1
				printmap = code[ccode]&XCL_MAP != 0
				if code[ccode]&XCL_NOT != 0 {
					invertmap = code[ccode]&XCL_HASPROP == 0
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

			if op == OP_XCLASS {
				for {
					ch := code[ccode]
					ccode++
					if ch == XCL_END {
						break
					}
					notch := ""

					switch ch {
					case XCL_NOTPROP, XCL_PROP:
						if ch == XCL_NOTPROP {
							notch = "^"
						}
						ptype := uint32(code[ccode])
						ccode++
						pvalue := uint32(code[ccode])
						ccode++

						switch ptype {
						case PT_PXGRAPH:
							fmt.Fprintf(f, "[:%sgraph:]", notch)
						case PT_PXPRINT:
							fmt.Fprintf(f, "[:%sprint:]", notch)
						case PT_PXPUNCT:
							fmt.Fprintf(f, "[:%spunct:]", notch)
						case PT_PXXDIGIT:
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
						if ch == XCL_RANGE {
							fmt.Fprintf(f, "-")
							ccode += 1 + print_char(f, code[ccode:], utf)
						}
					}
				}
			}

			// Indicate a non-UTF class which was created by negation

			if op == OP_NCLASS {
				fmt.Fprintf(f, "] (neg)")
			} else {
				fmt.Fprintf(f, "]")
			}

			// Handle repeats after a class or a back reference
			classRefRepeat()

		case OP_MARK, OP_COMMIT_ARG, OP_PRUNE_ARG, OP_SKIP_ARG, OP_THEN_ARG:
			fmt.Fprintf(f, "    %s ", OP_names[op])
			print_custring_bylen(f, c[2:], int(c[1]))
			extra += int(c[1])

		case OP_THEN:
			fmt.Fprintf(f, "    %s", OP_names[op])

		case OP_CIRCM, OP_DOLLM:
			flag = "/m"
			fmt.Fprintf(f, " %s %s", flag, OP_names[op])

		// Anything else is just an item with no data, but possibly a flag.

		default:
			fmt.Fprintf(f, " %s %s", flag, OP_names[op])
		}

		pos += int(OP_lengths[op]) + extra
		fmt.Fprintf(f, "\n")
	}
}
