package pcre2testgo

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/go-regexp/pcre2/internal/pcre2testgo/mods"
)

// copyBufUnits is sizeof(copybuffer)/code_unit_size in pcre2test.c:
// uint32_t copybuffer[256] holds 1024 8-bit code units.
const copyBufUnits = 1024

// Match option bits used by the global loop.
const (
	optNotEmptyAtStart = mods.NOTEMPTY_ATSTART
	optAnchored        = mods.ANCHORED
)

// processData ports process_data() for the native interface of an 8-bit,
// non-JIT build.
func (r *Runner) processData(line []byte) int {
	pat := &r.patCtl
	subjectLiteral := pat.Control2&mods.CTL2_SUBJECT_LITERAL != 0

	dat := r.defDat
	dat.CopyNames = append([]string(nil), r.defDat.CopyNames...)
	dat.GetNames = append([]string(nil), r.defDat.GetNames...)
	mc := r.defMC
	dat.Control |= pat.Control & mods.CTL_ALLPD
	dat.Control2 |= pat.Control2 & mods.CTL2_ALLPD
	dat.Replacement = pat.Replacement
	if dat.Jitstack == 0 {
		dat.Jitstack = pat.Jitstack
	}
	if dat.SubstSkip == 0 {
		dat.SubstSkip = pat.SubstSkip
	}
	if dat.SubstStop == 0 {
		dat.SubstStop = pat.SubstStop
	}

	utf := r.utf

	// Trim trailing whitespace, skip leading whitespace.
	n := len(line)
	for n > 0 && isSpace(line[n-1]) {
		n--
	}
	buf := append(append([]byte(nil), line[:n]...), 0)
	p := 0
	for isSpace(buf[p]) {
		p++
	}

	if utf {
		q := p
		for q < n {
			_, k := utf82ord(buf[q:n])
			if k <= 0 {
				r.printf("** Failed: invalid UTF-8 string cannot be used as input in UTF mode\n")
				return prOK
			}
			q += k
		}
	}

	var d []byte // the subject (dbuffer)
	startRep := -1
	endOfString := false
	for !endOfString {
		c := uint32(buf[p])
		p++
		if c == 0 {
			break
		}
		i := 0

		if c == ']' && startRep >= 0 {
			if buf[p] != '{' {
				p++
				r.printf("** Expected '{' after \\[....]\n")
				return prOK
			}
			p++
			v, e := parseLong(buf, p)
			if v > 0x7fffffff || v < -0x80000000 {
				r.printf("** Repeat count too large\n")
				return prOK
			}
			p = e
			if buf[p] != '}' {
				p++
				r.printf("** Expected '}' after \\[...]{...\n")
				return prOK
			}
			p++
			cnt := int(v)
			cnt--
			if cnt < 0 {
				r.printf("** Zero or negative repeat not allowed\n")
				return prOK
			}
			rep := append([]byte(nil), d[startRep:]...)
			if len(rep) > 0 && cnt > (1<<30)/len(rep) {
				r.printf("** Expanded content too large\n")
				return prOK
			}
			for ; cnt > 0; cnt-- {
				d = append(d, rep...)
			}
			startRep = -1
			continue
		}

		if c != '\\' || subjectLiteral {
			if utf && c >= 0xc0 {
				// GETUTF8INC: decode the multibyte character.
				v, k := utf82ord(buf[p-1 : n])
				if k > 0 {
					c = v
					p += k - 1
				}
			}
		} else {
			c = uint32(buf[p])
			p++
			switch c {
			case '\\':
			case 'a':
				c = 7
			case 'b':
				c = '\b'
			case 'e':
				c = 0x1b
			case 'f':
				c = '\f'
			case 'n':
				c = '\n'
			case 'r':
				c = '\r'
			case 't':
				c = '\t'
			case 'v':
				c = '\v'
			case '0', '1', '2', '3', '4', '5', '6', '7':
				c -= '0'
				for i < 2 && isDigit(buf[p]) && buf[p] != '8' && buf[p] != '9' {
					i++
					c = c*8 + uint32(buf[p]) - '0'
					p++
				}
			case 'o':
				if buf[p] == '{' {
					pt := p
					c = 0
					for pt++; isDigit(buf[pt]) && buf[pt] != '8' && buf[pt] != '9'; pt++ {
						i++
						if i == 12 {
							r.printf("** Too many octal digits in \\o{...} item; using only the first twelve.\n")
						} else {
							c = c*8 + uint32(buf[pt]) - '0'
						}
					}
					if buf[pt] == '}' {
						p = pt + 1
					} else {
						r.printf("** Missing } after \\o{ (assumed)\n")
					}
				}
			case 'x':
				done := false
				if buf[p] == '{' {
					pt := p
					c = 0
					for pt++; isXDigit(buf[pt]); pt++ {
						i++
						if i == 9 {
							r.printf("** Too many hex digits in \\x{...} item; using only the first eight.\n")
						} else {
							c = c*16 + uint32(hexVal(buf[pt]))
						}
					}
					if buf[pt] == '}' {
						p = pt + 1
						done = true
					}
				}
				if !done {
					c = 0
					for {
						ii := i
						i++
						if !(ii < 2 && isXDigit(buf[p])) {
							break
						}
						c = c*16 + uint32(hexVal(buf[p]))
						p++
					}
					if utf {
						d = append(d, byte(c))
						continue
					}
				}
			case 0:
				p--
				continue
			case '=':
				endOfString = true
			case '[':
				if startRep >= 0 {
					r.printf("** Nested replication is not supported\n")
					return prOK
				}
				startRep = len(d)
				continue
			default:
				if isAlnum(byte(c)) {
					r.printf("** Unrecognized escape sequence \"\\%c\"\n", c)
					return prOK
				}
			}
			if endOfString {
				break
			}
		}

		if utf {
			if c > 0x7fffffff {
				r.printf("** Character \\x{%x} is greater than 0x7fffffff and so cannot be converted to UTF-8\n", c)
				return prOK
			}
			d = append(d, ord2utf8(c)...)
		} else {
			if c > 0xff {
				r.printf("** Character \\x{%x} is greater than 255 and UTF-8 mode is not enabled.\n", c)
				r.printf("** Truncation will probably give the wrong result.\n")
			}
			d = append(d, byte(c))
		}
	}

	ulen := uint64(len(d))

	// Modifiers after "\=".
	if endOfString {
		st := r.newState(mods.CtxDat)
		st.Dat, st.MC = &dat, &mc
		if !st.Decode(buf[p:], mods.CtxDat) {
			return prOK
		}
	}

	if dat.SubstSkip != 0 || dat.SubstStop != 0 {
		dat.Control2 |= mods.CTL2_SUBSTITUTE_CALLOUT
	}
	for _, ex := range []uint32{
		mods.CTL_ALLUSEDTEXT | mods.CTL_STARTCHAR,
		mods.CTL_FINDLIMITS | mods.CTL_NULLCONTEXT,
		mods.CTL_FINDLIMITS_NOHEAP | mods.CTL_NULLCONTEXT,
	} {
		c := dat.Control & ex
		if c != 0 && c != (c&(^c+1)) {
			r.showControls(c, 0, "** Not allowed together:")
			r.printf("\n")
			return prOK
		}
	}
	if pat.Replacement != "" {
		if dat.Control2&mods.CTL2_SUBSTITUTE_CALLOUT != 0 && dat.Control&mods.CTL_NULLCONTEXT != 0 {
			r.printf("** Replacement callouts are not supported with null_context.\n")
			return prOK
		}
		if dat.Control&mods.CTL_ALLCAPTURES != 0 {
			r.printf("** Ignored with replacement text: allcaptures\n")
		}
	}
	if dat.Control&mods.CTL_DFA != 0 {
		if dat.Control&mods.CTL_ALLCAPTURES != 0 {
			r.printf("** Ignored for DFA matching: allcaptures\n")
		}
		if dat.Control2&mods.CTL2_HEAPFRAMES_SIZE != 0 {
			r.printf("** Ignored for DFA matching: heapframes_size\n")
		}
	}

	if dat.Startend[0] != mods.CforeUnset {
		r.printf("** \\=posix_startend ignored for non-POSIX matching\n")
	}

	// ALLUSEDTEXT is not supported with JIT; there is no JIT here.

	show := dat.Control&mods.CTL_MEMORY != 0
	if show {
		r.unsup("memory tracing (memory)")
	}

	if dat.Replacement != "" && dat.Control&mods.CTL_DFA != 0 {
		r.printf("** Ignored for DFA matching: replace\n")
		dat.Replacement = ""
	}
	if dat.Replacement != "" {
		r.unsup("substitution (replace)")
		return prOK
	}
	if dat.Control&mods.CTL_DFA != 0 {
		r.unsup("DFA matching (dfa)")
		return prOK
	}
	if dat.Control&(mods.CTL_FINDLIMITS|mods.CTL_FINDLIMITS_NOHEAP) != 0 {
		r.unsup("limit finding (find_limits)")
		return prOK
	}
	if dat.Control&mods.CTL_CALLOUT_NONE == 0 && r.hasCallout {
		r.unsup("callouts")
	}
	if dat.Control2&mods.CTL2_HEAPFRAMES_SIZE != 0 {
		r.unsup("heap frames size")
	}

	var subject []byte
	if dat.Control2&mods.CTL2_NULL_SUBJECT == 0 {
		subject = d
		if subject == nil {
			subject = []byte{}
		}
	}

	// Match data.
	md := r.code.NewMatchData(dat.Oveccount)
	if md == nil {
		r.printf("** Failed to get memory for recording matching information (size requested: %d)\n", dat.Oveccount)
		return prOK
	}
	ovector := md.Ovector()
	oveccount := md.OvectorCount()

	ms := MatchSettings{MatchCtx: mc, Null: dat.Control&mods.CTL_NULLCONTEXT != 0}

	var gnotempty uint32
	ovecsave := [3]uint64{unsetSize, unsetSize, unsetSize}
	subj := subject
	curLen := ulen
	for gmatched := 0; ; gmatched++ {
		ovector = md.Ovector()
		for j := range ovector {
			ovector[j] = junkOffset
		}
		capcount := r.code.Match(subj, uint64(dat.Offset), dat.Options|gnotempty, md, ms)
		if capcount == 0 {
			r.printf("Matched, but too many substrings\n")
			capcount = int(dat.Oveccount)
		}
		ovector = md.Ovector()

		switch {
		case capcount >= 0:
			if capcount > int(oveccount) {
				r.printf("** PCRE2 error: returned count %d is too big for ovector count %d\n", capcount, oveccount)
				capcount = int(oveccount)
				if dat.Control&mods.CTL_ANYGLOB != 0 {
					r.printf("** Global loop abandoned\n")
					dat.Control &^= mods.CTL_ANYGLOB
				}
			}
			if gmatched > 0 && ovecsave[0] == ovector[0] && ovecsave[1] == ovector[1] {
				if ovector[0] == ovector[1] && ovecsave[2] != uint64(dat.Offset) {
					gnotempty = optNotEmptyAtStart | optAnchored
					ovecsave[2] = uint64(dat.Offset)
					continue
				}
				r.printf("** PCRE2 error: global repeat returned the same string as previous\n")
				r.printf("** Global loop abandoned\n")
				dat.Control &^= mods.CTL_ANYGLOB
			}
			if dat.Control&(mods.CTL_ALLCAPTURES|mods.CTL_DFA) == mods.CTL_ALLCAPTURES {
				capcount = int(r.maxCapCount) + 1
				if capcount > int(oveccount) {
					capcount = int(oveccount)
				}
			}
			if dat.Control2&mods.CTL2_ALLVECTOR != 0 {
				capcount = int(oveccount)
			}
			for i := 0; i < 2*capcount; i += 2 {
				start := ovector[i]
				end := ovector[i+1]
				if start > end {
					start, end = end, start
					r.printf("Start of matched string is beyond its end - displaying from end to start.\n")
				}
				r.printf("%2d: ", i/2)
				if start == unsetSize && end == unsetSize {
					r.printf("<unset>\n")
					continue
				}
				if start > ulen || end > ulen {
					if i >= int(2*r.maxCapCount+2) && start == junkOffset && end == junkOffset {
						r.printf("<unchanged>\n")
					} else {
						r.printf("ERROR: bad value(s) for offset(s): 0x%x 0x%x\n", start, end)
					}
					continue
				}
				if i == 0 {
					showAllUsed := false
					var leftchar, rightchar uint64
					if dat.Control&mods.CTL_ALLUSEDTEXT != 0 {
						var ok bool
						leftchar, rightchar, ok = md.UsedChars()
						if !ok {
							r.unsup("allusedtext")
							leftchar, rightchar = start, end
						}
						showAllUsed = leftchar < start || rightchar > end
					}
					switch {
					case showAllUsed:
						lleft := pchars(subj[leftchar:start], utf, r.out)
						lmiddle := pchars(subj[start:end], utf, r.out)
						lright := pchars(subj[end:rightchar], utf, r.out)
						r.printf("\n    ")
						r.out.WriteString(strings.Repeat("<", lleft))
						r.out.WriteString(strings.Repeat(" ", lmiddle))
						r.out.WriteString(strings.Repeat(">", lright))
					case dat.Control&mods.CTL_STARTCHAR != 0:
						startchar := md.StartChar()
						lleft := pchars(subj[startchar:start], utf, r.out)
						pchars(subj[start:end], utf, r.out)
						if startchar != start {
							r.printf("\n    ")
							r.out.WriteString(strings.Repeat("^", lleft))
						}
					default:
						pchars(subj[start:end], utf, r.out)
					}
				} else {
					pchars(subj[start:end], utf, r.out)
				}
				r.printf("\n")
				if dat.Control&mods.CTL_ALLAFTERTEXT != 0 || (i == 0 && dat.Control&mods.CTL_AFTERTEXT != 0) {
					r.printf("%2d+ ", i/2)
					pchars(subj[ovector[i+1]:], utf, r.out)
					r.printf("\n")
				}
			}
			if dat.Control&mods.CTL_MARK != 0 {
				if mk := md.Mark(); mk != nil {
					r.printf("MK: ")
					pchars(mk, utf, r.out)
					r.printf("\n")
				}
			}
			if !r.copyAndGet(md, &dat, utf, capcount) {
				return prAbend
			}

		case capcount == errPartial:
			leftchar := ovector[0]
			if dat.Control&mods.CTL_ALLUSEDTEXT != 0 {
				l, _, ok := md.UsedChars()
				if !ok {
					r.unsup("allusedtext")
				} else {
					leftchar = l
				}
			}
			r.printf("Partial match")
			rubric := 0
			if dat.Control&mods.CTL_MARK != 0 {
				if mk := md.Mark(); mk != nil {
					r.printf(", mark=")
					rubric = pchars(mk, utf, r.out) + 7
				}
			}
			r.printf(": ")
			rubric += 15
			back := pchars(subj[leftchar:ovector[0]], utf, r.out)
			pchars(subj[ovector[0]:ovector[1]], utf, r.out)
			r.printf("\n")
			if back != 0 {
				r.out.WriteString(strings.Repeat(" ", rubric))
				r.out.WriteString(strings.Repeat("<", back))
				r.printf("\n")
			}
			if ulen != ovector[1] {
				r.printf("** ovector[1] is not equal to the subject length: %d != %d\n", ovector[1], ulen)
			}
			if !r.copyAndGet(md, &dat, utf, 1) {
				return prAbend
			}
			if dat.Control2&mods.CTL2_ALLVECTOR != 0 {
				r.showOvector(ovector, oveccount)
			}
			return prOK

		case gnotempty != 0:
			start := uint64(dat.Offset)
			end := start + 1
			nl, _ := r.code.Info(infoNewline)
			if (nl == mods.NEWLINE_CRLF || nl == mods.NEWLINE_ANY || nl == mods.NEWLINE_ANYCRLF) &&
				start+1 < ulen && subj[start] == '\r' && subj[end] == '\n' {
				end++
			} else if utf {
				for ; end < ulen; end++ {
					if subj[end]&0xc0 != 0x80 {
						break
					}
				}
			}
			ovector[0] = start
			ovector[1] = end

		default:
			switch capcount {
			case errNoMatch:
				if gmatched == 0 {
					r.printf("No match")
					if dat.Control&mods.CTL_MARK != 0 {
						if mk := md.Mark(); mk != nil {
							r.printf(", mark = ")
							pchars(mk, utf, r.out)
						}
					}
					r.printf("\n")
					if dat.Control2&mods.CTL2_ALLVECTOR != 0 {
						r.showOvector(ovector, oveccount)
					}
				}
			case errBadUTFOffset:
				r.printf("Error %d (bad UTF-%d offset)\n", capcount, 8)
			default:
				r.printf("Failed: error %d: ", capcount)
				if !r.printError(capcount, "", "") {
					return prAbend
				}
				if capcount <= errUTF8Err1 && capcount >= errUTF32Err2 {
					r.printf(" at offset %d", md.StartChar())
				}
				r.printf("\n")
			}
			return prOK
		}

		if dat.Control&mods.CTL_ANYGLOB == 0 {
			break
		}
		matchOffset := md.Ovector()[0]
		endOffset := md.Ovector()[1]
		if matchOffset == endOffset {
			if endOffset == curLen {
				break
			}
			if matchOffset <= uint64(dat.Offset) {
				gnotempty = optNotEmptyAtStart | optAnchored
			}
		} else {
			gnotempty = 0
			if dat.Control&mods.CTL_GLOBAL != 0 {
				startchar := md.StartChar()
				if endOffset <= startchar {
					if startchar >= curLen {
						break
					}
					endOffset = startchar + 1
					if utf {
						for ; endOffset < curLen; endOffset++ {
							if subj[endOffset]&0xc0 != 0x80 {
								break
							}
						}
					}
				}
			}
		}
		if dat.Control&mods.CTL_GLOBAL != 0 {
			o := md.Ovector()
			ovecsave[0] = o[0]
			ovecsave[1] = o[1]
			ovecsave[2] = uint64(dat.Offset)
			dat.Offset = uint32(endOffset)
		} else {
			subj = subj[endOffset:]
			curLen -= endOffset
			ulen = curLen
		}
	}
	return prOK
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlnum(c byte) bool {
	return isDigit(c) || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// parseLong is strtol(p, &end, 10) without the whitespace skipping.
func parseLong(b []byte, i int) (int64, int) {
	neg := false
	if at(b, i) == '-' {
		neg = true
		i++
	} else if at(b, i) == '+' {
		i++
	}
	v, e := atoi(b, i)
	if v > 1<<62 {
		v = 1 << 62
	}
	if neg {
		return -int64(v), e
	}
	return int64(v), e
}

func (r *Runner) showOvector(ovector []uint64, count uint32) {
	for i := uint32(0); i < 2*count; i += 2 {
		start, end := ovector[i], ovector[i+1]
		r.printf("%2d: ", i/2)
		switch {
		case start == unsetSize && end == unsetSize:
			r.printf("<unset>\n")
		case start == junkOffset && end == junkOffset:
			r.printf("<unchanged>\n")
		default:
			r.printf("%d %d\n", start, end)
		}
	}
}

// copyAndGet ports copy_and_get().
func (r *Runner) copyAndGet(md MatchData, dat *mods.DatCtl, utf bool, capcount int) bool {
	out := r.out
	for i := 0; i < mods.MaxCpyGet && dat.CopyNumbers[i] >= 0; i++ {
		n := uint32(dat.CopyNumbers[i])
		buf, rc := md.CopyByNumber(n, copyBufUnits)
		if rc == Unsupported {
			r.unsup("substring copy")
			continue
		}
		if rc < 0 {
			r.printf("Copy substring %d failed (%d): ", n, rc)
			if !r.printError(rc, "", "\n") {
				return false
			}
			continue
		}
		length := uint64(len(buf))
		length2, rc2 := md.LengthByNumber(n)
		if rc2 < 0 {
			r.printf("Get substring %d length failed (%d): ", n, rc2)
			if !r.printError(rc2, "", "\n") {
				return false
			}
		} else if length2 != length {
			r.printf("Mismatched substring lengths: %d %d\n", length, length2)
		}
		r.printf("%2dC ", n)
		pchars(buf, utf, out)
		r.printf(" (%d)\n", length)
	}

	for _, name := range dat.CopyNames {
		groupnumber := r.code.NumberFromName(name)
		if groupnumber < 0 && groupnumber != errNoUniqueSubstr {
			r.printf("Number not found for group '%s'\n", name)
		}
		buf, rc := md.CopyByName(name, copyBufUnits)
		if rc == Unsupported {
			r.unsup("substring copy by name")
			continue
		}
		if rc < 0 {
			r.printf("Copy substring '%s' failed (%d): ", name, rc)
			if !r.printError(rc, "", "\n") {
				return false
			}
			continue
		}
		length := uint64(len(buf))
		length2, rc2 := md.LengthByName(name)
		if rc2 < 0 {
			r.printf("Get substring '%s' length failed (%d): ", name, rc2)
			if !r.printError(rc2, "", "\n") {
				return false
			}
		} else if length2 != length {
			r.printf("Mismatched substring lengths: %d %d\n", length, length2)
		}
		r.printf("  C ")
		pchars(buf, utf, out)
		r.printf(" (%d) %s", length, name)
		if groupnumber >= 0 {
			r.printf(" (group %d)\n", groupnumber)
		} else {
			r.printf(" (non-unique)\n")
		}
	}

	for i := 0; i < mods.MaxCpyGet && dat.GetNumbers[i] >= 0; i++ {
		n := uint32(dat.GetNumbers[i])
		buf, rc := md.GetByNumber(n)
		if rc == Unsupported {
			r.unsup("substring get")
			continue
		}
		if rc < 0 {
			r.printf("Get substring %d failed (%d): ", n, rc)
			if !r.printError(rc, "", "\n") {
				return false
			}
			continue
		}
		r.printf("%2dG ", n)
		pchars(buf, utf, out)
		r.printf(" (%d)\n", len(buf))
	}

	for _, name := range dat.GetNames {
		groupnumber := r.code.NumberFromName(name)
		if groupnumber < 0 && groupnumber != errNoUniqueSubstr {
			r.printf("Number not found for group '%s'\n", name)
		}
		buf, rc := md.GetByName(name)
		if rc == Unsupported {
			r.unsup("substring get by name")
			continue
		}
		if rc < 0 {
			r.printf("Get substring '%s' failed (%d): ", name, rc)
			if !r.printError(rc, "", "\n") {
				return false
			}
			continue
		}
		r.printf("  G ")
		pchars(buf, utf, out)
		r.printf(" (%d) %s", len(buf), name)
		if groupnumber >= 0 {
			r.printf(" (group %d)\n", groupnumber)
		} else {
			r.printf(" (non-unique)\n")
		}
	}

	if dat.Control&mods.CTL_GETALL != 0 {
		list, rc := md.ListGet()
		if rc == Unsupported {
			r.unsup("substring list")
		} else if rc < 0 {
			r.printf("get substring list failed (%d): ", rc)
			if !r.printError(rc, "", "\n") {
				return false
			}
		} else {
			for i := 0; i < capcount && i < len(list); i++ {
				r.printf("%2dL ", i)
				pchars(list[i], utf, out)
				r.printf("\n")
			}
		}
	}
	return true
}

// ErrorMessages ports the "-error" command line option of pcre2test: it
// prints one line per comma-separated error number.
func ErrorMessages(lib Lib, list string) (string, error) {
	var b bytes.Buffer
	for _, f := range strings.Split(list, ",") {
		var code int
		if _, err := fmt.Sscanf(f, "%d", &code); err != nil {
			return b.String(), fmt.Errorf("'%s' is not a valid error number list", list)
		}
		fmt.Fprintf(&b, "Error %d: ", code)
		msg, ok := lib.ErrorMessage(code)
		if !ok {
			b.WriteString("PCRE2_ERROR_BADDATA (unknown error number)")
		} else {
			b.WriteString(msg)
		}
		b.WriteString("\n")
	}
	return b.String(), nil
}
