package pcre2

// Small helpers of match() that stand for macros and repeated fragments of
// pcre2_match.c.

// checkPartial is CHECK_PARTIAL() (pcre2_match.c:531): true when a hard
// partial match must be returned.
func (mb *matchBlock) checkPartial(eptr int) bool {
	return eptr >= mb.endSubject && mb.scheck(eptr)
}

// wideChar is the test used by the repeated multi-code-unit character code
// (pcre2_match.c:1298): match the character at tempSptr[1] (length F.length) or
// its other case (F.occu, length F.tempSize) at F.eptr, advancing F.eptr.
func (mb *matchBlock) wideChar(F *heapframe) bool {
	subj := mb.subject
	if F.eptr <= mb.endSubject-F.length {
		cp := mb.startCode[F.tempSptr[1] : F.tempSptr[1]+F.length]
		s := subj[F.eptr : F.eptr+F.length]
		eq := true
		for k := range cp {
			if cp[k] != s[k] {
				eq = false
				break
			}
		}
		if eq {
			F.eptr += F.length
			return true
		}
	}
	if F.tempSize > 0 && F.eptr <= mb.endSubject-F.tempSize {
		s := subj[F.eptr : F.eptr+F.tempSize]
		eq := true
		for k := range s {
			if F.occu[k] != s[k] {
				eq = false
				break
			}
		}
		if eq {
			F.eptr += F.tempSize
			return true
		}
	}
	return false
}

// classHas tests a character against the bit map of OP_CLASS/OP_NCLASS at code
// offset mapAddr (pcre2_match.c:2041).
func (mb *matchBlock) classHas(mapAddr int, op uint8, fc uint32) bool {
	if fc > 255 {
		return op != OP_CLASS
	}
	return mb.startCode[mapAddr+int(fc/8)]&(1<<(fc&7)) != 0
}

// simpleType is the test of the non-UCP type opcodes OP_DIGIT ...
// OP_NOT_VSPACE (pcre2_match.c:2305); limit is 256 (CHMAX_255).
func (mb *matchBlock) simpleType(op int, fc uint32, limit uint32) bool {
	switch op {
	case OP_NOT_DIGIT:
		return !(fc < limit && mb.ctypes[fc]&ctype_digit != 0)
	case OP_DIGIT:
		return fc < limit && mb.ctypes[fc]&ctype_digit != 0
	case OP_NOT_WHITESPACE:
		return !(fc < limit && mb.ctypes[fc]&ctype_space != 0)
	case OP_WHITESPACE:
		return fc < limit && mb.ctypes[fc]&ctype_space != 0
	case OP_NOT_WORDCHAR:
		return !(fc < limit && mb.ctypes[fc]&ctype_word != 0)
	case OP_WORDCHAR:
		return fc < limit && mb.ctypes[fc]&ctype_word != 0
	case OP_NOT_HSPACE:
		return !isHspace(fc)
	case OP_HSPACE:
		return isHspace(fc)
	case OP_NOT_VSPACE:
		return !isVspace(fc)
	case OP_VSPACE:
		return isVspace(fc)
	}
	return false
}

// Results of typeStep.
const (
	stepOK = iota
	stepNoMatch
	stepPartial  // hard partial match: return PCRE2_ERROR_PARTIAL
	stepInternal // PCRE2_ERROR_INTERNAL
)

// typeStep matches one character of the repeated type of frame F (Lctype =
// temp32[2], proptype = tempSize, Lpropvalue = temp32[3]) at F.eptr, advancing
// F.eptr: the body of the "ensure the minimum" loops and of the minimizing
// loop (pcre2_match.c:2733-3500, 3519-4100). limit is the CHMAX_255 bound for
// the simple type tests.
func (mb *matchBlock) typeStep(F *heapframe, utf bool, limit uint32) int {
	subj := mb.subject
	if F.eptr >= mb.endSubject {
		if mb.scheck(F.eptr) {
			return stepPartial
		}
		return stepNoMatch
	}
	ctype := int(F.temp32[2])
	if F.tempSize >= 0 { // property test
		var fc uint32
		fc, F.eptr = GETCHARINCTEST(utf, subj, F.eptr)
		res, ok := propTest(F.tempSize, fc, F.temp32[3])
		if !ok {
			return stepInternal
		}
		if res == (ctype == OP_NOTPROP) {
			return stepNoMatch
		}
		return stepOK
	}
	if ctype == OP_EXTUNI {
		var fc uint32
		fc, F.eptr = GETCHARINCTEST(utf, subj, F.eptr)
		F.eptr = extuni(fc, subj, F.eptr, 0, mb.endSubject, utf, nil)
		if mb.checkPartial(F.eptr) {
			return stepPartial
		}
		return stepOK
	}
	if ctype == OP_ANY && mb.isNewline(F.eptr) {
		return stepNoMatch
	}
	var fc uint32
	fc, F.eptr = GETCHARINCTEST(utf, subj, F.eptr)
	switch ctype {
	case OP_ANY: // This is the non-NL case; take care with CRLF partial
		if mb.partial != 0 && F.eptr >= mb.endSubject && mb.nltype == NLTYPE_FIXED &&
			mb.nllen == 2 && fc == uint32(mb.nl[0]) {
			mb.hitend = true
			if mb.partial > 1 {
				return stepPartial
			}
		}
	case OP_ALLANY, OP_ANYBYTE:
	case OP_ANYNL:
		switch fc {
		case CHAR_CR:
			if F.eptr < mb.endSubject && subj[F.eptr] == CHAR_LF {
				F.eptr++
			}
		case CHAR_LF:
		case CHAR_VT, CHAR_FF, CHAR_NEL, 0x2028, 0x2029:
			if mb.bsrConvention == PCRE2_BSR_ANYCRLF {
				return stepNoMatch
			}
		default:
			return stepNoMatch
		}
	case OP_NOT_HSPACE, OP_HSPACE, OP_NOT_VSPACE, OP_VSPACE, OP_NOT_DIGIT, OP_DIGIT,
		OP_NOT_WHITESPACE, OP_WHITESPACE, OP_NOT_WORDCHAR, OP_WORDCHAR:
		if !mb.simpleType(ctype, fc, limit) {
			return stepNoMatch
		}
	default:
		return stepInternal
	}
	return stepOK
}

// typeMaxStep is one iteration of the maximizing scans (pcre2_match.c:4121-4970):
// it advances F.eptr over one repeated item and reports adv=true, or leaves it
// (except for the \R and EXTUNI quirks) and reports adv=false. partial is true
// when a hard partial match must be returned; bad when the type is unknown.
func (mb *matchBlock) typeMaxStep(F *heapframe, utf bool) (adv, partial, bad bool) {
	subj := mb.subject
	if F.eptr >= mb.endSubject {
		if mb.scheck(F.eptr) {
			return false, true, false
		}
		return false, false, false
	}
	ctype := int(F.temp32[2])
	if F.tempSize >= 0 {
		fc, ex := GETCHARLENTEST(utf, subj, F.eptr)
		res, ok := propTest(F.tempSize, fc, F.temp32[3])
		if !ok {
			return false, false, true
		}
		if res == (ctype == OP_NOTPROP) {
			return false, false, false
		}
		F.eptr += 1 + ex
		return true, false, false
	}
	if ctype == OP_EXTUNI {
		var fc uint32
		fc, F.eptr = GETCHARINCTEST(utf, subj, F.eptr)
		F.eptr = extuni(fc, subj, F.eptr, 0, mb.endSubject, utf, nil)
		if mb.checkPartial(F.eptr) {
			return false, true, false
		}
		return true, false, false
	}
	switch ctype {
	case OP_ANY:
		if mb.isNewline(F.eptr) {
			return false, false, false
		}
		if mb.partial != 0 && F.eptr+1 >= mb.endSubject && mb.nltype == NLTYPE_FIXED &&
			mb.nllen == 2 && subj[F.eptr] == mb.nl[0] {
			mb.hitend = true
			if mb.partial > 1 {
				return false, true, false
			}
		}
		F.eptr++
		if utf {
			F.eptr = acrossChar(subj, F.eptr, mb.endSubject)
		}
		return true, false, false
	case OP_ALLANY: // limited UTF repeat (the unlimited and non-UTF cases are bulk)
		F.eptr++
		F.eptr = acrossChar(subj, F.eptr, mb.endSubject)
		return true, false, false
	case OP_ANYNL:
		fc, ex := GETCHARLENTEST(utf, subj, F.eptr)
		if fc == CHAR_CR {
			F.eptr++
			if F.eptr >= mb.endSubject {
				return false, false, false
			}
			if subj[F.eptr] == CHAR_LF {
				F.eptr++
			}
			return true, false, false
		}
		if fc != CHAR_LF && (mb.bsrConvention == PCRE2_BSR_ANYCRLF ||
			(fc != CHAR_VT && fc != CHAR_FF && fc != CHAR_NEL && fc != 0x2028 && fc != 0x2029)) {
			return false, false, false
		}
		F.eptr += 1 + ex
		return true, false, false
	case OP_NOT_HSPACE, OP_HSPACE, OP_NOT_VSPACE, OP_VSPACE, OP_NOT_DIGIT, OP_DIGIT,
		OP_NOT_WHITESPACE, OP_WHITESPACE, OP_NOT_WORDCHAR, OP_WORDCHAR:
		fc, ex := GETCHARLENTEST(utf, subj, F.eptr)
		if !mb.simpleType(ctype, fc, 256) {
			return false, false, false
		}
		F.eptr += 1 + ex
		return true, false, false
	}
	return false, false, true
}

func b2u32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

// ucpIsWord is the PCRE2_UCP word test of the \b code (pcre2_match.c:6285).
func ucpIsWord(fc uint32) bool {
	ct := UCD_CHARTYPE(fc)
	cat := ucp_gentype[ct]
	return cat == ucp_L || cat == ucp_N || uint32(ct) == ucp_Mn || uint32(ct) == ucp_Pc
}

// cstrEqual is PRIV(strcmp) == 0 on two zero-terminated strings in code
// (pcre2_util: used for (*MARK) names).
func cstrEqual(code []byte, a, b int) bool {
	for {
		if code[a] != code[b] {
			return false
		}
		if code[a] == 0 {
			return true
		}
		a++
		b++
	}
}
