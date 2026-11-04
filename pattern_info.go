// Port of pcre2_pattern_info.c: pcre2_pattern_info() and
// pcre2_callout_enumerate().
package pcre2

// heapframeOvectorOffset is offsetof(heapframe, ovector) of pcre2_intmodedep.h
// on a 64-bit target with 8-bit code units (see the struct at :790); it is used
// only for PCRE2_INFO_FRAMESIZE.
const heapframeOvectorOffset = 136

// PatternInfoSize is pcre2_pattern_info(code, what, NULL): the size in bytes C
// would write for item what (4, 8 or pointer size), or 0 when what is not a
// known item (C then falls through to the other checks; for NULL where and an
// unknown item it ends in PCRE2_ERROR_BADOPTION, returned here as negative).
func PatternInfoSize(code *Code, what uint32) int {
	switch what {
	case PCRE2_INFO_ALLOPTIONS, PCRE2_INFO_ARGOPTIONS, PCRE2_INFO_BACKREFMAX,
		PCRE2_INFO_BSR, PCRE2_INFO_CAPTURECOUNT, PCRE2_INFO_DEPTHLIMIT,
		PCRE2_INFO_EXTRAOPTIONS, PCRE2_INFO_FIRSTCODETYPE, PCRE2_INFO_FIRSTCODEUNIT,
		PCRE2_INFO_HASBACKSLASHC, PCRE2_INFO_HASCRORLF, PCRE2_INFO_HEAPLIMIT,
		PCRE2_INFO_JCHANGED, PCRE2_INFO_LASTCODETYPE, PCRE2_INFO_LASTCODEUNIT,
		PCRE2_INFO_MATCHEMPTY, PCRE2_INFO_MATCHLIMIT, PCRE2_INFO_MAXLOOKBEHIND,
		PCRE2_INFO_MINLENGTH, PCRE2_INFO_NAMEENTRYSIZE, PCRE2_INFO_NAMECOUNT,
		PCRE2_INFO_NEWLINE:
		return 4
	case PCRE2_INFO_FIRSTBITMAP, PCRE2_INFO_JITSIZE, PCRE2_INFO_SIZE,
		PCRE2_INFO_FRAMESIZE, PCRE2_INFO_NAMETABLE:
		return 8
	}
	return PCRE2_ERROR_BADOPTION
}

// checkCode applies the checks pcre2_pattern_info() makes before the switch.
func (re *Code) check() int {
	if re == nil {
		return PCRE2_ERROR_NULL
	}
	// Check that the first field in the block is the magic number.
	if re.magicNumber != xMAGIC_NUMBER {
		return PCRE2_ERROR_BADMAGIC
	}
	// Check that this pattern was compiled in the correct bit mode (8).
	if re.flags&(8/8) == 0 {
		return PCRE2_ERROR_BADMODE
	}
	return 0
}

// PatternInfo is pcre2_pattern_info() for the scalar items: it returns the
// value and the C return code (0, PCRE2_ERROR_UNSET for an unset limit - the
// value is still returned, as C stores it first - or a negative error with
// value 0). Items that C returns through a pointer are handled as follows:
// PCRE2_INFO_FIRSTBITMAP gives 1 if a first-unit bitmap exists (read it with
// FirstBitmap), PCRE2_INFO_NAMETABLE gives the table length in bytes (read it
// with NameTable).
func (re *Code) PatternInfo(what uint32) (uint64, int) {
	if rc := re.check(); rc != 0 {
		return 0, rc
	}
	switch what {
	case PCRE2_INFO_ALLOPTIONS:
		return uint64(re.overallOptions), 0
	case PCRE2_INFO_ARGOPTIONS:
		return uint64(re.compileOptions), 0
	case PCRE2_INFO_BACKREFMAX:
		return uint64(re.topBackref), 0
	case PCRE2_INFO_BSR:
		return uint64(re.bsrConvention), 0
	case PCRE2_INFO_CAPTURECOUNT:
		return uint64(re.topBracket), 0
	case PCRE2_INFO_DEPTHLIMIT:
		if re.limitDepth == 0xffffffff {
			return uint64(re.limitDepth), PCRE2_ERROR_UNSET
		}
		return uint64(re.limitDepth), 0
	case PCRE2_INFO_EXTRAOPTIONS:
		return uint64(re.extraOptions), 0
	case PCRE2_INFO_FIRSTCODETYPE:
		switch {
		case re.flags&PCRE2_FIRSTSET != 0:
			return 1, 0
		case re.flags&PCRE2_STARTLINE != 0:
			return 2, 0
		}
		return 0, 0
	case PCRE2_INFO_FIRSTCODEUNIT:
		if re.flags&PCRE2_FIRSTSET != 0 {
			return uint64(re.firstCodeunit), 0
		}
		return 0, 0
	case PCRE2_INFO_FIRSTBITMAP:
		if re.flags&PCRE2_FIRSTMAPSET != 0 {
			return 1, 0
		}
		return 0, 0
	case PCRE2_INFO_FRAMESIZE:
		return heapframeOvectorOffset + uint64(re.topBracket)*2*8, 0
	case PCRE2_INFO_HASBACKSLASHC:
		return b2u(re.flags&PCRE2_HASBKC != 0), 0
	case PCRE2_INFO_HASCRORLF:
		return b2u(re.flags&PCRE2_HASCRORLF != 0), 0
	case PCRE2_INFO_HEAPLIMIT:
		if re.limitHeap == 0xffffffff {
			return uint64(re.limitHeap), PCRE2_ERROR_UNSET
		}
		return uint64(re.limitHeap), 0
	case PCRE2_INFO_JCHANGED:
		return b2u(re.flags&PCRE2_JCHANGED != 0), 0
	case PCRE2_INFO_JITSIZE:
		return 0, 0 // no JIT in this build
	case PCRE2_INFO_LASTCODETYPE:
		return b2u(re.flags&PCRE2_LASTSET != 0), 0
	case PCRE2_INFO_LASTCODEUNIT:
		if re.flags&PCRE2_LASTSET != 0 {
			return uint64(re.lastCodeunit), 0
		}
		return 0, 0
	case PCRE2_INFO_MATCHEMPTY:
		return b2u(re.flags&PCRE2_MATCH_EMPTY != 0), 0
	case PCRE2_INFO_MATCHLIMIT:
		if re.limitMatch == 0xffffffff {
			return uint64(re.limitMatch), PCRE2_ERROR_UNSET
		}
		return uint64(re.limitMatch), 0
	case PCRE2_INFO_MAXLOOKBEHIND:
		return uint64(re.maxLookbehind), 0
	case PCRE2_INFO_MINLENGTH:
		return uint64(re.minlength), 0
	case PCRE2_INFO_NAMEENTRYSIZE:
		return uint64(re.nameEntrySize), 0
	case PCRE2_INFO_NAMECOUNT:
		return uint64(re.nameCount), 0
	case PCRE2_INFO_NAMETABLE:
		return uint64(len(re.nameTable())), 0
	case PCRE2_INFO_NEWLINE:
		return uint64(re.newlineConvention), 0
	case PCRE2_INFO_SIZE:
		return re.blocksize, 0
	}
	return 0, PCRE2_ERROR_BADOPTION
}

func b2u(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

// FirstBitmap is PCRE2_INFO_FIRSTBITMAP: the 32-byte bitmap of possible first
// code units, or nil when none was computed.
func (re *Code) FirstBitmap() []byte {
	if re.check() != 0 || re.flags&PCRE2_FIRSTMAPSET == 0 {
		return nil
	}
	return re.startBitmap[:]
}

// NameTable is PCRE2_INFO_NAMETABLE with NAMECOUNT and NAMEENTRYSIZE: the
// table (count entries of entrySize bytes: 2-byte big-endian group number, then
// the NUL-terminated name), as laid out by the C library.
func (re *Code) NameTable() (table []byte, count, entrySize uint32) {
	if re.check() != 0 {
		return nil, 0, 0
	}
	return re.nameTable(), uint32(re.nameCount), uint32(re.nameEntrySize)
}

// CalloutEnumerate is pcre2_callout_enumerate(): callback is called for every
// callout in the pattern; a non-zero result stops the scan and is returned.
// (pcre2_pattern_info.c:268)
func (re *Code) CalloutEnumerate(callback func(*CalloutEnumerateBlock, any) int, calloutData any) int {
	if rc := re.check(); rc != 0 {
		return rc
	}
	utf := re.overallOptions&PCRE2_UTF != 0
	var cb CalloutEnumerateBlock
	cb.Version = 0
	code := re.startCode()
	cc := 0
	for {
		switch code[cc] {
		case xOP_END:
			return 0

		case xOP_CHAR, xOP_CHARI, xOP_NOT, xOP_NOTI, xOP_STAR, xOP_MINSTAR, xOP_PLUS,
			xOP_MINPLUS, xOP_QUERY, xOP_MINQUERY, xOP_UPTO, xOP_MINUPTO, xOP_EXACT,
			xOP_POSSTAR, xOP_POSPLUS, xOP_POSQUERY, xOP_POSUPTO,
			xOP_STARI, xOP_MINSTARI, xOP_PLUSI, xOP_MINPLUSI, xOP_QUERYI, xOP_MINQUERYI,
			xOP_UPTOI, xOP_MINUPTOI, xOP_EXACTI, xOP_POSSTARI, xOP_POSPLUSI,
			xOP_POSQUERYI, xOP_POSUPTOI,
			xOP_NOTSTAR, xOP_NOTMINSTAR, xOP_NOTPLUS, xOP_NOTMINPLUS, xOP_NOTQUERY,
			xOP_NOTMINQUERY, xOP_NOTUPTO, xOP_NOTMINUPTO, xOP_NOTEXACT, xOP_NOTPOSSTAR,
			xOP_NOTPOSPLUS, xOP_NOTPOSQUERY, xOP_NOTPOSUPTO,
			xOP_NOTSTARI, xOP_NOTMINSTARI, xOP_NOTPLUSI, xOP_NOTMINPLUSI, xOP_NOTQUERYI,
			xOP_NOTMINQUERYI, xOP_NOTUPTOI, xOP_NOTMINUPTOI, xOP_NOTEXACTI,
			xOP_NOTPOSSTARI, xOP_NOTPOSPLUSI, xOP_NOTPOSQUERYI, xOP_NOTPOSUPTOI:
			cc += int(xOP_lengths[code[cc]])
			if utf && xHAS_EXTRALEN(uint32(code[cc-1])) {
				cc += xGET_EXTRALEN(uint32(code[cc-1]))
			}

		case xOP_TYPESTAR, xOP_TYPEMINSTAR, xOP_TYPEPLUS, xOP_TYPEMINPLUS,
			xOP_TYPEQUERY, xOP_TYPEMINQUERY, xOP_TYPEUPTO, xOP_TYPEMINUPTO,
			xOP_TYPEEXACT, xOP_TYPEPOSSTAR, xOP_TYPEPOSPLUS, xOP_TYPEPOSQUERY,
			xOP_TYPEPOSUPTO:
			cc += int(xOP_lengths[code[cc]])
			if code[cc-1] == xOP_PROP || code[cc-1] == xOP_NOTPROP {
				cc += 2
			}

		case xOP_XCLASS:
			cc += xGET(code, cc+1)

		case xOP_MARK, xOP_COMMIT_ARG, xOP_PRUNE_ARG, xOP_SKIP_ARG, xOP_THEN_ARG:
			cc += int(xOP_lengths[code[cc]]) + int(code[cc+1])

		case xOP_CALLOUT:
			cb.PatternPosition = uint64(xGET(code, cc+1))
			cb.NextItemLength = uint64(xGET(code, cc+1+xLINK_SIZE))
			cb.CalloutNumber = uint32(code[cc+1+2*xLINK_SIZE])
			cb.CalloutStringOffset = 0
			cb.CalloutStringLength = 0
			cb.CalloutString = nil
			if rc := callback(&cb, calloutData); rc != 0 {
				return rc
			}
			cc += int(xOP_lengths[code[cc]])

		case xOP_CALLOUT_STR:
			cb.PatternPosition = uint64(xGET(code, cc+1))
			cb.NextItemLength = uint64(xGET(code, cc+1+xLINK_SIZE))
			cb.CalloutNumber = 0
			cb.CalloutStringOffset = uint64(xGET(code, cc+1+3*xLINK_SIZE))
			cb.CalloutStringLength = uint64(xGET(code, cc+1+2*xLINK_SIZE) - (1 + 4*xLINK_SIZE) - 2)
			cb.CalloutString = code[cc+(1+4*xLINK_SIZE)+1:]
			cb.CalloutString = cb.CalloutString[:cb.CalloutStringLength]
			if rc := callback(&cb, calloutData); rc != 0 {
				return rc
			}
			cc += xGET(code, cc+1+2*xLINK_SIZE)

		default:
			cc += int(xOP_lengths[code[cc]])
		}
	}
}

// Free is pcre2_code_free(); the garbage collector owns the memory.
func (re *Code) Free() {
	if re != nil {
		re.code = nil
		re.executableJIT = nil
	}
}
