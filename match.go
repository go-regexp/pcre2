// Port of pcre2_match.c (PCRE2 10.44): the interpretive backtracking matcher,
// the "match()" function with explicit heap frames. The C code is a state
// machine whose RMATCH() macro saves a return number in the frame and jumps to
// MATCH_RECURSE, and whose RRETURN() jumps to RETURN_SWITCH, which resumes at
// the label L_RMn that follows the RMATCH. Go cannot jump into a block, so the
// code of every opcode that contains an RMATCH is laid out as top-level
// labelled sections of one function, joined with goto exactly as the C code
// joins them with its labels; every section cites the C line it comes from.
// All variables are declared at the head of the function (a goto may not jump
// over a declaration).
//
// Differences from C that do not change behaviour:
//   - subject and code pointers are int offsets (see match_block.go);
//   - the repeated-type, repeated-NOT and single-character repeat loops share
//     return points where the C code has several identical ones (RM208-RM219,
//     RM223-RM225 and RM33 are RM208; RM204-207 and RM29-32 are RM29/RM30;
//     RM25/RM27 are RM25; RM26/RM28 are RM26; RM220-222/RM34 are RM220/RM221;
//     RM200/RM23 are RM23);
//   - the property tests of PT_xxx are in propTest and the per-character type
//     tests of the repeated types are in typeFwd/typeMax (match_block.go,
//     match_types.go).
package pcre2

// Numbers for RMATCH calls at backtracking points (pcre2_match.c:155).
const (
	RM1 = 1 + iota
	RM2
	RM3
	RM4
	RM5
	RM6
	RM7
	RM8
	RM9
	RM10
	RM11
	RM12
	RM13
	RM14
	RM15
	RM16
	RM17
	RM18
	RM19
	RM20
	RM21
	RM22
	RM23
	RM24
	RM25
	RM26
	RM29
	RM30
	RM35
	RM36
	RM37
	RM100 = 100
	RM101 = 101
	RM202 = 202
	RM203 = 203
	RM208 = 208
	RM220 = 220
	RM221 = 221
)

// doCallout is do_callout() (pcre2_match.c:272): F.ecode points to OP_CALLOUT
// or OP_CALLOUT_STR; it returns the callout's return code (0 when there is no
// callout function) and the length of the callout item.
func doCallout(F *heapframe, mb *matchBlock) (rc int, length int) {
	code := mb.startCode
	e := F.ecode
	if code[e] == OP_CALLOUT {
		length = int(OP_lengths[OP_CALLOUT])
	} else {
		length = GET(code, e+1+2*LINK_SIZE)
	}
	if mb.callout == nil {
		return 0, length
	}
	cb := mb.cb
	cb.CaptureTop = uint32(F.offsetTop/2 + 1)
	cb.CaptureLast = F.captureLast
	// The callout sees the offset vector as if the first two slots (the
	// overall match) were in front of the frame's ovector, and unset.
	n := 2 + F.offsetTop
	if cap(mb.cbvec) < 2+len(F.ovector) {
		mb.cbvec = make([]uint64, 2+len(F.ovector))
	}
	cv := mb.cbvec[:2+len(F.ovector)]
	cv[0], cv[1] = PCRE2_UNSET, PCRE2_UNSET
	copy(cv[2:], F.ovector)
	_ = n
	cb.OffsetVector = cv
	cb.Mark = mb.markName(mb.nomatchMark)
	cb.CurrentPosition = uint64(F.eptr)
	cb.PatternPosition = uint64(GET(code, e+1))
	cb.NextItemLength = uint64(GET(code, e+1+LINK_SIZE))
	if code[e] == OP_CALLOUT {
		cb.CalloutNumber = uint32(code[e+1+2*LINK_SIZE])
		cb.CalloutStringOffset = 0
		cb.CalloutString = nil
		cb.CalloutStringLength = 0
	} else {
		cb.CalloutNumber = 0
		cb.CalloutStringOffset = uint64(GET(code, e+1+3*LINK_SIZE))
		cb.CalloutString = code[e+(1+4*LINK_SIZE)+1:]
		cb.CalloutStringLength = uint64(length - (1 + 4*LINK_SIZE) - 2)
		cb.CalloutString = cb.CalloutString[:cb.CalloutStringLength]
	}
	rc = mb.callout(cb, mb.calloutData)
	cb.CalloutFlags = 0
	return rc, length
}

// matchRef is match_ref() (pcre2_match.c:360): match a back reference at
// F.eptr. It returns 0 for a match (length is the number of code units
// matched), < 0 for no match and > 0 for a partial match.
func matchRef(offset int, caseless bool, F *heapframe, mb *matchBlock) (rc int, length int) {
	subj := mb.subject
	if offset >= F.offsetTop || F.ovector[offset] == PCRE2_UNSET {
		if mb.poptions&PCRE2_MATCH_UNSET_BACKREF != 0 {
			return 0, 0
		}
		return -1, 0
	}
	eptr := F.eptr
	eptrStart := eptr
	p := int(F.ovector[offset])
	rlen := int(F.ovector[offset+1] - F.ovector[offset])
	if caseless {
		utf := mb.poptions&PCRE2_UTF != 0
		if utf || mb.poptions&PCRE2_UCP != 0 {
			endptr := p + rlen
			for p < endptr {
				var c, d uint32
				if eptr >= mb.endSubject {
					return 1, 0
				}
				if utf {
					c, eptr = GETCHARINC(subj, eptr)
					d, p = GETCHARINC(subj, p)
				} else {
					c = uint32(subj[eptr])
					eptr++
					d = uint32(subj[p])
					p++
				}
				ur := GET_UCD(d)
				if c != d && c != uint32(int32(d)+ur.otherCase) {
					pp := ucd_caseless_sets[ur.caseset:]
					for k := 0; ; k++ {
						if c < pp[k] {
							return -1, 0
						}
						if c == pp[k] {
							break
						}
					}
				}
			}
		} else {
			for ; rlen > 0; rlen-- {
				if eptr >= mb.endSubject {
					return 1, 0
				}
				cc := subj[eptr]
				cp := subj[p]
				if mb.lcc[cp] != mb.lcc[cc] {
					return -1, 0
				}
				p++
				eptr++
			}
		}
	} else if mb.partial != 0 {
		for ; rlen > 0; rlen-- {
			if eptr >= mb.endSubject {
				return 1, 0
			}
			if subj[p] != subj[eptr] {
				return -1, 0
			}
			p++
			eptr++
		}
	} else {
		if mb.endSubject-eptr < rlen {
			return 1, 0
		}
		for k := 0; k < rlen; k++ {
			if subj[p+k] != subj[eptr+k] {
				return -1, 0
			}
		}
		eptr += rlen
	}
	return 0, eptr - eptrStart
}

// copyFrameState copies the part of a frame that new frames inherit (the C
// memcpy of frame_copy_size bytes starting at eptr).
func copyFrameState(dst, src *heapframe) {
	dst.eptr = src.eptr
	dst.startMatch = src.startMatch
	dst.mark = src.mark
	dst.recurseLastUsed = src.recurseLastUsed
	dst.currentRecurse = src.currentRecurse
	dst.captureLast = src.captureLast
	dst.lastGroupOffset = src.lastGroupOffset
	dst.offsetTop = src.offsetTop
	copy(dst.ovector, src.ovector)
}

// match is match() (pcre2_match.c:593): one match attempt at a single starting
// point. frameSize is the size in bytes of a C heap frame (used for the heap
// limit only).
func match(startEptr, startEcode int, topBracket uint16, frameSize int, md *MatchData, mb *matchBlock) int {
	var (
		fs     = md.heapframes.(*frameStore)
		frames = fs.frames
		subj   = mb.subject
		code   = mb.startCode
		utf    = mb.poptions&PCRE2_UTF != 0
		ucp    = mb.poptions&PCRE2_UCP != 0

		F, N, P *heapframe
		fi      int // index of F
		ni, pi  int // indices of N and P

		assertAcceptFrame = -1
		branchEnd         = -1
		branchStart       int
		bracode           int
		offset            int
		length            int
		rrc               int
		proptype          int
		i, fc, number     uint32
		reptype           uint32
		groupFrameType    uint32
		condition         bool
		curIsWord         bool
		prevIsWord        bool
		extra             int
		st                int
		xi                int
	)
	_, _, _, _ = ucp, extra, st, xi
	_, _ = bracode, ni

	// The first frame (pcre2_match.c:646).
	F = &frames[0]
	fi = 0
	F.rdepth = 0
	F.captureLast = 0
	F.currentRecurse = recurseUnset
	F.startMatch, F.eptr = startEptr, startEptr
	F.eptr = startEptr
	F.mark = -1
	F.offsetTop = 0
	F.lastGroupOffset = -1
	groupFrameType = 0
	goto newFrame

	// Come back here when we want to create a new frame for remembering a
	// backtracking point. (pcre2_match.c:662)
matchRecurse:
	// Set up a new backtracking frame. If the vector is full, get a new one,
	// doubling the size, but constrained by the heap limit (in KiB).
	ni = fi + 1
	if (ni+1)*frameSize >= int(md.heapframesSz) {
		usedsize := ni * frameSize
		var newsize uint64
		if md.heapframesSz >= PCRE2_SIZE_MAX/2 {
			if md.heapframesSz == PCRE2_SIZE_MAX-1 {
				return PCRE2_ERROR_NOMEMORY
			}
			newsize = PCRE2_SIZE_MAX - 1
		} else {
			newsize = md.heapframesSz * 2
		}
		if newsize/1024 >= uint64(mb.heapLimit) {
			oldSize := md.heapframesSz / 1024
			if uint64(mb.heapLimit) <= oldSize {
				return PCRE2_ERROR_HEAPLIMIT
			}
			maxDelta := 1024 * (uint64(mb.heapLimit) - oldSize)
			overBytes := md.heapframesSz % 1024
			if overBytes != 0 {
				maxDelta -= 1024 - overBytes
			}
			newsize = md.heapframesSz + maxDelta
		}
		// With a heap limit set, the permitted additional size may not be
		// enough for another frame, so do a final check.
		if newsize-uint64(usedsize) < uint64(frameSize) {
			return PCRE2_ERROR_HEAPLIMIT
		}
		md.heapframesSz = newsize
	}
	// The Go slices grow lazily under the emulated byte size.
	if ni+2 > len(fs.frames) {
		n := 2 * len(fs.frames)
		if n < ni+2 {
			n = ni + 2
		}
		fs.grow(n)
		frames = fs.frames
		F = &frames[fi]
	}
	// Copy those fields that must be copied into the new frame, increase the
	// "recursion" depth and then make the new frame current.
	N = &frames[ni]
	copyFrameState(N, F)
	N.rdepth = F.rdepth + 1
	F = N
	fi = ni

	// Carry on processing with a new frame. (pcre2_match.c:758)
newFrame:
	F.groupFrameType = groupFrameType
	F.ecode = startEcode
	F.backFrame = 1 // default is go back one frame

	// If this is a special type of group frame, remember its offset for quick
	// access at the end of the group. If this is a recursion, set a new current
	// recursion value.
	if groupFrameType != 0 {
		F.lastGroupOffset = fi
		if GF_IDMASK(groupFrameType) == GF_RECURSE {
			F.currentRecurse = GF_DATAMASK(groupFrameType)
		}
		groupFrameType = 0
	}

	// This is the main processing loop. First check that we haven't recorded
	// too many backtracks, or that we haven't exceeded the recursive depth
	// limit. (pcre2_match.c:782)
	{
		over := mb.matchCallCount >= mb.matchLimit
		mb.matchCallCount++
		if over {
			return PCRE2_ERROR_MATCHLIMIT
		}
	}
	if F.rdepth >= mb.matchLimitDepth {
		return PCRE2_ERROR_DEPTHLIMIT
	}

nextOp:
	F.op = code[F.ecode]
	switch int(F.op) {

	// Before OP_ACCEPT there may be any number of OP_CLOSE opcodes, to close
	// any currently open capturing brackets. (pcre2_match.c:809)
	case OP_CLOSE:
		if F.currentRecurse == recurseUnset {
			number = uint32(GET2(code, F.ecode+1))
			offset = F.lastGroupOffset
			for {
				if offset < 0 {
					return PCRE2_ERROR_INTERNAL
				}
				N = &frames[offset]
				P = &frames[offset-1]
				if N.groupFrameType == (GF_CAPTURE | number) {
					break
				}
				offset = P.lastGroupOffset
			}
			offset = int(number<<1) - 2
			F.captureLast = number
			F.ovector[offset] = uint64(P.eptr)
			F.ovector[offset+1] = uint64(F.eptr)
			if offset >= F.offsetTop {
				F.offsetTop = offset + 2
			}
		}
		F.ecode += int(OP_lengths[code[F.ecode]])
		goto nextOp

	// Real or forced end of the pattern, assertion, or recursion. In an
	// assertion ACCEPT, update the last used pointer and remember the current
	// frame so that the captures and mark can be fished out of it.
	// (pcre2_match.c:837)
	case OP_ASSERT_ACCEPT:
		if F.eptr > mb.lastUsedPtr {
			mb.lastUsedPtr = F.eptr
		}
		assertAcceptFrame = fi
		rrc = MATCH_ACCEPT
		goto returnSwitch

	// For ACCEPT within a recursion, we have to find the most recent
	// recursion. If not in a recursion, fall through to OP_END.
	case OP_ACCEPT:
		if F.currentRecurse != recurseUnset {
			offset = F.lastGroupOffset
			for {
				if offset < 0 {
					return PCRE2_ERROR_INTERNAL
				}
				N = &frames[offset]
				P = &frames[offset-1]
				if GF_IDMASK(N.groupFrameType) == GF_RECURSE {
					break
				}
				offset = P.lastGroupOffset
			}
			// N is now the frame of the recursion; the previous frame is at
			// the OP_RECURSE position. Go back there, copying the current
			// subject position and mark, and the start_match position, and
			// then move on past the OP_RECURSE.
			P.eptr = F.eptr
			P.mark = F.mark
			P.startMatch = F.startMatch
			fi = offset - 1
			F = P
			F.ecode += 1 + LINK_SIZE
			goto nextOp
		}
		goto opEnd

	case OP_END:
		goto opEnd

	// Match any single character type except newline; have to take care with
	// CRLF newlines and partial matching. (pcre2_match.c:947)
	case OP_ANY:
		if mb.isNewline(F.eptr) {
			rrc = MATCH_NOMATCH
			goto returnSwitch
		}
		if mb.partial != 0 && F.eptr == mb.endSubject-1 && mb.nltype == NLTYPE_FIXED &&
			mb.nllen == 2 && subj[F.eptr] == mb.nl[0] {
			mb.hitend = true
			if mb.partial > 1 {
				return PCRE2_ERROR_PARTIAL
			}
		}
		fallthrough

	// Match any single character whatsoever.
	case OP_ALLANY:
		if F.eptr >= mb.endSubject { // DO NOT merge the Feptr++ here
			if mb.scheck(F.eptr) {
				return PCRE2_ERROR_PARTIAL
			}
			rrc = MATCH_NOMATCH
			goto returnSwitch
		}
		F.eptr++
		if utf {
			F.eptr = acrossChar(subj, F.eptr, mb.endSubject)
		}
		F.ecode++
		goto nextOp

	// Match a single code unit, even in UTF mode. (pcre2_match.c:981)
	case OP_ANYBYTE:
		if F.eptr >= mb.endSubject {
			if mb.scheck(F.eptr) {
				return PCRE2_ERROR_PARTIAL
			}
			rrc = MATCH_NOMATCH
			goto returnSwitch
		}
		F.eptr++
		F.ecode++
		goto nextOp

	// Match a single character, casefully (pcre2_match.c:995).
	case OP_CHAR:
		if utf {
			F.length = 1
			F.ecode++
			fc, extra = GETCHARLEN(code, F.ecode)
			F.length += extra
			if F.length > mb.endSubject-F.eptr {
				if F.eptr >= mb.endSubject && mb.scheck(F.eptr) { // CHECK_PARTIAL()
					return PCRE2_ERROR_PARTIAL
				}
				rrc = MATCH_NOMATCH
				goto returnSwitch
			}
			for ; F.length > 0; F.length-- {
				c := code[F.ecode]
				F.ecode++
				e := subj[F.eptr]
				F.eptr++
				if c != e {
					rrc = MATCH_NOMATCH
					goto returnSwitch
				}
			}
		} else {
			if mb.endSubject-F.eptr < 1 {
				if mb.scheck(F.eptr) {
					return PCRE2_ERROR_PARTIAL
				}
				rrc = MATCH_NOMATCH
				goto returnSwitch
			}
			c := subj[F.eptr]
			F.eptr++
			if code[F.ecode+1] != c {
				rrc = MATCH_NOMATCH
				goto returnSwitch
			}
			F.ecode += 2
		}
		goto nextOp

	// Match a single character, caselessly (pcre2_match.c:1034).
	case OP_CHARI:
		if F.eptr >= mb.endSubject {
			if mb.scheck(F.eptr) {
				return PCRE2_ERROR_PARTIAL
			}
			rrc = MATCH_NOMATCH
			goto returnSwitch
		}
		if utf {
			F.length = 1
			F.ecode++
			fc, extra = GETCHARLEN(code, F.ecode)
			F.length += extra
			if fc < 128 {
				cc := uint32(subj[F.eptr])
				if uint32(mb.lcc[fc]) != uint32(mb.lcc[cc]) {
					rrc = MATCH_NOMATCH
					goto returnSwitch
				}
				F.ecode++
				F.eptr++
			} else {
				var dc uint32
				dc, F.eptr = GETCHARINC(subj, F.eptr)
				F.ecode += F.length
				if dc != fc && dc != UCD_OTHERCASE(fc) {
					rrc = MATCH_NOMATCH
					goto returnSwitch
				}
			}
		} else if ucp {
			cc := uint32(subj[F.eptr])
			fc = uint32(code[F.ecode+1])
			if fc < 128 {
				if uint32(mb.lcc[fc]) != uint32(mb.lcc[cc]) {
					rrc = MATCH_NOMATCH
					goto returnSwitch
				}
			} else if cc != fc && cc != UCD_OTHERCASE(fc) {
				rrc = MATCH_NOMATCH
				goto returnSwitch
			}
			F.eptr++
			F.ecode += 2
		} else {
			if mb.lcc[code[F.ecode+1]] != mb.lcc[subj[F.eptr]] {
				rrc = MATCH_NOMATCH
				goto returnSwitch
			}
			F.eptr++
			F.ecode += 2
		}
		goto nextOp

	// Match not a single character (pcre2_match.c:1110).
	case OP_NOT, OP_NOTI:
		if F.eptr >= mb.endSubject {
			if mb.scheck(F.eptr) {
				return PCRE2_ERROR_PARTIAL
			}
			rrc = MATCH_NOMATCH
			goto returnSwitch
		}
		if utf {
			var ch uint32
			F.ecode++
			ch, F.ecode = GETCHARINC(code, F.ecode)
			fc, F.eptr = GETCHARINC(subj, F.eptr)
			if ch == fc {
				rrc = MATCH_NOMATCH
				goto returnSwitch
			} else if F.op == OP_NOTI {
				if ch > 127 {
					ch = UCD_OTHERCASE(ch)
				} else {
					ch = uint32(mb.fcc[ch])
				}
				if ch == fc {
					rrc = MATCH_NOMATCH
					goto returnSwitch
				}
			}
		} else if ucp {
			fc = uint32(subj[F.eptr])
			F.eptr++
			ch := uint32(code[F.ecode+1])
			F.ecode += 2
			if ch == fc {
				rrc = MATCH_NOMATCH
				goto returnSwitch
			} else if F.op == OP_NOTI {
				if ch > 127 {
					ch = UCD_OTHERCASE(ch)
				} else {
					ch = uint32(mb.fcc[ch])
				}
				if ch == fc {
					rrc = MATCH_NOMATCH
					goto returnSwitch
				}
			}
		} else {
			ch := uint32(code[F.ecode+1])
			fc = uint32(subj[F.eptr])
			F.eptr++
			if ch == fc || (F.op == OP_NOTI && uint32(mb.fcc[ch]) == fc) {
				rrc = MATCH_NOMATCH
				goto returnSwitch
			}
			F.ecode += 2
		}
		goto nextOp

	// Match a single character repeatedly (pcre2_match.c:1188). The temporary
	// fields: tempSize = Loclength, tempSptr[0] = Lstart_eptr, tempSptr[1] =
	// Lcharptr, temp32[0] = Lmin, [1] = Lmax, [2] = Lc, [3] = Loc.
	case OP_EXACT, OP_EXACTI:
		F.temp32[0] = uint32(GET2(code, F.ecode+1))
		F.temp32[1] = F.temp32[0]
		F.ecode += 1 + IMM2_SIZE
		goto repeatChar

	case OP_POSUPTO, OP_POSUPTOI:
		reptype = REPTYPE_POS
		F.temp32[0] = 0
		F.temp32[1] = uint32(GET2(code, F.ecode+1))
		F.ecode += 1 + IMM2_SIZE
		goto repeatChar

	case OP_UPTO, OP_UPTOI:
		reptype = REPTYPE_MAX
		F.temp32[0] = 0
		F.temp32[1] = uint32(GET2(code, F.ecode+1))
		F.ecode += 1 + IMM2_SIZE
		goto repeatChar

	case OP_MINUPTO, OP_MINUPTOI:
		reptype = REPTYPE_MIN
		F.temp32[0] = 0
		F.temp32[1] = uint32(GET2(code, F.ecode+1))
		F.ecode += 1 + IMM2_SIZE
		goto repeatChar

	case OP_POSSTAR, OP_POSSTARI:
		reptype = REPTYPE_POS
		F.temp32[0], F.temp32[1] = 0, uint32Max
		F.ecode++
		goto repeatChar

	case OP_POSPLUS, OP_POSPLUSI:
		reptype = REPTYPE_POS
		F.temp32[0], F.temp32[1] = 1, uint32Max
		F.ecode++
		goto repeatChar

	case OP_POSQUERY, OP_POSQUERYI:
		reptype = REPTYPE_POS
		F.temp32[0], F.temp32[1] = 0, 1
		F.ecode++
		goto repeatChar

	case OP_STAR, OP_STARI, OP_MINSTAR, OP_MINSTARI, OP_PLUS, OP_PLUSI, OP_MINPLUS, OP_MINPLUSI,
		OP_QUERY, OP_QUERYI, OP_MINQUERY, OP_MINQUERYI:
		if F.op < OP_STARI {
			fc = uint32(code[F.ecode]) - OP_STAR
		} else {
			fc = uint32(code[F.ecode]) - OP_STARI
		}
		F.ecode++
		F.temp32[0] = rep_min[fc]
		F.temp32[1] = rep_max[fc]
		reptype = rep_typ[fc]
		goto repeatChar

	// Match a negated single character repeatedly (pcre2_match.c:1542).
	case OP_NOTEXACT, OP_NOTEXACTI:
		F.temp32[0] = uint32(GET2(code, F.ecode+1))
		F.temp32[1] = F.temp32[0]
		F.ecode += 1 + IMM2_SIZE
		goto repeatNotChar

	case OP_NOTUPTO, OP_NOTUPTOI:
		F.temp32[0] = 0
		F.temp32[1] = uint32(GET2(code, F.ecode+1))
		reptype = REPTYPE_MAX
		F.ecode += 1 + IMM2_SIZE
		goto repeatNotChar

	case OP_NOTMINUPTO, OP_NOTMINUPTOI:
		F.temp32[0] = 0
		F.temp32[1] = uint32(GET2(code, F.ecode+1))
		reptype = REPTYPE_MIN
		F.ecode += 1 + IMM2_SIZE
		goto repeatNotChar

	case OP_NOTPOSSTAR, OP_NOTPOSSTARI:
		reptype = REPTYPE_POS
		F.temp32[0], F.temp32[1] = 0, uint32Max
		F.ecode++
		goto repeatNotChar

	case OP_NOTPOSPLUS, OP_NOTPOSPLUSI:
		reptype = REPTYPE_POS
		F.temp32[0], F.temp32[1] = 1, uint32Max
		F.ecode++
		goto repeatNotChar

	case OP_NOTPOSQUERY, OP_NOTPOSQUERYI:
		reptype = REPTYPE_POS
		F.temp32[0], F.temp32[1] = 0, 1
		F.ecode++
		goto repeatNotChar

	case OP_NOTPOSUPTO, OP_NOTPOSUPTOI:
		reptype = REPTYPE_POS
		F.temp32[0] = 0
		F.temp32[1] = uint32(GET2(code, F.ecode+1))
		F.ecode += 1 + IMM2_SIZE
		goto repeatNotChar

	case OP_NOTSTAR, OP_NOTSTARI, OP_NOTMINSTAR, OP_NOTMINSTARI, OP_NOTPLUS, OP_NOTPLUSI,
		OP_NOTMINPLUS, OP_NOTMINPLUSI, OP_NOTQUERY, OP_NOTQUERYI, OP_NOTMINQUERY, OP_NOTMINQUERYI:
		if F.op >= OP_NOTSTARI {
			fc = uint32(code[F.ecode]) - OP_NOTSTARI
		} else {
			fc = uint32(code[F.ecode]) - OP_NOTSTAR
		}
		F.ecode++
		F.temp32[0] = rep_min[fc]
		F.temp32[1] = rep_max[fc]
		reptype = rep_typ[fc]
		goto repeatNotChar

	// Match a bit-mapped character class, possibly repeatedly (pcre2_match.c:1933).
	// tempSptr[0] = Lstart_eptr, tempSptr[1] = Lbyte_map_address, temp32[0] =
	// Lmin, temp32[1] = Lmax.
	case OP_NCLASS, OP_CLASS:
		F.tempSptr[1] = F.ecode + 1 // save for matching
		F.ecode += 1 + 32           // advance past the item
		switch int(code[F.ecode]) {
		case OP_CRSTAR, OP_CRMINSTAR, OP_CRPLUS, OP_CRMINPLUS, OP_CRQUERY, OP_CRMINQUERY,
			OP_CRPOSSTAR, OP_CRPOSPLUS, OP_CRPOSQUERY:
			fc = uint32(code[F.ecode]) - OP_CRSTAR
			F.ecode++
			F.temp32[0] = rep_min[fc]
			F.temp32[1] = rep_max[fc]
			reptype = rep_typ[fc]
		case OP_CRRANGE, OP_CRMINRANGE, OP_CRPOSRANGE:
			F.temp32[0] = uint32(GET2(code, F.ecode+1))
			F.temp32[1] = uint32(GET2(code, F.ecode+1+IMM2_SIZE))
			if F.temp32[1] == 0 {
				F.temp32[1] = uint32Max
			}
			reptype = rep_typ[int(code[F.ecode])-OP_CRSTAR]
			F.ecode += 1 + 2*IMM2_SIZE
		default: // no repeat follows
			F.temp32[0], F.temp32[1] = 1, 1
		}

		// First, ensure the minimum number of matches are present.
		for i = 1; i <= F.temp32[0]; i++ {
			if F.eptr >= mb.endSubject {
				if mb.scheck(F.eptr) {
					return PCRE2_ERROR_PARTIAL
				}
				rrc = MATCH_NOMATCH
				goto returnSwitch
			}
			fc, F.eptr = GETCHARINCTEST(utf, subj, F.eptr)
			if !mb.classHas(F.tempSptr[1], F.op, fc) {
				rrc = MATCH_NOMATCH
				goto returnSwitch
			}
		}
		// If Lmax == Lmin we are done. Continue with main loop.
		if F.temp32[0] == F.temp32[1] {
			goto nextOp
		}
		// If minimizing, keep testing the rest of the expression and
		// advancing the pointer while it matches the class.
		if reptype == REPTYPE_MIN {
			goto classMinLoop
		}
		// If maximizing, find the longest possible run, then work backwards.
		F.tempSptr[0] = F.eptr
		for i = F.temp32[0]; i < F.temp32[1]; i++ {
			l := 1
			if F.eptr >= mb.endSubject {
				if mb.scheck(F.eptr) {
					return PCRE2_ERROR_PARTIAL
				}
				break
			}
			fc, extra = GETCHARLENTEST(utf, subj, F.eptr)
			l += extra
			if !mb.classHas(F.tempSptr[1], F.op, fc) {
				break
			}
			F.eptr += l
		}
		if reptype == REPTYPE_POS {
			goto nextOp // no backtracking
		}
		if utf {
			goto classMaxUTF
		}
		goto classMax

	// Match an extended character class (pcre2_match.c:2175). tempSptr[0] =
	// Lstart_eptr, tempSptr[1] = Lxclass_data.
	case OP_XCLASS:
		F.tempSptr[1] = F.ecode + 1 + LINK_SIZE // save for matching
		F.ecode += GET(code, F.ecode+1)         // advance past the item
		switch int(code[F.ecode]) {
		case OP_CRSTAR, OP_CRMINSTAR, OP_CRPLUS, OP_CRMINPLUS, OP_CRQUERY, OP_CRMINQUERY,
			OP_CRPOSSTAR, OP_CRPOSPLUS, OP_CRPOSQUERY:
			fc = uint32(code[F.ecode]) - OP_CRSTAR
			F.ecode++
			F.temp32[0] = rep_min[fc]
			F.temp32[1] = rep_max[fc]
			reptype = rep_typ[fc]
		case OP_CRRANGE, OP_CRMINRANGE, OP_CRPOSRANGE:
			F.temp32[0] = uint32(GET2(code, F.ecode+1))
			F.temp32[1] = uint32(GET2(code, F.ecode+1+IMM2_SIZE))
			if F.temp32[1] == 0 {
				F.temp32[1] = uint32Max
			}
			reptype = rep_typ[int(code[F.ecode])-OP_CRSTAR]
			F.ecode += 1 + 2*IMM2_SIZE
		default:
			F.temp32[0], F.temp32[1] = 1, 1
		}
		for i = 1; i <= F.temp32[0]; i++ {
			if F.eptr >= mb.endSubject {
				if mb.scheck(F.eptr) {
					return PCRE2_ERROR_PARTIAL
				}
				rrc = MATCH_NOMATCH
				goto returnSwitch
			}
			fc, F.eptr = GETCHARINCTEST(utf, subj, F.eptr)
			if !xclass(fc, code[F.tempSptr[1]:], utf) {
				rrc = MATCH_NOMATCH
				goto returnSwitch
			}
		}
		if F.temp32[0] == F.temp32[1] {
			goto nextOp
		}
		if reptype == REPTYPE_MIN {
			goto xclassMinLoop
		}
		F.tempSptr[0] = F.eptr
		for i = F.temp32[0]; i < F.temp32[1]; i++ {
			l := 1
			if F.eptr >= mb.endSubject {
				if mb.scheck(F.eptr) {
					return PCRE2_ERROR_PARTIAL
				}
				break
			}
			fc, extra = GETCHARLENTEST(utf, subj, F.eptr)
			l += extra
			if !xclass(fc, code[F.tempSptr[1]:], utf) {
				break
			}
			F.eptr += l
		}
		if reptype == REPTYPE_POS {
			goto nextOp // no backtracking
		}
		goto xclassMax

	// Match various character types when PCRE2_UCP is not set
	// (pcre2_match.c:2305). The tests are those of typeFwd with loop=true and
	// a single character; OP_DIGIT etc. here use GETCHARINCTEST then the
	// table (limit 256).
	case OP_NOT_DIGIT, OP_DIGIT, OP_NOT_WHITESPACE, OP_WHITESPACE, OP_NOT_WORDCHAR, OP_WORDCHAR,
		OP_NOT_HSPACE, OP_HSPACE, OP_NOT_VSPACE, OP_VSPACE:
		if F.eptr >= mb.endSubject {
			if mb.scheck(F.eptr) {
				return PCRE2_ERROR_PARTIAL
			}
			rrc = MATCH_NOMATCH
			goto returnSwitch
		}
		fc, F.eptr = GETCHARINCTEST(utf, subj, F.eptr)
		if !mb.simpleType(int(F.op), fc, 256) {
			rrc = MATCH_NOMATCH
			goto returnSwitch
		}
		F.ecode++
		goto nextOp

	case OP_ANYNL:
		if F.eptr >= mb.endSubject {
			if mb.scheck(F.eptr) {
				return PCRE2_ERROR_PARTIAL
			}
			rrc = MATCH_NOMATCH
			goto returnSwitch
		}
		fc, F.eptr = GETCHARINCTEST(utf, subj, F.eptr)
		switch fc {
		case CHAR_CR:
			if F.eptr >= mb.endSubject {
				if mb.scheck(F.eptr) {
					return PCRE2_ERROR_PARTIAL
				}
			} else if subj[F.eptr] == CHAR_LF {
				F.eptr++
			}
		case CHAR_LF:
		case CHAR_VT, CHAR_FF, CHAR_NEL, 0x2028, 0x2029:
			if mb.bsrConvention == PCRE2_BSR_ANYCRLF {
				rrc = MATCH_NOMATCH
				goto returnSwitch
			}
		default:
			rrc = MATCH_NOMATCH
			goto returnSwitch
		}
		F.ecode++
		goto nextOp

	// Check the next character by Unicode property (pcre2_match.c:2479).
	case OP_PROP, OP_NOTPROP:
		if F.eptr >= mb.endSubject {
			if mb.scheck(F.eptr) {
				return PCRE2_ERROR_PARTIAL
			}
			rrc = MATCH_NOMATCH
			goto returnSwitch
		}
		fc, F.eptr = GETCHARINCTEST(utf, subj, F.eptr)
		{
			res, ok := propTest(int(code[F.ecode+1]), fc, uint32(code[F.ecode+2]))
			if !ok {
				return PCRE2_ERROR_INTERNAL // this should never occur
			}
			if res == (F.op == OP_NOTPROP) {
				rrc = MATCH_NOMATCH
				goto returnSwitch
			}
			F.ecode += 3
		}
		goto nextOp

	// Match an extended Unicode sequence (pcre2_match.c:2621).
	case OP_EXTUNI:
		if F.eptr >= mb.endSubject {
			if mb.scheck(F.eptr) {
				return PCRE2_ERROR_PARTIAL
			}
			rrc = MATCH_NOMATCH
			goto returnSwitch
		}
		fc, F.eptr = GETCHARINCTEST(utf, subj, F.eptr)
		F.eptr = extuni(fc, subj, F.eptr, 0, mb.endSubject, utf, nil)
		if F.eptr >= mb.endSubject && mb.scheck(F.eptr) { // CHECK_PARTIAL()
			return PCRE2_ERROR_PARTIAL
		}
		F.ecode++
		goto nextOp

	// Match a single character type repeatedly (pcre2_match.c:2651).
	// temp32[0] = Lmin, [1] = Lmax, [2] = Lctype, [3] = Lpropvalue,
	// tempSptr[0] = Lstart_eptr.
	case OP_TYPEEXACT:
		F.temp32[0] = uint32(GET2(code, F.ecode+1))
		F.temp32[1] = F.temp32[0]
		F.ecode += 1 + IMM2_SIZE
		goto repeatType

	case OP_TYPEUPTO, OP_TYPEMINUPTO:
		F.temp32[0] = 0
		F.temp32[1] = uint32(GET2(code, F.ecode+1))
		if code[F.ecode] == OP_TYPEMINUPTO {
			reptype = REPTYPE_MIN
		} else {
			reptype = REPTYPE_MAX
		}
		F.ecode += 1 + IMM2_SIZE
		goto repeatType

	case OP_TYPEPOSSTAR:
		reptype = REPTYPE_POS
		F.temp32[0], F.temp32[1] = 0, uint32Max
		F.ecode++
		goto repeatType

	case OP_TYPEPOSPLUS:
		reptype = REPTYPE_POS
		F.temp32[0], F.temp32[1] = 1, uint32Max
		F.ecode++
		goto repeatType

	case OP_TYPEPOSQUERY:
		reptype = REPTYPE_POS
		F.temp32[0], F.temp32[1] = 0, 1
		F.ecode++
		goto repeatType

	case OP_TYPEPOSUPTO:
		reptype = REPTYPE_POS
		F.temp32[0] = 0
		F.temp32[1] = uint32(GET2(code, F.ecode+1))
		F.ecode += 1 + IMM2_SIZE
		goto repeatType

	case OP_TYPESTAR, OP_TYPEMINSTAR, OP_TYPEPLUS, OP_TYPEMINPLUS, OP_TYPEQUERY, OP_TYPEMINQUERY:
		fc = uint32(code[F.ecode]) - OP_TYPESTAR
		F.ecode++
		F.temp32[0] = rep_min[fc]
		F.temp32[1] = rep_max[fc]
		reptype = rep_typ[fc]
		goto repeatType

	//@@MORE_OPS@@

	default:
		return PCRE2_ERROR_INTERNAL
	}
	// Do not insert any code in here without much thought; it is assumed that
	// "goto nextOp" in the code above comes out to here to repeat the main loop.

	//@@MORE_SECTIONS@@

	// The RRETURN() macro jumps here. The number that is saved in Freturn_id
	// indicates which label we actually want to return to. (pcre2_match.c:6469)
returnSwitch:
	if F.eptr > mb.lastUsedPtr {
		mb.lastUsedPtr = F.eptr
	}
	if F.rdepth == 0 { // exit from the top level
		return rrc
	}
	fi -= F.backFrame // backtrack
	F = &frames[fi]
	mb.cb.CalloutFlags |= PCRE2_CALLOUT_BACKTRACK // note for callouts
	switch F.returnID {
		//@@DISPATCH@@
	default:
		return PCRE2_ERROR_INTERNAL
	}

	_, _, _, _, _, _ = branchEnd, branchStart, condition, curIsWord, prevIsWord, assertAcceptFrame
	_ = pi
	_ = proptype
	_ = number
	_ = reptype
	_ = length
	_ = i
}
