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
	RM201 = 201
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

	// Match a back reference, possibly repeatedly (pcre2_match.c:4994).
	// temp32[0] = Lmin, [1] = Lmax, [2] = Lcaseless, tempSptr[0] = Lstart,
	// tempSize = Loffset.
	case OP_DNREF, OP_DNREFI:
		F.temp32[2] = matchBool32(F.op == OP_DNREFI)
		{
			count := GET2(code, F.ecode+1+IMM2_SIZE)
			slot := int(mb.nameEntrySize) * GET2(code, F.ecode+1)
			F.ecode += 1 + 2*IMM2_SIZE
			for ; count > 0; count-- {
				F.tempSize = (GET2(mb.nameTable, slot) << 1) - 2
				if F.tempSize < F.offsetTop && F.ovector[F.tempSize] != PCRE2_UNSET {
					break
				}
				slot += int(mb.nameEntrySize)
			}
		}
		goto refRepeat

	case OP_REF, OP_REFI:
		F.temp32[2] = matchBool32(F.op == OP_REFI)
		F.tempSize = (GET2(code, F.ecode+1) << 1) - 2
		F.ecode += 1 + IMM2_SIZE
		goto refRepeat

	// BRAZERO, BRAMINZERO and SKIPZERO (pcre2_match.c:5224). tempSptr[0] =
	// Lnext_ecode.
	case OP_BRAZERO:
		F.tempSptr[0] = F.ecode + 1
		startEcode = F.tempSptr[0]
		F.returnID = RM9
		goto matchRecurse

	case OP_BRAMINZERO:
		F.tempSptr[0] = F.ecode + 1
		for {
			F.tempSptr[0] += GET(code, F.tempSptr[0]+1)
			if code[F.tempSptr[0]] != OP_ALT {
				break
			}
		}
		startEcode = F.tempSptr[0] + 1 + LINK_SIZE
		F.returnID = RM10
		goto matchRecurse

	case OP_SKIPZERO:
		F.ecode++
		for {
			F.ecode += GET(code, F.ecode+1)
			if code[F.ecode] != OP_ALT {
				break
			}
		}
		F.ecode += 1 + LINK_SIZE
		goto nextOp

	// Possessive brackets with an unlimited repeat (pcre2_match.c:5260).
	// temp32[0] = Lframe_type, [1] = Lmatched_once, [2] = Lzero_allowed,
	// tempSptr[0] = Lstart_eptr, [1] = Lstart_group.
	case OP_BRAPOSZERO:
		F.temp32[2] = 1 // Zero repeat is allowed
		F.ecode++
		if code[F.ecode] == OP_CBRAPOS || code[F.ecode] == OP_SCBRAPOS {
			goto posCapture
		}
		goto posNonCapture

	case OP_BRAPOS, OP_SBRAPOS:
		F.temp32[2] = 0 // Zero repeat not allowed
		goto posNonCapture

	case OP_CBRAPOS, OP_SCBRAPOS:
		F.temp32[2] = 0 // Zero repeat not allowed
		goto posCapture

	// Non-capturing brackets that cannot match an empty string (pcre2_match.c:5349).
	case OP_BRA:
		if mb.hasthen || F.rdepth == 0 {
			F.temp32[0] = 0
			goto groupLoop
		}
		goto braLoop

	// Capturing brackets other than the possessive ones (pcre2_match.c:5381).
	case OP_CBRA, OP_SCBRA:
		F.temp32[0] = GF_CAPTURE | uint32(GET2(code, F.ecode+1+LINK_SIZE))
		goto groupLoop

	// Atomic groups and non-capturing brackets that can match an empty string.
	case OP_ONCE, OP_SCRIPT_RUN, OP_SBRA:
		F.temp32[0] = GF_NOCAPTURE | uint32(F.op)
		goto groupLoop

	// Pattern recursion (pcre2_match.c:5427).
	case OP_RECURSE:
		bracode = GET(code, F.ecode+1)
		if bracode == 0 {
			number = 0
		} else {
			number = uint32(GET2(code, bracode+1+LINK_SIZE))
		}
		// If we are already in a pattern recursion, check for repeating the same
		// one without changing the subject pointer or the last referenced
		// character in the subject.
		if F.currentRecurse != recurseUnset {
			offset = F.lastGroupOffset
			for offset >= 0 {
				N = &frames[offset]
				P = &frames[offset-1]
				if N.groupFrameType == (GF_RECURSE | number) {
					if F.eptr == P.eptr && mb.lastUsedPtr == P.recurseLastUsed &&
						mb.moptions&PCRE2_DISABLE_RECURSELOOP_CHECK == 0 {
						return PCRE2_ERROR_RECURSELOOP
					}
					break
				}
				offset = P.lastGroupOffset
			}
		}
		// Remember the current last referenced character and then run the
		// recursion branch by branch.
		F.recurseLastUsed = mb.lastUsedPtr
		F.tempSptr[0] = bracode
		F.temp32[0] = GF_RECURSE | number
		goto recurseLoop

	// Positive assertions (pcre2_match.c:5511).
	case OP_ASSERT, OP_ASSERTBACK, OP_ASSERT_NA, OP_ASSERTBACK_NA:
		F.temp32[0] = GF_NOCAPTURE | uint32(F.op)
		goto assertLoop

	// Negative assertions (pcre2_match.c:5547).
	case OP_ASSERT_NOT, OP_ASSERTBACK_NOT:
		F.temp32[0] = GF_NOCAPTURE | uint32(F.op)
		goto assertNotLoop

	// Callouts (pcre2_match.c:5594).
	case OP_CALLOUT, OP_CALLOUT_STR:
		rrc, length = doCallout(F, mb)
		if rrc > 0 {
			rrc = MATCH_NOMATCH
			goto returnSwitch
		}
		if rrc < 0 {
			goto returnSwitch
		}
		F.ecode += length
		goto nextOp

	// Conditional group (pcre2_match.c:5609): compilation checked that there are
	// no more than two branches. If the condition is false, skipping the first
	// branch takes us past the end of the item if there is only one branch, but
	// that's exactly what we want. F.length is added to F.ecode when the
	// condition is false, to get to the second branch.
	case OP_COND, OP_SCOND:
		F.length = GET(code, F.ecode+1) // Offset to the second branch
		if code[F.ecode+F.length] != OP_ALT {
			F.length -= 1 + LINK_SIZE
		}
		F.ecode += 1 + LINK_SIZE // From this opcode

		// Because of the way auto-callout works during compile, a callout item
		// is inserted between OP_COND and an assertion condition. Such a callout
		// can also be inserted manually.
		if code[F.ecode] == OP_CALLOUT || code[F.ecode] == OP_CALLOUT_STR {
			rrc, length = doCallout(F, mb)
			if rrc > 0 {
				rrc = MATCH_NOMATCH
				goto returnSwitch
			}
			if rrc < 0 {
				goto returnSwitch
			}
			// Advance F.ecode past the callout, so it now points to the
			// condition. F.length is adjusted so that F.ecode+F.length is
			// unchanged.
			F.ecode += length
			F.length -= length
		}

		// Test the various possible conditions
		condition = false
		switch int(code[F.ecode]) {
		case OP_RREF: // Group recursion test
			if F.currentRecurse != recurseUnset {
				number = uint32(GET2(code, F.ecode+1))
				condition = number == RREF_ANY || number == F.currentRecurse
			}
		case OP_DNRREF: // Duplicate named group recursion test
			if F.currentRecurse != recurseUnset {
				count := GET2(code, F.ecode+1+IMM2_SIZE)
				slot := int(mb.nameEntrySize) * GET2(code, F.ecode+1)
				for ; count > 0; count-- {
					number = uint32(GET2(mb.nameTable, slot))
					condition = number == F.currentRecurse
					if condition {
						break
					}
					slot += int(mb.nameEntrySize)
				}
			}
		case OP_CREF: // Numbered group used test
			offset = (GET2(code, F.ecode+1) << 1) - 2 // Doubled ref number
			condition = offset < F.offsetTop && F.ovector[offset] != PCRE2_UNSET
		case OP_DNCREF: // Duplicate named group used test
			count := GET2(code, F.ecode+1+IMM2_SIZE)
			slot := int(mb.nameEntrySize) * GET2(code, F.ecode+1)
			for ; count > 0; count-- {
				offset = (GET2(mb.nameTable, slot) << 1) - 2
				condition = offset < F.offsetTop && F.ovector[offset] != PCRE2_UNSET
				if condition {
					break
				}
				slot += int(mb.nameEntrySize)
			}
		case OP_FALSE, OP_FAIL: // The assertion (?!) becomes OP_FAIL
		case OP_TRUE:
			condition = true
		default:
			// The condition is an assertion. Run code similar to the assertion
			// code above. temp32[0] = Lpositive, tempSptr[0] = Lstart_branch.
			F.temp32[0] = matchBool32(code[F.ecode] == OP_ASSERT || code[F.ecode] == OP_ASSERTBACK)
			F.tempSptr[0] = F.ecode
			goto condAssertLoop
		}
		goto condChoose

	// Move the subject pointer back by one fixed amount (pcre2_match.c:5793).
	case OP_REVERSE:
		number = uint32(GET2(code, F.ecode+1))
		if utf {
			for ; number > 0; number-- {
				if F.eptr <= mb.checkSubject {
					rrc = MATCH_NOMATCH
					goto returnSwitch
				}
				F.eptr--
				F.eptr = BACKCHAR(subj, F.eptr)
			}
		} else {
			// No UTF support, or not in UTF mode: count is code unit count
			if int(number) > F.eptr {
				rrc = MATCH_NOMATCH
				goto returnSwitch
			}
			F.eptr -= int(number)
		}
		// Save the earliest consulted character, then skip to next opcode
		if F.eptr < mb.startUsedPtr {
			mb.startUsedPtr = F.eptr
		}
		F.ecode += 1 + IMM2_SIZE
		goto nextOp

	// Move the subject pointer back by a variable amount (pcre2_match.c:5834).
	// temp32[0] = Lmin, [1] = Lmax, tempSptr[0] = Leptr.
	case OP_VREVERSE:
		F.temp32[0] = uint32(GET2(code, F.ecode+1))
		F.temp32[1] = uint32(GET2(code, F.ecode+1+IMM2_SIZE))
		F.tempSptr[0] = F.eptr
		// Move back by the maximum branch length and then work forwards. This
		// ensures that items such as \d{3,5} get the maximum length, which is
		// relevant for captures, and makes for Perl compatibility.
		if utf {
			for i = 0; i < F.temp32[1]; i++ {
				if F.eptr == 0 {
					if i < F.temp32[0] {
						rrc = MATCH_NOMATCH
						goto returnSwitch
					}
					F.temp32[1] = i
					break
				}
				F.eptr--
				F.eptr = BACKCHAR(subj, F.eptr)
			}
		} else {
			diff := F.eptr
			available := uint32(diff)
			if diff > 65535 {
				available = 65535
			}
			if F.temp32[0] > available {
				rrc = MATCH_NOMATCH
				goto returnSwitch
			}
			if F.temp32[1] > available {
				F.temp32[1] = available
			}
			F.eptr -= int(F.temp32[1])
		}
		goto vrevLoop

	// An alternation is the end of a branch; scan along to find the end of the
	// bracketed group (pcre2_match.c:5894).
	case OP_ALT:
		branchEnd = F.ecode
		for {
			F.ecode += GET(code, F.ecode+1)
			if code[F.ecode] != OP_ALT {
				break
			}
		}
		goto nextOp

	// The end of a parenthesized group (pcre2_match.c:5906). For all but OP_BRA
	// and OP_COND, the starting frame was added to the chained frames in order
	// to remember the starting subject position for the group.
	case OP_KET, OP_KETRMIN, OP_KETRMAX, OP_KETRPOS:
		bracode = F.ecode - GET(code, F.ecode+1)
		if branchEnd < 0 {
			branchEnd = F.ecode
		}
		branchStart = bracode
		for branchStart+GET(code, branchStart+1) != branchEnd {
			branchStart += GET(code, branchStart+1)
		}
		branchEnd = -1

		// Point N to the frame at the start of the most recent group, and P to
		// its predecessor. Remember the subject pointer at the start of the
		// group.
		P = nil
		if code[bracode] != OP_BRA && code[bracode] != OP_COND {
			ni = F.lastGroupOffset
			if ni < 1 {
				return PCRE2_ERROR_INTERNAL
			}
			N = &frames[ni]
			pi = ni - 1
			P = &frames[pi]
			F.lastGroupOffset = P.lastGroupOffset

			// If we are at the end of an assertion that is a condition, return
			// a match, discarding any intermediate backtracking points. Copy
			// back the mark setting and the captures into the frame before N so
			// that they are set on return.
			if GF_IDMASK(N.groupFrameType) == GF_CONDASSERT {
				copy(P.ovector[:F.offsetTop], F.ovector[:F.offsetTop])
				P.offsetTop = F.offsetTop
				P.mark = F.mark
				F.backFrame = fi - pi
				rrc = MATCH_MATCH
				goto returnSwitch
			}
		}

		// The group was not a conditional assertion.
		switch int(code[bracode]) {
		// Whole pattern recursion is handled as a recursion into group 0, but
		// the entire pattern is wrapped in OP_BRA/OP_KET rather than a
		// capturing group. The end of such recursion is detected by checking
		// for an immediately following OP_END when we are recursing in group 0.
		case OP_BRA:
			if F.currentRecurse != 0 || code[F.ecode+1+LINK_SIZE] != OP_END {
				break
			}
			// It is the end of whole-pattern recursion.
			offset = F.lastGroupOffset
			if offset < 1 {
				return PCRE2_ERROR_INTERNAL
			}
			N = &frames[offset]
			pi = offset - 1
			P = &frames[pi]
			F.lastGroupOffset = P.lastGroupOffset
			// Reinstate the previous set of captures and then carry on after
			// the recursion call.
			copy(F.ovector[:F.offsetTop], P.ovector[:F.offsetTop])
			F.offsetTop = P.offsetTop
			F.captureLast = P.captureLast
			F.currentRecurse = P.currentRecurse
			F.ecode = P.ecode + 1 + LINK_SIZE
			goto nextOp // With next opcode

		case OP_COND, OP_SCOND: // No need to do anything for these

		// Non-atomic positive assertions are like OP_BRA, except that the
		// subject pointer must be put back to where it was at the start of the
		// assertion. For a variable lookbehind, check its end point.
		case OP_ASSERTBACK_NA:
			if code[branchStart+1+LINK_SIZE] == OP_VREVERSE && F.eptr != P.eptr {
				rrc = MATCH_NOMATCH
				goto returnSwitch
			}
			if F.eptr > mb.lastUsedPtr {
				mb.lastUsedPtr = F.eptr
			}
			F.eptr = P.eptr

		case OP_ASSERT_NA:
			if F.eptr > mb.lastUsedPtr {
				mb.lastUsedPtr = F.eptr
			}
			F.eptr = P.eptr

		// Atomic positive assertions are like OP_ONCE, except that in addition
		// the subject pointer must be put back to where it was at the start of
		// the assertion. For a variable lookbehind, check its end point.
		case OP_ASSERTBACK, OP_ASSERT:
			if code[bracode] == OP_ASSERTBACK && code[branchStart+1+LINK_SIZE] == OP_VREVERSE && F.eptr != P.eptr {
				rrc = MATCH_NOMATCH
				goto returnSwitch
			}
			if F.eptr > mb.lastUsedPtr {
				mb.lastUsedPtr = F.eptr
			}
			F.eptr = P.eptr
			fallthrough

		// For an atomic group, discard internal backtracking points. We must
		// also ensure that any remaining branches within the top-level of the
		// group are not tried. Do this by adjusting the code pointer within the
		// backtrack frame so that it points to the final branch.
		case OP_ONCE:
			F.backFrame = fi - pi
			for {
				y := GET(code, P.ecode+1)
				if code[P.ecode+y] != OP_ALT {
					break
				}
				P.ecode += y
			}

		// A matching negative assertion returns MATCH, which is turned into
		// NOMATCH at the assertion level. For a variable lookbehind, check its
		// end point.
		case OP_ASSERTBACK_NOT:
			if code[branchStart+1+LINK_SIZE] == OP_VREVERSE && F.eptr != P.eptr {
				rrc = MATCH_NOMATCH
				goto returnSwitch
			}
			rrc = MATCH_MATCH
			goto returnSwitch

		case OP_ASSERT_NOT:
			rrc = MATCH_MATCH
			goto returnSwitch

		// At the end of a script run, apply the script-checking rules.
		case OP_SCRIPT_RUN:
			if !script_run(subj, P.eptr, F.eptr, utf) {
				rrc = MATCH_NOMATCH
				goto returnSwitch
			}

		// Whole-pattern recursion is coded as a recurse into group 0, and is
		// handled with OP_BRA above. Other recursion is handled here.
		case OP_CBRA, OP_CBRAPOS, OP_SCBRA, OP_SCBRAPOS:
			number = uint32(GET2(code, bracode+1+LINK_SIZE))

			// Handle a recursively called group. We reinstate the previous set
			// of captures and then carry on after the recursion call.
			if F.currentRecurse == number {
				copy(F.ovector[:F.offsetTop], P.ovector[:F.offsetTop])
				F.offsetTop = P.offsetTop
				F.captureLast = P.captureLast
				F.currentRecurse = P.currentRecurse
				F.ecode = P.ecode + 1 + LINK_SIZE
				goto nextOp // With next opcode
			}

			// Deal with actual capturing.
			offset = int(number<<1) - 2
			F.captureLast = number
			F.ovector[offset] = uint64(P.eptr)
			F.ovector[offset+1] = uint64(F.eptr)
			if offset >= F.offsetTop {
				F.offsetTop = offset + 2
			}
		} // End actions relating to the starting opcode

		// OP_KETRPOS is a possessive repeating ket. Remember the current
		// position, and return the MATCH_KETRPOS. This makes it possible to do
		// the repeats one at a time from the outer level. This must precede the
		// empty string test - in this case that test is done at the outer level.
		if code[F.ecode] == OP_KETRPOS {
			copyFrameState(P, F)
			rrc = MATCH_KETRPOS
			goto returnSwitch
		}

		// Handle the different kinds of closing brackets. A non-repeating ket
		// needs no special action, just continuing at this level. This also
		// happens for the repeating kets if the group matched no characters, in
		// order to forcibly break infinite loops. Otherwise, the repeating kets
		// try the rest of the pattern or restart from the preceding bracket, in
		// the appropriate order.
		if F.op != OP_KET && (P == nil || F.eptr != P.eptr) {
			if F.op == OP_KETRMIN {
				startEcode = F.ecode + 1 + LINK_SIZE
				F.returnID = RM6
				goto matchRecurse
			}
			// Repeat the maximum number of times (KETRMAX)
			startEcode = bracode
			F.returnID = RM7
			goto matchRecurse
		}
		// Carry on at this level for a non-repeating ket, or after matching an
		// empty string, or after repeating for a maximum number of times.
		F.ecode += 1 + LINK_SIZE
		goto nextOp

	// Start and end of line assertions, not multiline mode (pcre2_match.c:6133).
	case OP_CIRC: // Start of line, unless PCRE2_NOTBOL is set.
		if F.eptr != 0 || mb.moptions&PCRE2_NOTBOL != 0 {
			rrc = MATCH_NOMATCH
			goto returnSwitch
		}
		F.ecode++
		goto nextOp

	case OP_SOD: // Unconditional start of subject
		if F.eptr != 0 {
			rrc = MATCH_NOMATCH
			goto returnSwitch
		}
		F.ecode++
		goto nextOp

	// When PCRE2_NOTEOL is unset, assert before the subject end, or a
	// terminating newline unless PCRE2_DOLLAR_ENDONLY is set.
	case OP_DOLL:
		if mb.moptions&PCRE2_NOTEOL != 0 {
			rrc = MATCH_NOMATCH
			goto returnSwitch
		}
		if mb.poptions&PCRE2_DOLLAR_ENDONLY == 0 {
			goto assertNlOrEos
		}
		fallthrough

	// Unconditional end of subject assertion (\z).
	case OP_EOD:
		if F.eptr < mb.trueEndSubject {
			rrc = MATCH_NOMATCH
			goto returnSwitch
		}
		if mb.partial != 0 {
			mb.hitend = true
			if mb.partial > 1 {
				return PCRE2_ERROR_PARTIAL
			}
		}
		F.ecode++
		goto nextOp

	// End of subject or ending \n assertion (\Z)
	case OP_EODN:
		goto assertNlOrEos

	// Start of subject unless notbol, or after any newline except for one at
	// the very end, unless PCRE2_ALT_CIRCUMFLEX is set (pcre2_match.c:6200).
	case OP_CIRCM:
		if mb.moptions&PCRE2_NOTBOL != 0 && F.eptr == 0 {
			rrc = MATCH_NOMATCH
			goto returnSwitch
		}
		if F.eptr != 0 &&
			((F.eptr == mb.endSubject && mb.poptions&PCRE2_ALT_CIRCUMFLEX == 0) ||
				!mb.wasNewline(F.eptr)) {
			rrc = MATCH_NOMATCH
			goto returnSwitch
		}
		F.ecode++
		goto nextOp

	// Assert before any newline, or before end of subject unless noteol is set.
	case OP_DOLLM:
		if F.eptr < mb.endSubject {
			if !mb.isNewline(F.eptr) {
				if mb.partial != 0 && F.eptr+1 >= mb.endSubject && mb.nltype == NLTYPE_FIXED &&
					mb.nllen == 2 && subj[F.eptr] == mb.nl[0] {
					mb.hitend = true
					if mb.partial > 1 {
						return PCRE2_ERROR_PARTIAL
					}
				}
				rrc = MATCH_NOMATCH
				goto returnSwitch
			}
		} else {
			if mb.moptions&PCRE2_NOTEOL != 0 {
				rrc = MATCH_NOMATCH
				goto returnSwitch
			}
			if mb.scheck(F.eptr) {
				return PCRE2_ERROR_PARTIAL
			}
		}
		F.ecode++
		goto nextOp

	// Start of match assertion (pcre2_match.c:6243).
	case OP_SOM:
		if F.eptr != mb.startOffset {
			rrc = MATCH_NOMATCH
			goto returnSwitch
		}
		F.ecode++
		goto nextOp

	// Reset the start of match point.
	case OP_SET_SOM:
		F.startMatch = F.eptr
		F.ecode++
		goto nextOp

	// Word boundary assertions (pcre2_match.c:6265). Find out if the previous
	// and current characters are "word" characters. Remember the earliest and
	// latest consulted characters.
	case OP_NOT_WORD_BOUNDARY, OP_WORD_BOUNDARY, OP_NOT_UCP_WORD_BOUNDARY, OP_UCP_WORD_BOUNDARY:
		if F.eptr == mb.checkSubject {
			prevIsWord = false
		} else {
			lastptr := F.eptr - 1
			if utf {
				lastptr = BACKCHAR(subj, lastptr)
				fc = GETCHAR(subj, lastptr)
			} else {
				fc = uint32(subj[lastptr])
			}
			if lastptr < mb.startUsedPtr {
				mb.startUsedPtr = lastptr
			}
			if F.op == OP_UCP_WORD_BOUNDARY || F.op == OP_NOT_UCP_WORD_BOUNDARY {
				prevIsWord = ucpIsWord(fc)
			} else {
				prevIsWord = fc < 256 && mb.ctypes[fc]&ctype_word != 0
			}
		}
		// Get status of next character
		if F.eptr >= mb.endSubject {
			if mb.scheck(F.eptr) {
				return PCRE2_ERROR_PARTIAL
			}
			curIsWord = false
		} else {
			nextptr := F.eptr + 1
			if utf {
				for nextptr < mb.endSubject && subj[nextptr]&0xc0 == 0x80 { // FORWARDCHARTEST
					nextptr++
				}
				fc = GETCHAR(subj, F.eptr)
			} else {
				fc = uint32(subj[F.eptr])
			}
			if nextptr > mb.lastUsedPtr {
				mb.lastUsedPtr = nextptr
			}
			if F.op == OP_UCP_WORD_BOUNDARY || F.op == OP_NOT_UCP_WORD_BOUNDARY {
				curIsWord = ucpIsWord(fc)
			} else {
				curIsWord = fc < 256 && mb.ctypes[fc]&ctype_word != 0
			}
		}
		// Now see if the situation is what we want
		{
			opc := code[F.ecode]
			F.ecode++
			if opc == OP_WORD_BOUNDARY || F.op == OP_UCP_WORD_BOUNDARY {
				if curIsWord == prevIsWord {
					rrc = MATCH_NOMATCH
					goto returnSwitch
				}
			} else if curIsWord != prevIsWord {
				rrc = MATCH_NOMATCH
				goto returnSwitch
			}
		}
		goto nextOp

	// Backtracking (*VERB)s, with and without arguments (pcre2_match.c:6340).
	// Note that if the pattern is successfully matched, we do not come back
	// from RMATCH.
	case OP_MARK:
		F.mark = F.ecode + 2
		mb.nomatchMark = F.ecode + 2
		startEcode = F.ecode + int(OP_lengths[code[F.ecode]]) + int(code[F.ecode+1])
		F.returnID = RM12
		goto matchRecurse

	case OP_FAIL:
		rrc = MATCH_NOMATCH
		goto returnSwitch

	// Record the current recursing group number in mb->verb_current_recurse when
	// a backtracking return such as MATCH_COMMIT is given. This enables the
	// recurse processing to catch verbs from within the recursion.
	case OP_COMMIT:
		startEcode = F.ecode + int(OP_lengths[code[F.ecode]])
		F.returnID = RM13
		goto matchRecurse

	case OP_COMMIT_ARG:
		F.mark = F.ecode + 2
		mb.nomatchMark = F.ecode + 2
		startEcode = F.ecode + int(OP_lengths[code[F.ecode]]) + int(code[F.ecode+1])
		F.returnID = RM36
		goto matchRecurse

	case OP_PRUNE:
		startEcode = F.ecode + int(OP_lengths[code[F.ecode]])
		F.returnID = RM14
		goto matchRecurse

	case OP_PRUNE_ARG:
		F.mark = F.ecode + 2
		mb.nomatchMark = F.ecode + 2
		startEcode = F.ecode + int(OP_lengths[code[F.ecode]]) + int(code[F.ecode+1])
		F.returnID = RM15
		goto matchRecurse

	case OP_SKIP:
		startEcode = F.ecode + int(OP_lengths[code[F.ecode]])
		F.returnID = RM16
		goto matchRecurse

	// Note that, for Perl compatibility, SKIP with an argument does NOT set
	// nomatch_mark. When a pattern match ends with a SKIP_ARG for which there
	// was not a matching mark, we have to re-run the match, ignoring the
	// SKIP_ARG that failed and any that precede it.
	case OP_SKIP_ARG:
		mb.skipArgCount++
		if mb.skipArgCount <= mb.ignoreSkipArg {
			F.ecode += int(OP_lengths[code[F.ecode]]) + int(code[F.ecode+1])
			goto nextOp
		}
		startEcode = F.ecode + int(OP_lengths[code[F.ecode]]) + int(code[F.ecode+1])
		F.returnID = RM17
		goto matchRecurse

	// For THEN (and THEN_ARG) we pass back the address of the opcode, so that
	// the branch in which it occurs can be determined.
	case OP_THEN:
		startEcode = F.ecode + int(OP_lengths[code[F.ecode]])
		F.returnID = RM18
		goto matchRecurse

	case OP_THEN_ARG:
		F.mark = F.ecode + 2
		mb.nomatchMark = F.ecode + 2
		startEcode = F.ecode + int(OP_lengths[code[F.ecode]]) + int(code[F.ecode+1])
		F.returnID = RM19
		goto matchRecurse

	//@@MORE_OPS@@

	default:
		return PCRE2_ERROR_INTERNAL
	}
	// Every case of the switch ends in a goto: the "break" and "continue" of the
	// C switch, which repeat the main loop, are "goto nextOp" here.

	// Common code for all repeated single-character matches (pcre2_match.c:1276).
	// tempSize = Loclength, tempSptr[0] = Lstart_eptr, tempSptr[1] = Lcharptr,
	// temp32[0] = Lmin, [1] = Lmax, [2] = Lc, [3] = Loc.
repeatChar:
	if utf {
		F.length = 1
		F.tempSptr[1] = F.ecode
		fc, extra = GETCHARLEN(code, F.ecode)
		F.length += extra
		F.ecode += F.length

		// Handle multi-code-unit character matching, caseful and caseless.
		if F.length > 1 {
			F.tempSize = 0
			if F.op >= OP_STARI {
				if oc := UCD_OTHERCASE(fc); oc != fc {
					F.tempSize = int(ord2utf(oc, F.occu[:]))
				}
			}
			for i = 1; i <= F.temp32[0]; i++ {
				if mb.wideChar(F) {
					continue
				}
				if mb.checkPartial(F.eptr) {
					return PCRE2_ERROR_PARTIAL
				}
				rrc = MATCH_NOMATCH
				goto returnSwitch
			}
			if F.temp32[0] == F.temp32[1] {
				goto nextOp
			}
			if reptype == REPTYPE_MIN {
				goto wideMinLoop
			}
			F.tempSptr[0] = F.eptr
			for i = F.temp32[0]; i < F.temp32[1]; i++ {
				if mb.wideChar(F) {
					continue
				}
				if mb.checkPartial(F.eptr) {
					return PCRE2_ERROR_PARTIAL
				}
				break
			}
			// After \C in UTF mode, Lstart_eptr might be in the middle of a
			// Unicode character. Use <= Lstart_eptr to ensure backtracking
			// doesn't go too far.
			if reptype != REPTYPE_POS {
				goto wideMaxLoop
			}
			goto nextOp // End of repeated wide character handling
		}
		// Length of UTF character is 1. Put it into the preserved variable and
		// fall through to the non-UTF code.
		F.temp32[2] = fc
	} else {
		F.temp32[2] = uint32(code[F.ecode])
		F.ecode++
	}

	if F.op >= OP_STARI { // Caseless comparison
		fc = F.temp32[2]
		if ucp && !utf && fc > 127 {
			F.temp32[3] = UCD_OTHERCASE(fc)
		} else {
			F.temp32[3] = uint32(mb.fcc[fc]) // Lc will be < 128 in UTF-8 mode
		}
	} else {
		F.temp32[3] = F.temp32[2] // caseful: Loc == Lc makes the same test
	}
	for i = 1; i <= F.temp32[0]; i++ {
		if F.eptr >= mb.endSubject {
			if mb.scheck(F.eptr) {
				return PCRE2_ERROR_PARTIAL
			}
			rrc = MATCH_NOMATCH
			goto returnSwitch
		}
		fc = uint32(subj[F.eptr])
		if F.temp32[2] != fc && F.temp32[3] != fc {
			rrc = MATCH_NOMATCH
			goto returnSwitch
		}
		F.eptr++
	}
	if F.temp32[0] == F.temp32[1] {
		goto nextOp
	}
	if reptype == REPTYPE_MIN {
		goto charMinLoop
	}
	F.tempSptr[0] = F.eptr
	for i = F.temp32[0]; i < F.temp32[1]; i++ {
		if F.eptr >= mb.endSubject {
			if mb.scheck(F.eptr) {
				return PCRE2_ERROR_PARTIAL
			}
			break
		}
		fc = uint32(subj[F.eptr])
		if F.temp32[2] != fc && F.temp32[3] != fc {
			break
		}
		F.eptr++
	}
	if reptype != REPTYPE_POS {
		goto charMaxLoop
	}
	goto nextOp

wideMinLoop:
	startEcode = F.ecode
	F.returnID = RM202
	goto matchRecurse
L_RM202:
	if rrc != MATCH_NOMATCH {
		goto returnSwitch
	}
	i = F.temp32[0]
	F.temp32[0]++
	if i >= F.temp32[1] {
		rrc = MATCH_NOMATCH
		goto returnSwitch
	}
	if !mb.wideChar(F) {
		if mb.checkPartial(F.eptr) {
			return PCRE2_ERROR_PARTIAL
		}
		rrc = MATCH_NOMATCH
		goto returnSwitch
	}
	goto wideMinLoop

wideMaxLoop:
	if F.eptr <= F.tempSptr[0] {
		goto nextOp
	}
	startEcode = F.ecode
	F.returnID = RM203
	goto matchRecurse
L_RM203:
	if rrc != MATCH_NOMATCH {
		goto returnSwitch
	}
	F.eptr--
	F.eptr = BACKCHAR(subj, F.eptr)
	goto wideMaxLoop
	// (the C code "break"s out of the switch when the loop ends and so
	// reaches the end of the opcode: goto nextOp, which wideMaxLoop does)

charMinLoop:
	startEcode = F.ecode
	F.returnID = RM25
	goto matchRecurse
L_RM25:
	if rrc != MATCH_NOMATCH {
		goto returnSwitch
	}
	i = F.temp32[0]
	F.temp32[0]++
	if i >= F.temp32[1] {
		rrc = MATCH_NOMATCH
		goto returnSwitch
	}
	if F.eptr >= mb.endSubject {
		if mb.scheck(F.eptr) {
			return PCRE2_ERROR_PARTIAL
		}
		rrc = MATCH_NOMATCH
		goto returnSwitch
	}
	fc = uint32(subj[F.eptr])
	if F.temp32[2] != fc && F.temp32[3] != fc {
		rrc = MATCH_NOMATCH
		goto returnSwitch
	}
	F.eptr++
	goto charMinLoop

charMaxLoop:
	if F.eptr <= F.tempSptr[0] {
		goto nextOp
	}
	startEcode = F.ecode
	F.returnID = RM26
	goto matchRecurse
L_RM26:
	F.eptr--
	if rrc != MATCH_NOMATCH {
		goto returnSwitch
	}
	goto charMaxLoop

	// Common code for all repeated single-character non-matches
	// (pcre2_match.c:1615). The caseful forms use Loc = Lc, so the unified
	// loops need only one test. RM29 is the minimizing return point (C: RM29,
	// RM31, RM204, RM206) and RM30 the maximizing one (RM30, RM32, RM205, RM207).
repeatNotChar:
	fc, F.ecode = GETCHARINCTEST(utf, code, F.ecode)
	F.temp32[2] = fc
	if F.op >= OP_NOTSTARI { // Caseless
		if (utf || ucp) && fc > 127 {
			F.temp32[3] = UCD_OTHERCASE(fc)
		} else {
			F.temp32[3] = uint32(mb.fcc[fc]) // Other case from table
		}
	} else {
		F.temp32[3] = fc
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
		if F.temp32[2] == fc || F.temp32[3] == fc {
			rrc = MATCH_NOMATCH
			goto returnSwitch
		}
	}
	if F.temp32[0] == F.temp32[1] {
		goto nextOp
	}
	if reptype == REPTYPE_MIN {
		goto notMinLoop
	}
	F.tempSptr[0] = F.eptr
	for i = F.temp32[0]; i < F.temp32[1]; i++ {
		if F.eptr >= mb.endSubject {
			if mb.scheck(F.eptr) {
				return PCRE2_ERROR_PARTIAL
			}
			break
		}
		fc, extra = GETCHARLENTEST(utf, subj, F.eptr)
		if F.temp32[2] == fc || F.temp32[3] == fc {
			break
		}
		F.eptr += 1 + extra
	}
	if reptype != REPTYPE_POS {
		goto notMaxLoop
	}
	goto nextOp

notMinLoop:
	startEcode = F.ecode
	F.returnID = RM29
	goto matchRecurse
L_RM29:
	if rrc != MATCH_NOMATCH {
		goto returnSwitch
	}
	i = F.temp32[0]
	F.temp32[0]++
	if i >= F.temp32[1] {
		rrc = MATCH_NOMATCH
		goto returnSwitch
	}
	if F.eptr >= mb.endSubject {
		if mb.scheck(F.eptr) {
			return PCRE2_ERROR_PARTIAL
		}
		rrc = MATCH_NOMATCH
		goto returnSwitch
	}
	fc, F.eptr = GETCHARINCTEST(utf, subj, F.eptr)
	if F.temp32[2] == fc || F.temp32[3] == fc {
		rrc = MATCH_NOMATCH
		goto returnSwitch
	}
	goto notMinLoop

notMaxLoop:
	if F.eptr <= F.tempSptr[0] {
		goto nextOp
	}
	startEcode = F.ecode
	F.returnID = RM30
	goto matchRecurse
L_RM30:
	if rrc != MATCH_NOMATCH {
		goto returnSwitch
	}
	F.eptr--
	if utf {
		F.eptr = BACKCHAR(subj, F.eptr)
	}
	goto notMaxLoop

	// Bit-mapped class: minimizing and maximizing loops (pcre2_match.c:2025).
classMinLoop:
	startEcode = F.ecode
	F.returnID = RM23
	goto matchRecurse
L_RM23:
	if rrc != MATCH_NOMATCH {
		goto returnSwitch
	}
	i = F.temp32[0]
	F.temp32[0]++
	if i >= F.temp32[1] {
		rrc = MATCH_NOMATCH
		goto returnSwitch
	}
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
	goto classMinLoop

classMaxUTF:
	startEcode = F.ecode
	F.returnID = RM201
	goto matchRecurse
L_RM201:
	if rrc != MATCH_NOMATCH {
		goto returnSwitch
	}
	F.eptr--
	if F.eptr+1 <= F.tempSptr[0] { // Tried at original position
		rrc = MATCH_NOMATCH
		goto returnSwitch
	}
	F.eptr = BACKCHAR(subj, F.eptr)
	goto classMaxUTF

classMax:
	if F.eptr < F.tempSptr[0] {
		rrc = MATCH_NOMATCH
		goto returnSwitch
	}
	startEcode = F.ecode
	F.returnID = RM24
	goto matchRecurse
L_RM24:
	if rrc != MATCH_NOMATCH {
		goto returnSwitch
	}
	F.eptr--
	goto classMax

xclassMinLoop:
	startEcode = F.ecode
	F.returnID = RM100
	goto matchRecurse
L_RM100:
	if rrc != MATCH_NOMATCH {
		goto returnSwitch
	}
	i = F.temp32[0]
	F.temp32[0]++
	if i >= F.temp32[1] {
		rrc = MATCH_NOMATCH
		goto returnSwitch
	}
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
	goto xclassMinLoop

xclassMax:
	startEcode = F.ecode
	F.returnID = RM101
	goto matchRecurse
L_RM101:
	if rrc != MATCH_NOMATCH {
		goto returnSwitch
	}
	F.eptr--
	if F.eptr+1 <= F.tempSptr[0] { // Tried at original position
		rrc = MATCH_NOMATCH
		goto returnSwitch
	}
	if utf {
		F.eptr = BACKCHAR(subj, F.eptr)
	}
	goto xclassMax

	// Common code for all repeated character type matches (pcre2_match.c:2705).
	// temp32[2] = Lctype, temp32[3] = Lpropvalue, tempSize = proptype (-1 when
	// the type is not a property; C keeps it in a local), tempSptr[0] =
	// Lstart_eptr.
repeatType:
	F.temp32[2] = uint32(code[F.ecode])
	F.ecode++
	if F.temp32[2] == OP_PROP || F.temp32[2] == OP_NOTPROP {
		F.tempSize = int(code[F.ecode])
		F.temp32[3] = uint32(code[F.ecode+1])
		F.ecode += 2
	} else {
		F.tempSize = -1
	}

	// First, ensure the minimum number of matches are present.
	if F.temp32[0] > 0 {
		var limit uint32 = 256
		if utf {
			limit = 128
		}
		switch {
		case F.tempSize == PT_ANY && F.temp32[2] == OP_NOTPROP:
			rrc = MATCH_NOMATCH
			goto returnSwitch
		case F.tempSize < 0 && F.temp32[2] == OP_ALLANY && !utf:
			if F.eptr > mb.endSubject-int(F.temp32[0]) {
				if mb.scheck(F.eptr) {
					return PCRE2_ERROR_PARTIAL
				}
				rrc = MATCH_NOMATCH
				goto returnSwitch
			}
			F.eptr += int(F.temp32[0])
		case F.tempSize < 0 && F.temp32[2] == OP_ANYBYTE && utf:
			if F.eptr > mb.endSubject-int(F.temp32[0]) {
				rrc = MATCH_NOMATCH
				goto returnSwitch
			}
			F.eptr += int(F.temp32[0])
		default:
			for i = 1; i <= F.temp32[0]; i++ {
				switch mb.typeStep(F, utf, limit) {
				case stepOK:
				case stepNoMatch:
					rrc = MATCH_NOMATCH
					goto returnSwitch
				case stepPartial:
					return PCRE2_ERROR_PARTIAL
				default:
					return PCRE2_ERROR_INTERNAL
				}
			}
		}
	}

	// If Lmin = Lmax we are done. Continue with the main loop.
	if F.temp32[0] == F.temp32[1] {
		goto nextOp
	}

	// If minimizing, we have to test the rest of the pattern before each
	// subsequent match.
	if reptype == REPTYPE_MIN {
		goto typeMinLoop
	}

	// If maximizing, find the longest possible run, then work backwards.
	F.tempSptr[0] = F.eptr // Remember where we started
	if F.tempSize < 0 && F.temp32[2] == OP_EXTUNI {
		for i = F.temp32[0]; i < F.temp32[1]; i++ {
			if F.eptr >= mb.endSubject {
				if mb.scheck(F.eptr) {
					return PCRE2_ERROR_PARTIAL
				}
				break
			}
			fc, F.eptr = GETCHARINCTEST(utf, subj, F.eptr)
			F.eptr = extuni(fc, subj, F.eptr, 0, mb.endSubject, utf, nil)
			if mb.checkPartial(F.eptr) {
				return PCRE2_ERROR_PARTIAL
			}
		}
		if reptype == REPTYPE_POS {
			goto nextOp // No backtracking
		}
		goto extuniMaxLoop
	}
	switch {
	case F.tempSize < 0 && F.temp32[2] == OP_ALLANY && utf && F.temp32[1] == uint32Max:
		F.eptr = mb.endSubject // Unlimited UTF-8 repeat
		if mb.scheck(F.eptr) {
			return PCRE2_ERROR_PARTIAL
		}
	case F.tempSize < 0 && (F.temp32[2] == OP_ANYBYTE || (F.temp32[2] == OP_ALLANY && !utf)):
		fc = F.temp32[1] - F.temp32[0]
		if int64(fc) > int64(mb.endSubject-F.eptr) {
			F.eptr = mb.endSubject
			if mb.scheck(F.eptr) {
				return PCRE2_ERROR_PARTIAL
			}
		} else {
			F.eptr += int(fc)
		}
	default:
		for i = F.temp32[0]; i < F.temp32[1]; i++ {
			adv, part, bad := mb.typeMaxStep(F, utf)
			if part {
				return PCRE2_ERROR_PARTIAL
			}
			if bad {
				return PCRE2_ERROR_INTERNAL
			}
			if !adv {
				break
			}
		}
	}
	// Feptr is now past the end of the maximum run
	if reptype == REPTYPE_POS {
		goto nextOp // No backtracking
	}
	goto typeMaxLoop

	// Minimizing loop (RM208 stands for RM208-RM219, RM223-RM225, RM33 and
	// RM218).
typeMinLoop:
	startEcode = F.ecode
	F.returnID = RM208
	goto matchRecurse
L_RM208:
	if rrc != MATCH_NOMATCH {
		goto returnSwitch
	}
	i = F.temp32[0]
	F.temp32[0]++
	if i >= F.temp32[1] {
		rrc = MATCH_NOMATCH
		goto returnSwitch
	}
	{
		var limit uint32 = 256
		switch mb.typeStep(F, utf, limit) {
		case stepOK:
		case stepNoMatch:
			rrc = MATCH_NOMATCH
			goto returnSwitch
		case stepPartial:
			return PCRE2_ERROR_PARTIAL
		default:
			return PCRE2_ERROR_INTERNAL
		}
	}
	goto typeMinLoop

	// Backtracking over the run (RM221 stands for RM221, RM222 and RM34).
	// After \C in UTF mode, Lstart_eptr might be in the middle of a Unicode
	// character. Use <= Lstart_eptr to ensure backtracking doesn't go too far.
typeMaxLoop:
	if F.eptr <= F.tempSptr[0] {
		goto nextOp
	}
	startEcode = F.ecode
	F.returnID = RM221
	goto matchRecurse
L_RM221:
	if rrc != MATCH_NOMATCH {
		goto returnSwitch
	}
	F.eptr--
	if utf {
		F.eptr = BACKCHAR(subj, F.eptr)
	}
	if F.tempSize < 0 && F.temp32[2] == OP_ANYNL && F.eptr > F.tempSptr[0] &&
		subj[F.eptr] == CHAR_NL && subj[F.eptr-1] == CHAR_CR {
		F.eptr--
	}
	goto typeMaxLoop

	// Backtracking over a run of extended grapheme clusters (pcre2_match.c:4431).
extuniMaxLoop:
	if F.eptr <= F.tempSptr[0] { // At start of char run
		goto nextOp
	}
	startEcode = F.ecode
	F.returnID = RM220
	goto matchRecurse
L_RM220:
	if rrc != MATCH_NOMATCH {
		goto returnSwitch
	}
	// Backtracking over an extended grapheme cluster involves inspecting the
	// previous two characters (if present) to see if a break is permitted
	// between them.
	F.eptr--
	if !utf {
		fc = uint32(subj[F.eptr])
	} else {
		F.eptr = BACKCHAR(subj, F.eptr)
		fc = GETCHAR(subj, F.eptr)
	}
	{
		rgb := UCD_GRAPHBREAK(fc)
		for F.eptr > F.tempSptr[0] {
			fptr := F.eptr - 1
			if !utf {
				fc = uint32(subj[fptr])
			} else {
				fptr = BACKCHAR(subj, fptr)
				fc = GETCHAR(subj, fptr)
			}
			lgb := UCD_GRAPHBREAK(fc)
			if ucp_gbtable[lgb]&(1<<rgb) == 0 {
				break
			}
			F.eptr = fptr
			rgb = uint8(lgb)
		}
	}
	goto extuniMaxLoop

	// Set up for repetition, or handle the non-repeated case of a back
	// reference (pcre2_match.c:5021).
refRepeat:
	switch int(code[F.ecode]) {
	case OP_CRSTAR, OP_CRMINSTAR, OP_CRPLUS, OP_CRMINPLUS, OP_CRQUERY, OP_CRMINQUERY:
		fc = uint32(code[F.ecode]) - OP_CRSTAR
		F.ecode++
		F.temp32[0] = rep_min[fc]
		F.temp32[1] = rep_max[fc]
		reptype = rep_typ[fc]
	case OP_CRRANGE, OP_CRMINRANGE:
		F.temp32[0] = uint32(GET2(code, F.ecode+1))
		F.temp32[1] = uint32(GET2(code, F.ecode+1+IMM2_SIZE))
		reptype = rep_typ[int(code[F.ecode])-OP_CRSTAR]
		if F.temp32[1] == 0 {
			F.temp32[1] = uint32Max // Max 0 => infinity
		}
		F.ecode += 1 + 2*IMM2_SIZE
	default: // No repeat follows
		rrc, length = matchRef(F.tempSize, F.temp32[2] != 0, F, mb)
		if rrc != 0 {
			if rrc > 0 {
				F.eptr = mb.endSubject // Partial match
			}
			if mb.checkPartial(F.eptr) {
				return PCRE2_ERROR_PARTIAL
			}
			rrc = MATCH_NOMATCH
			goto returnSwitch
		}
		F.eptr += length
		goto nextOp
	}

	// Handle repeated back references. If a set group has length zero, just
	// continue with the main loop, because it matches however many times.
	if F.tempSize < F.offsetTop && F.ovector[F.tempSize] != PCRE2_UNSET {
		if F.ovector[F.tempSize] == F.ovector[F.tempSize+1] {
			goto nextOp
		}
	} else { // Group is not set
		if F.temp32[0] == 0 || mb.poptions&PCRE2_MATCH_UNSET_BACKREF != 0 {
			goto nextOp
		}
	}

	// First, ensure the minimum number of matches are present.
	for i = 1; i <= F.temp32[0]; i++ {
		rrc, length = matchRef(F.tempSize, F.temp32[2] != 0, F, mb)
		if rrc != 0 {
			if rrc > 0 {
				F.eptr = mb.endSubject // Partial match
			}
			if mb.checkPartial(F.eptr) {
				return PCRE2_ERROR_PARTIAL
			}
			rrc = MATCH_NOMATCH
			goto returnSwitch
		}
		F.eptr += length
	}

	// If min = max, we are done. They are not both allowed to be zero.
	if F.temp32[0] == F.temp32[1] {
		goto nextOp
	}

	// If minimizing, keep trying and advancing the pointer.
	if reptype == REPTYPE_MIN {
		goto refMinLoop
	}

	// If maximizing, find the longest string and work backwards, as long as the
	// matched lengths for each iteration are the same. tempSptr[0] = Lstart;
	// length (Flength) is the length of the group; samelengths is kept in
	// temp32[3].
	F.temp32[3] = 1
	F.tempSptr[0] = F.eptr // Starting position
	F.length = int(F.ovector[F.tempSize+1] - F.ovector[F.tempSize])
	for i = F.temp32[0]; i < F.temp32[1]; i++ {
		rrc, length = matchRef(F.tempSize, F.temp32[2] != 0, F, mb)
		if rrc != 0 {
			// Can't use CHECK_PARTIAL because we don't want to update Feptr
			// in the soft partial matching case.
			if rrc > 0 && mb.partial != 0 && mb.endSubject > mb.startUsedPtr {
				mb.hitend = true
				if mb.partial > 1 {
					return PCRE2_ERROR_PARTIAL
				}
			}
			break
		}
		if length != F.length {
			F.temp32[3] = 0
		}
		F.eptr += length
	}
	// If the length matched for each repetition is the same as the length of
	// the captured group, we can easily work backwards. This is the normal
	// case.
	if F.temp32[3] != 0 {
		goto refMaxSame
	}
	// The rare case of non-matching lengths. Re-scan the repetition for each
	// iteration. We know that match_ref() will succeed every time.
	F.temp32[1] = i
	goto refMaxDiff

refMinLoop:
	startEcode = F.ecode
	F.returnID = RM20
	goto matchRecurse
L_RM20:
	if rrc != MATCH_NOMATCH {
		goto returnSwitch
	}
	i = F.temp32[0]
	F.temp32[0]++
	if i >= F.temp32[1] {
		rrc = MATCH_NOMATCH
		goto returnSwitch
	}
	rrc, length = matchRef(F.tempSize, F.temp32[2] != 0, F, mb)
	if rrc != 0 {
		if rrc > 0 {
			F.eptr = mb.endSubject // Partial match
		}
		if mb.checkPartial(F.eptr) {
			return PCRE2_ERROR_PARTIAL
		}
		rrc = MATCH_NOMATCH
		goto returnSwitch
	}
	F.eptr += length
	goto refMinLoop

refMaxSame:
	if F.eptr < F.tempSptr[0] {
		rrc = MATCH_NOMATCH
		goto returnSwitch
	}
	startEcode = F.ecode
	F.returnID = RM21
	goto matchRecurse
L_RM21:
	if rrc != MATCH_NOMATCH {
		goto returnSwitch
	}
	F.eptr -= F.length
	goto refMaxSame

refMaxDiff:
	startEcode = F.ecode
	F.returnID = RM22
	goto matchRecurse
L_RM22:
	if rrc != MATCH_NOMATCH {
		goto returnSwitch
	}
	if F.eptr == F.tempSptr[0] { // Failed after minimal repetition
		rrc = MATCH_NOMATCH
		goto returnSwitch
	}
	F.eptr = F.tempSptr[0]
	F.temp32[1]--
	for i = F.temp32[0]; i < F.temp32[1]; i++ {
		_, length = matchRef(F.tempSize, F.temp32[2] != 0, F, mb)
		F.eptr += length
	}
	goto refMaxDiff

L_RM9:
	if rrc != MATCH_NOMATCH {
		goto returnSwitch
	}
	for {
		F.tempSptr[0] += GET(code, F.tempSptr[0]+1)
		if code[F.tempSptr[0]] != OP_ALT {
			break
		}
	}
	F.ecode = F.tempSptr[0] + 1 + LINK_SIZE
	goto nextOp

L_RM10:
	if rrc != MATCH_NOMATCH {
		goto returnSwitch
	}
	F.ecode++
	goto nextOp

posCapture:
	number = uint32(GET2(code, F.ecode+1+LINK_SIZE))
	F.temp32[0] = GF_CAPTURE | number // Remembered frame type
	goto posGroup

posNonCapture:
	F.temp32[0] = GF_NOCAPTURE // Remembered frame type

posGroup:
	F.temp32[1] = 0         // Never matched
	F.tempSptr[1] = F.ecode // Start of this group
posLoop:
	F.tempSptr[0] = F.eptr // Position at group start
	groupFrameType = F.temp32[0]
	startEcode = F.ecode + int(OP_lengths[code[F.ecode]])
	F.returnID = RM8
	goto matchRecurse
L_RM8:
	if rrc == MATCH_KETRPOS {
		F.temp32[1] = 1              // Matched at least once
		if F.eptr == F.tempSptr[0] { // Empty match; skip to end
			for {
				F.ecode += GET(code, F.ecode+1)
				if code[F.ecode] != OP_ALT {
					break
				}
			}
			goto posEnd
		}
		F.ecode = F.tempSptr[1]
		goto posLoop
	}
	// See comment above about handling THEN.
	if rrc == MATCH_THEN {
		next := F.ecode + GET(code, F.ecode+1)
		if mb.verbEcodePtr < next && (code[F.ecode] == OP_ALT || code[next] == OP_ALT) {
			rrc = MATCH_NOMATCH
		}
	}
	if rrc != MATCH_NOMATCH {
		goto returnSwitch
	}
	F.ecode += GET(code, F.ecode+1)
	if code[F.ecode] != OP_ALT {
		goto posEnd
	}
	goto posLoop
posEnd:
	// Success if matched something or zero repeat allowed
	if F.temp32[1] != 0 || F.temp32[2] != 0 {
		F.ecode += 1 + LINK_SIZE
		goto nextOp
	}
	rrc = MATCH_NOMATCH
	goto returnSwitch

braLoop:
	F.tempSptr[0] = F.ecode + GET(code, F.ecode+1)
	if code[F.tempSptr[0]] != OP_ALT {
		// Hit the start of the final branch. Continue at this level.
		F.ecode += int(OP_lengths[code[F.ecode]])
		goto nextOp
	}
	// This is never the final branch. We do not need to test for MATCH_THEN here
	// because this code is not used when there is a THEN in the pattern.
	startEcode = F.ecode + int(OP_lengths[code[F.ecode]])
	F.returnID = RM1
	goto matchRecurse
L_RM1:
	if rrc != MATCH_NOMATCH {
		goto returnSwitch
	}
	F.ecode = F.tempSptr[0]
	goto braLoop

groupLoop:
	groupFrameType = F.temp32[0]
	startEcode = F.ecode + int(OP_lengths[code[F.ecode]])
	F.returnID = RM2
	goto matchRecurse
L_RM2:
	if rrc == MATCH_THEN {
		next := F.ecode + GET(code, F.ecode+1)
		if mb.verbEcodePtr < next && (code[F.ecode] == OP_ALT || code[next] == OP_ALT) {
			rrc = MATCH_NOMATCH
		}
	}
	if rrc != MATCH_NOMATCH {
		goto returnSwitch
	}
	F.ecode += GET(code, F.ecode+1)
	if code[F.ecode] != OP_ALT {
		rrc = MATCH_NOMATCH
		goto returnSwitch
	}
	goto groupLoop

recurseLoop:
	groupFrameType = F.temp32[0]
	startEcode = F.tempSptr[0] + int(OP_lengths[code[F.tempSptr[0]]])
	F.returnID = RM11
	goto matchRecurse
L_RM11:
	{
		next := F.tempSptr[0] + GET(code, F.tempSptr[0]+1)
		// Handle backtracking verbs, which are defined in a range that can
		// easily be tested for. PCRE does not allow THEN, SKIP, PRUNE or COMMIT
		// to escape beyond a recursion; they cause a NOMATCH for the entire
		// recursion.
		if rrc >= MATCH_BACKTRACK_MIN && rrc <= MATCH_BACKTRACK_MAX &&
			mb.verbCurrentRecurse == (F.temp32[0]^GF_RECURSE) {
			if rrc == MATCH_THEN && mb.verbEcodePtr < next &&
				(code[F.tempSptr[0]] == OP_ALT || code[next] == OP_ALT) {
				rrc = MATCH_NOMATCH
			} else {
				rrc = MATCH_NOMATCH
				goto returnSwitch
			}
		}
		// Note that carrying on after (*ACCEPT) in a recursion is handled in
		// the OP_ACCEPT code. Nothing needs to be done here.
		if rrc != MATCH_NOMATCH {
			goto returnSwitch
		}
		F.tempSptr[0] = next
		if code[next] != OP_ALT {
			rrc = MATCH_NOMATCH
			goto returnSwitch
		}
	}
	goto recurseLoop

assertLoop:
	groupFrameType = F.temp32[0]
	startEcode = F.ecode + int(OP_lengths[code[F.ecode]])
	F.returnID = RM3
	goto matchRecurse
L_RM3:
	if rrc == MATCH_ACCEPT {
		N = &frames[assertAcceptFrame]
		copy(F.ovector[:N.offsetTop], N.ovector[:N.offsetTop])
		F.offsetTop = N.offsetTop
		F.mark = N.mark
		goto assertDone
	}
	if rrc != MATCH_NOMATCH && rrc != MATCH_THEN {
		goto returnSwitch
	}
	F.ecode += GET(code, F.ecode+1)
	if code[F.ecode] != OP_ALT {
		rrc = MATCH_NOMATCH
		goto returnSwitch
	}
	goto assertLoop
assertDone:
	for {
		F.ecode += GET(code, F.ecode+1)
		if code[F.ecode] != OP_ALT {
			break
		}
	}
	F.ecode += 1 + LINK_SIZE
	goto nextOp

assertNotLoop:
	groupFrameType = F.temp32[0]
	startEcode = F.ecode + int(OP_lengths[code[F.ecode]])
	F.returnID = RM4
	goto matchRecurse
L_RM4:
	switch rrc {
	case MATCH_ACCEPT, MATCH_MATCH: // Assertion matched, therefore it fails.
		rrc = MATCH_NOMATCH
		goto returnSwitch
	case MATCH_NOMATCH, MATCH_THEN: // Branch failed, try next if present.
		F.ecode += GET(code, F.ecode+1)
		if code[F.ecode] != OP_ALT {
			goto assertNotFailed
		}
		goto assertNotLoop
	case MATCH_COMMIT, MATCH_SKIP, MATCH_PRUNE: // Assertion forced to fail, therefore continue.
		for {
			F.ecode += GET(code, F.ecode+1)
			if code[F.ecode] != OP_ALT {
				break
			}
		}
		goto assertNotFailed
	default: // Pass back any other return
		goto returnSwitch
	}
	// None of the branches have matched or there was a backtrack to (*COMMIT),
	// (*SKIP), (*PRUNE), or (*THEN) in the last branch. This is success for a
	// negative assertion, so carry on.
assertNotFailed:
	F.ecode += 1 + LINK_SIZE
	goto nextOp

condAssertLoop:
	groupFrameType = GF_CONDASSERT | uint32(code[F.ecode])
	startEcode = F.tempSptr[0] + int(OP_lengths[code[F.tempSptr[0]]])
	F.returnID = RM5
	goto matchRecurse
L_RM5:
	switch rrc {
	case MATCH_ACCEPT, MATCH_MATCH: // Save captures
		if rrc == MATCH_ACCEPT {
			N = &frames[assertAcceptFrame]
			copy(F.ovector[:N.offsetTop], N.ovector[:N.offsetTop])
			F.offsetTop = N.offsetTop
		}
		// In the case of a match, the captures have already been put into the
		// current frame.
		condition = F.temp32[0] != 0 // TRUE for positive assertion
	case MATCH_NOMATCH, MATCH_THEN:
		// PCRE doesn't allow the effect of (*THEN) to escape beyond an
		// assertion; it is therefore always treated as NOMATCH.
		F.tempSptr[0] += GET(code, F.tempSptr[0]+1)
		if code[F.tempSptr[0]] == OP_ALT {
			goto condAssertLoop // Try next branch
		}
		condition = F.temp32[0] == 0 // TRUE for negative assertion
	case MATCH_COMMIT, MATCH_SKIP, MATCH_PRUNE: // These force no match without checking other branches.
		condition = F.temp32[0] == 0
	default:
		goto returnSwitch
	}
	// If the condition is true, find the end of the assertion so that advancing
	// past it gets us to the start of the first branch.
	if condition {
		for {
			F.ecode += GET(code, F.ecode+1)
			if code[F.ecode] != OP_ALT {
				break
			}
		}
	}

	// Choose branch according to the condition.
condChoose:
	if condition {
		F.ecode += int(OP_lengths[code[F.ecode]])
	} else {
		F.ecode += F.length
	}
	// If the opcode is OP_SCOND it means we are at a repeated conditional group
	// that might match an empty string. We must therefore descend a level so
	// that the start is remembered for checking. For OP_COND we can just
	// continue at this level.
	if F.op == OP_SCOND {
		groupFrameType = GF_NOCAPTURE | uint32(F.op)
		startEcode = F.ecode
		F.returnID = RM35
		goto matchRecurse
	}
	goto nextOp
L_RM35:
	goto returnSwitch

vrevLoop:
	// Now try matching, moving forward one character on failure, until we reach
	// the minimum back length.
	startEcode = F.ecode + 1 + 2*IMM2_SIZE
	F.returnID = RM37
	goto matchRecurse
L_RM37:
	if rrc != MATCH_NOMATCH {
		goto returnSwitch
	}
	i = F.temp32[1]
	F.temp32[1]--
	if i <= F.temp32[0] {
		rrc = MATCH_NOMATCH
		goto returnSwitch
	}
	F.eptr++
	if utf {
		for F.eptr < mb.endSubject && subj[F.eptr]&0xc0 == 0x80 { // FORWARDCHARTEST
			F.eptr++
		}
	}
	goto vrevLoop

L_RM6:
	if rrc != MATCH_NOMATCH {
		goto returnSwitch
	}
	F.ecode -= GET(code, F.ecode+1)
	goto nextOp

L_RM7:
	if rrc != MATCH_NOMATCH {
		goto returnSwitch
	}
	F.ecode += 1 + LINK_SIZE
	goto nextOp

	// End of subject or ending \n assertion (\Z) (pcre2_match.c:6166).
assertNlOrEos:
	if F.eptr < mb.endSubject && (!mb.isNewline(F.eptr) || F.eptr != mb.endSubject-int(mb.nllen)) {
		if mb.partial != 0 && F.eptr+1 >= mb.endSubject && mb.nltype == NLTYPE_FIXED &&
			mb.nllen == 2 && subj[F.eptr] == mb.nl[0] {
			mb.hitend = true
			if mb.partial > 1 {
				return PCRE2_ERROR_PARTIAL
			}
		}
		rrc = MATCH_NOMATCH
		goto returnSwitch
	}
	// Either at end of string or \n before end.
	if mb.partial != 0 {
		mb.hitend = true
		if mb.partial > 1 {
			return PCRE2_ERROR_PARTIAL
		}
	}
	F.ecode++
	goto nextOp

L_RM12:
	// A return of MATCH_SKIP_ARG means that matching failed at SKIP with an
	// argument, and we must check whether that argument matches this MARK's
	// argument. It is passed back in mb->verb_skip_ptr. If it does match, we
	// return MATCH_SKIP with mb->verb_skip_ptr now pointing to the subject
	// position that corresponds to this mark. Otherwise, pass back the return
	// code unaltered.
	if rrc == MATCH_SKIP_ARG && cstrEqual(code, F.ecode+2, mb.verbSkipCode) {
		mb.verbSkipPtr = F.eptr // Pass back current position
		rrc = MATCH_SKIP
	}
	goto returnSwitch

L_RM13:
	if rrc != MATCH_NOMATCH {
		goto returnSwitch
	}
	mb.verbCurrentRecurse = F.currentRecurse
	rrc = MATCH_COMMIT
	goto returnSwitch

L_RM36:
	if rrc != MATCH_NOMATCH {
		goto returnSwitch
	}
	mb.verbCurrentRecurse = F.currentRecurse
	rrc = MATCH_COMMIT
	goto returnSwitch

L_RM14:
	if rrc != MATCH_NOMATCH {
		goto returnSwitch
	}
	mb.verbCurrentRecurse = F.currentRecurse
	rrc = MATCH_PRUNE
	goto returnSwitch

L_RM15:
	if rrc != MATCH_NOMATCH {
		goto returnSwitch
	}
	mb.verbCurrentRecurse = F.currentRecurse
	rrc = MATCH_PRUNE
	goto returnSwitch

L_RM16:
	if rrc != MATCH_NOMATCH {
		goto returnSwitch
	}
	mb.verbSkipPtr = F.eptr // Pass back current position
	mb.verbCurrentRecurse = F.currentRecurse
	rrc = MATCH_SKIP
	goto returnSwitch

L_RM17:
	if rrc != MATCH_NOMATCH {
		goto returnSwitch
	}
	// Pass back the current skip name and return the special MATCH_SKIP_ARG
	// return code. This will either be caught by a matching MARK, or get to the
	// top, where it causes a rematch with mb->ignore_skip_arg set to the value
	// of mb->skip_arg_count.
	mb.verbSkipCode = F.ecode + 2
	mb.verbCurrentRecurse = F.currentRecurse
	rrc = MATCH_SKIP_ARG
	goto returnSwitch

L_RM18:
	if rrc != MATCH_NOMATCH {
		goto returnSwitch
	}
	mb.verbEcodePtr = F.ecode
	mb.verbCurrentRecurse = F.currentRecurse
	rrc = MATCH_THEN
	goto returnSwitch

L_RM19:
	if rrc != MATCH_NOMATCH {
		goto returnSwitch
	}
	mb.verbEcodePtr = F.ecode
	mb.verbCurrentRecurse = F.currentRecurse
	rrc = MATCH_THEN
	goto returnSwitch

	// OP_END, and OP_ACCEPT outside a recursion (pcre2_match.c:879).
opEnd:
	// Fail for an empty string match if either PCRE2_NOTEMPTY is set, or if
	// PCRE2_NOTEMPTY_ATSTART is set and we have matched at the start of the
	// subject. In both cases, backtracking will then try other alternatives, if
	// any.
	if F.eptr == F.startMatch &&
		(mb.moptions&PCRE2_NOTEMPTY != 0 ||
			(mb.moptions&PCRE2_NOTEMPTY_ATSTART != 0 && F.startMatch == mb.startOffset)) {
		rrc = MATCH_NOMATCH
		goto returnSwitch
	}
	// Fail if PCRE2_ENDANCHORED is set and the end of the match is not the end
	// of the subject. After (*ACCEPT) we fail the entire match (at this
	// position) but backtrack if we've reached the end of the pattern. This
	// applies whether or not we are in a recursion.
	if F.eptr < mb.endSubject && (mb.moptions|mb.poptions)&PCRE2_ENDANCHORED != 0 {
		if F.op == OP_END {
			rrc = MATCH_NOMATCH
			goto returnSwitch
		}
		return MATCH_NOMATCH // (*ACCEPT)
	}
	// We have a successful match of the whole pattern. Record the result and
	// then do a direct return from the function.
	mb.endMatchPtr = F.eptr       // Record where we ended
	mb.endOffsetTop = F.offsetTop // and how many extracts were taken
	mb.mark = F.mark              // and the last success mark
	if F.eptr > mb.lastUsedPtr {
		mb.lastUsedPtr = F.eptr
	}
	md.ovector[0] = uint64(F.startMatch)
	md.ovector[1] = uint64(F.eptr)
	// Set i to the smaller of the sizes of the external and frame ovectors.
	{
		nb := int(topBracket) + 1
		if nb > int(md.oveccount) {
			nb = int(md.oveccount)
		}
		xi = 2 * nb
		copy(md.ovector[2:xi], F.ovector[:xi-2])
		for xi--; xi >= F.offsetTop+2; xi-- {
			md.ovector[xi] = PCRE2_UNSET
		}
	}
	return MATCH_MATCH // Note: NOT RRETURN

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
	case RM1:
		goto L_RM1
	case RM2:
		goto L_RM2
	case RM3:
		goto L_RM3
	case RM4:
		goto L_RM4
	case RM5:
		goto L_RM5
	case RM6:
		goto L_RM6
	case RM7:
		goto L_RM7
	case RM8:
		goto L_RM8
	case RM9:
		goto L_RM9
	case RM10:
		goto L_RM10
	case RM11:
		goto L_RM11
	case RM12:
		goto L_RM12
	case RM13:
		goto L_RM13
	case RM14:
		goto L_RM14
	case RM15:
		goto L_RM15
	case RM16:
		goto L_RM16
	case RM17:
		goto L_RM17
	case RM18:
		goto L_RM18
	case RM19:
		goto L_RM19
	case RM20:
		goto L_RM20
	case RM21:
		goto L_RM21
	case RM22:
		goto L_RM22
	case RM23:
		goto L_RM23
	case RM24:
		goto L_RM24
	case RM25:
		goto L_RM25
	case RM26:
		goto L_RM26
	case RM29:
		goto L_RM29
	case RM30:
		goto L_RM30
	case RM35:
		goto L_RM35
	case RM36:
		goto L_RM36
	case RM37:
		goto L_RM37
	case RM100:
		goto L_RM100
	case RM101:
		goto L_RM101
	case RM201:
		goto L_RM201
	case RM202:
		goto L_RM202
	case RM203:
		goto L_RM203
	case RM208:
		goto L_RM208
	case RM220:
		goto L_RM220
	case RM221:
		goto L_RM221
	default:
		return PCRE2_ERROR_INTERNAL
	}
}
