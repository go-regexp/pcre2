// Port of the public function pcre2_match() (pcre2_match.c:6529 to the end,
// PCRE2 10.44, 8-bit, no JIT): argument checks, UTF validation, match block
// and frame store setup, the start-of-match optimizations and the bumpalong
// loop around match(), and the filling of the match data block.
//
// Differences from C that do not change behaviour:
//   - the subject is a slice and the length is len(subject); there is no
//     PCRE2_ZERO_TERMINATED and no NULL subject (a nil slice is the empty
//     string); pointers into the subject are int offsets;
//   - JIT is never used (executable_jit is always nil);
//   - PCRE2_COPY_MATCHED_SUBJECT copies into a new slice; the memctl hooks are
//     gone;
//   - mb.mark and mb.nomatchMark are code offsets (-1 is NULL); md.mark is
//     the mark name slice.
package pcre2

import "bytes"

// notFirstCU is NOT_FIRSTCU(c) for 8-bit code units: a UTF-8 continuation.
func notFirstCU(c byte) bool { return c&0xc0 == 0x80 }

// matchImpl is pcre2_match() (pcre2_match.c:6529).
func matchImpl(code *Code, subject []byte, startoffset uint64, options uint32, md *MatchData, mc *MatchContext) int {
	var (
		rc int
		re = code

		anchored, firstline, hasFirstCU, hasReqCU, startline bool
		startBits                                            *[32]uint8

		// memchr_found_first_cu(2): -1 is NULL.
		memchrFoundFirstCU, memchrFoundFirstCU2 int

		firstCU, firstCU2, reqCU, reqCU2 byte

		bumpalongLimit, endSubject, trueEndSubject, startMatch int
		reqCUPtr, startPartial, matchPartial, newStartMatch    int

		utf, ucp, allowInvalid bool
		fragmentOptions        uint32

		frameSize, heapframesSize uint64

		cb  *CalloutBlock
		amb matchBlock
		mb  = &amb

		defMC MatchContext
	)

	// pcre2_match.c:6595: plausibility checks.
	if options&^xPUBLIC_MATCH_OPTIONS != 0 {
		return PCRE2_ERROR_BADOPTION
	}
	if code == nil || md == nil {
		return PCRE2_ERROR_NULL
	}
	if subject == nil {
		subject = []byte{}
	}
	length := uint64(len(subject))
	if startoffset > length {
		return PCRE2_ERROR_BADOFFSET
	}
	startOffset := int(startoffset)
	startMatch = startOffset
	reqCUPtr = startMatch - 1
	trueEndSubject = int(length)
	endSubject = trueEndSubject

	// pcre2_match.c:6612: magic number and code unit width.
	if re.magicNumber != xMAGIC_NUMBER {
		return PCRE2_ERROR_BADMAGIC
	}
	if re.flags&PCRE2_MODE_MASK != 8/8 {
		return PCRE2_ERROR_BADMODE
	}

	// pcre2_match.c:6635: (*NOTEMPTY) and (*NOTEMPTY_ATSTART) set match-time
	// options. The flag bits are adjacent but not at the option positions.
	if re.flags&PCRE2_NOTEMPTY_SET != 0 {
		options |= PCRE2_NOTEMPTY
	}
	if re.flags&PCRE2_NE_ATST_SET != 0 {
		options |= PCRE2_NOTEMPTY_ATSTART
	}

	// pcre2_match.c:6650: UTF/UCP parameters.
	utf = re.overallOptions&PCRE2_UTF != 0
	allowInvalid = re.overallOptions&PCRE2_MATCH_INVALID_UTF != 0
	ucp = re.overallOptions&PCRE2_UCP != 0

	// pcre2_match.c:6658: partial matching flags as an integer.
	switch {
	case options&PCRE2_PARTIAL_HARD != 0:
		mb.partial = 2
	case options&PCRE2_PARTIAL_SOFT != 0:
		mb.partial = 1
	}

	// pcre2_match.c:6664: partial matching and ENDANCHORED do not mix.
	if mb.partial != 0 && (re.overallOptions|options)&PCRE2_ENDANCHORED != 0 {
		return PCRE2_ERROR_BADOPTION
	}

	// pcre2_match.c:6671: an offset limit needs the compile-time flag.
	if mc != nil && mc.offsetLimit != PCRE2_UNSET && re.overallOptions&PCRE2_USE_OFFSET_LIMIT == 0 {
		return PCRE2_ERROR_BADOFFSETLIMIT
	}

	// pcre2_match.c:6678: drop a copy of the subject kept from a previous call.
	if md.flags&PCRE2_MD_COPIED_SUBJECT != 0 {
		md.flags &^= PCRE2_MD_COPIED_SUBJECT
	}
	md.subject = nil

	// pcre2_match.c:6688: zero the error offset in case of invalid UTF.
	md.startchar = 0

	// pcre2_match.c:6795: lookbehinds may go back to the start of the subject
	// unless a UTF check at a non-zero offset says otherwise.
	mb.checkSubject = 0

	// pcre2_match.c:6814: UTF validity check, and handling of invalid UTF.
	if utf && (options&PCRE2_NO_UTF_CHECK == 0 || allowInvalid) {
		skippedBadStart := false

		// The first code unit must be a valid character start. If invalid UTF
		// is handled, skip such units; otherwise give an error.
		if allowInvalid {
			for startMatch < endSubject && notFirstCU(subject[startMatch]) {
				startMatch++
				skippedBadStart = true
			}
		} else if startMatch < endSubject && notFirstCU(subject[startMatch]) {
			if startoffset > 0 {
				return PCRE2_ERROR_BADUTFOFFSET
			}
			return PCRE2_ERROR_UTF8_ERR20 // Isolated 0x80 byte
		}

		// checkSubject is where UTF checking starts; lookbehinds go back no
		// further.
		mb.checkSubject = startMatch

		// Move back by the maximum lookbehind (in characters), unless bad
		// units were skipped above.
		if !skippedBadStart {
			for i := re.maxLookbehind; i > 0 && mb.checkSubject > 0; i-- {
				mb.checkSubject--
				for mb.checkSubject > 0 && notFirstCU(subject[mb.checkSubject]) {
					mb.checkSubject--
				}
			}
		}

		// Validate the relevant portion of the subject. The loop is for bad
		// UTF in the characters before startMatch scanned for a lookbehind.
		for {
			var eo uint64
			md.rc, eo = valid_utf(subject[mb.checkSubject:], length-uint64(mb.checkSubject))
			md.startchar = eo
			if md.rc == 0 {
				break
			}
			// Make the offset absolute. With invalid UTF handled, end the
			// subject before the bad unit and match "not end of line".
			md.startchar += uint64(mb.checkSubject)
			if !allowInvalid || md.rc > 0 {
				return md.rc
			}
			endSubject = int(md.startchar)

			// If the end precedes startMatch, the invalid UTF is in the extra
			// units reversed over for a lookbehind: advance past the first bad
			// unit, skip invalid starts, and retry with the original end.
			if endSubject < startMatch {
				mb.checkSubject = endSubject + 1
				for mb.checkSubject < startMatch && notFirstCU(subject[mb.checkSubject]) {
					mb.checkSubject++
				}
				endSubject = trueEndSubject
			} else {
				fragmentOptions = PCRE2_NOTEOL
				break
			}
		}
	}

	// pcre2_match.c:6934: a nil match context means the default one.
	if mc == nil {
		defMC = defaultMatchContext()
		mc = &defMC
	}

	anchored = (re.overallOptions|options)&PCRE2_ANCHORED != 0
	firstline = !anchored && re.overallOptions&PCRE2_FIRSTLINE != 0
	startline = re.flags&PCRE2_STARTLINE != 0
	if mc.offsetLimit == PCRE2_UNSET || mc.offsetLimit > length {
		bumpalongLimit = trueEndSubject
	} else {
		bumpalongLimit = int(mc.offsetLimit)
	}

	// pcre2_match.c:6950: the fixed fields of the callout block.
	// (The block is cached in the match data: no allocation per match.)
	if md.calloutBlock == nil {
		md.calloutBlock = new(CalloutBlock)
	}
	cb = md.calloutBlock
	*cb = CalloutBlock{}
	mb.cb = cb
	cb.Version = 2
	cb.Subject = subject
	cb.SubjectLength = uint64(endSubject)
	cb.CalloutFlags = 0

	// pcre2_match.c:6959: the other fields of the match block (moptions is set
	// for each attempt).
	mb.callout = mc.callout
	mb.calloutData = mc.calloutData
	mb.subject = subject
	mb.startOffset = startOffset
	mb.endSubject = endSubject
	mb.trueEndSubject = trueEndSubject
	mb.hasthen = re.flags&PCRE2_HASTHEN != 0
	mb.allowemptypartial = re.maxLookbehind > 0 || re.flags&PCRE2_MATCH_EMPTY != 0
	mb.poptions = re.overallOptions
	mb.ignoreSkipArg = 0
	mb.mark, mb.nomatchMark = -1, -1
	mb.utf = utf

	// pcre2_match.c:6976: the name table and the code that follows it.
	mb.nameTable = re.nameTable()
	mb.nameCount = re.nameCount
	mb.nameEntrySize = re.nameEntrySize
	mb.startCode = re.startCode()

	// pcre2_match.c:6983: \R and newline settings.
	mb.bsrConvention = re.bsrConvention
	mb.nltype = xNLTYPE_FIXED
	switch re.newlineConvention {
	case PCRE2_NEWLINE_CR:
		mb.nllen = 1
		mb.nl[0] = xCHAR_CR
	case PCRE2_NEWLINE_LF:
		mb.nllen = 1
		mb.nl[0] = xCHAR_NL
	case PCRE2_NEWLINE_NUL:
		mb.nllen = 1
		mb.nl[0] = xCHAR_NUL
	case PCRE2_NEWLINE_CRLF:
		mb.nllen = 2
		mb.nl[0] = xCHAR_CR
		mb.nl[1] = xCHAR_NL
	case PCRE2_NEWLINE_ANY:
		mb.nltype = xNLTYPE_ANY
	case PCRE2_NEWLINE_ANYCRLF:
		mb.nltype = xNLTYPE_ANYCRLF
	default:
		return PCRE2_ERROR_INTERNAL
	}

	// pcre2_match.c:7032: the frame size is the fixed part, then the ovector
	// of 2*top_bracket sizes, padded for alignment.
	frameSize = (heapframeOvectorOffset + uint64(re.topBracket)*2*8 + heapframeAlignment - 1) &^ (heapframeAlignment - 1)

	// pcre2_match.c:7039: limits in the pattern override the context only if
	// they are smaller.
	mb.heapLimit = mc.heapLimit
	if re.limitHeap < mb.heapLimit {
		mb.heapLimit = re.limitHeap
	}
	mb.matchLimit = mc.matchLimit
	if re.limitMatch < mb.matchLimit {
		mb.matchLimit = re.limitMatch
	}
	mb.matchLimitDepth = mc.depthLimit
	if re.limitDepth < mb.matchLimitDepth {
		mb.matchLimitDepth = re.limitDepth
	}

	// pcre2_match.c:7053: at least 10 frames and START_FRAMES_SIZE bytes, but
	// no more than the heap limit (in KiB) allows.
	heapframesSize = frameSize * 10
	if heapframesSize < xSTART_FRAMES_SIZE {
		heapframesSize = xSTART_FRAMES_SIZE
	}
	if heapframesSize/1024 > uint64(mb.heapLimit) {
		maxSize := 1024 * uint64(mb.heapLimit)
		if maxSize < frameSize {
			return PCRE2_ERROR_HEAPLIMIT
		}
		heapframesSize = maxSize
	}

	// pcre2_match.c:7065: reuse the frame vector of the match data block if it
	// is large enough (the C byte size is tracked in heapframesSz; the Go
	// slices are created lazily and grow in match()). A store made for a
	// pattern with another ovector stride cannot be reused as it is.
	stride := int(re.topBracket) * 2
	fs, _ := md.heapframes.(*frameStore)
	if md.heapframesSz < heapframesSize {
		fs = nil
		md.heapframesSz = heapframesSize
	}
	if fs == nil || fs.stride != stride {
		n := int(heapframesSize / frameSize)
		if n > 10 {
			n = 10
		}
		if n < 2 {
			n = 2
		}
		fs = newFrameStore(stride, n)
		md.heapframes = fs
	}

	// pcre2_match.c:7082: mark every capture of the first frame unset.
	{
		ov := fs.frames[0].ovector
		for i := range ov {
			ov[i] = PCRE2_UNSET
		}
	}

	// pcre2_match.c:7087: the character tables.
	tables := re.charTables()
	mb.lcc = tables[lcc_offset:]
	mb.fcc = tables[fcc_offset:]
	mb.ctypes = tables[ctypes_offset:]

	// pcre2_match.c:7094: the first code unit to match, or a bitmap of
	// possible first code units.
	if re.flags&PCRE2_FIRSTSET != 0 {
		hasFirstCU = true
		firstCU = byte(re.firstCodeunit)
		firstCU2 = firstCU
		if re.flags&PCRE2_FIRSTCASELESS != 0 {
			firstCU2 = mb.fcc[firstCU]
			if firstCU > 127 && ucp && !utf {
				firstCU2 = byte(xUCD_OTHERCASE(uint32(firstCU)))
			}
		}
	} else if !startline && re.flags&PCRE2_FIRSTMAPSET != 0 {
		startBits = &re.startBitmap
	}

	// pcre2_match.c:7116: the "last known required code unit".
	if re.flags&PCRE2_LASTSET != 0 {
		hasReqCU = true
		reqCU = byte(re.lastCodeunit)
		reqCU2 = reqCU
		if re.flags&PCRE2_LASTCASELESS != 0 {
			reqCU2 = mb.fcc[reqCU]
			if reqCU > 127 && ucp && !utf {
				reqCU2 = byte(xUCD_OTHERCASE(uint32(reqCU)))
			}
		}
	}

	// pcre2_match.c:7140: loop for unanchored repeated matching attempts; for
	// anchored patterns it runs once. Invalid UTF fragments restart here.
fragmentRestart:
	startPartial, matchPartial = -1, -1
	mb.hitend = false
	memchrFoundFirstCU, memchrFoundFirstCU2 = -1, -1

	for {
		// pcre2_match.c:7162: start-of-match optimizations (they can be
		// disabled at compile time).
		if re.overallOptions&PCRE2_NO_START_OPTIMIZE == 0 {
			// pcre2_match.c:7170: with firstline the start of the match is
			// constrained to the first line: temporarily move endSubject to the
			// first newline.
			if firstline {
				t := startMatch
				if utf {
					for t < endSubject && !mb.isNewline(t) {
						t++
						t = acrossChar(subject, t, endSubject)
					}
				} else {
					for t < endSubject && !mb.isNewline(t) {
						t++
					}
				}
				endSubject = t
			}

			if anchored {
				// pcre2_match.c:7192: check the first code unit if one is
				// recorded; it can detect a no match without scanning for the
				// required code unit.
				if hasFirstCU || startBits != nil {
					ok := startMatch < endSubject
					if ok {
						c := subject[startMatch]
						ok = hasFirstCU && (c == firstCU || c == firstCU2)
						if !ok && startBits != nil {
							ok = startBits[c/8]&(1<<(c&7)) != 0
						}
					}
					if !ok {
						rc = xMATCH_NOMATCH
						break
					}
				}
			} else {
				// pcre2_match.c:7221: advance to a unique first code unit.
				if hasFirstCU {
					if firstCU != firstCU2 { // Caseless
						// pcre2_match.c:7242: two searches, with the found
						// positions cached for the next iteration.
						pp1, pp2 := -1, -1
						search := subject[startMatch:endSubject]

						if memchrFoundFirstCU < 0 || startMatch > memchrFoundFirstCU {
							if k := bytes.IndexByte(search, firstCU); k >= 0 {
								pp1 = startMatch + k
								memchrFoundFirstCU = pp1
							} else {
								memchrFoundFirstCU = endSubject
							}
						} else if memchrFoundFirstCU != endSubject {
							pp1 = memchrFoundFirstCU
						}

						if memchrFoundFirstCU2 < 0 || startMatch > memchrFoundFirstCU2 {
							if k := bytes.IndexByte(search, firstCU2); k >= 0 {
								pp2 = startMatch + k
								memchrFoundFirstCU2 = pp2
							} else {
								memchrFoundFirstCU2 = endSubject
							}
						} else if memchrFoundFirstCU2 != endSubject {
							pp2 = memchrFoundFirstCU2
						}

						if pp1 < 0 {
							if pp2 < 0 {
								startMatch = endSubject
							} else {
								startMatch = pp2
							}
						} else if pp2 < 0 || pp1 < pp2 {
							startMatch = pp1
						} else {
							startMatch = pp2
						}
					} else { // pcre2_match.c:7295: the caseful case
						if k := bytes.IndexByte(subject[startMatch:endSubject], firstCU); k >= 0 {
							startMatch += k
						} else {
							startMatch = endSubject
						}
					}

					// pcre2_match.c:7311: no first code unit and the true end
					// of the subject reached: fail, except for partial matching
					// (think /(?<=abc)def/ on "abc") or when FIRSTLINE moved
					// endSubject.
					if mb.partial == 0 && startMatch >= mb.endSubject {
						rc = xMATCH_NOMATCH
						break
					}
				} else if startline {
					// pcre2_match.c:7321: advance to just after a linebreak.
					if startMatch > mb.startOffset {
						if utf {
							for startMatch < endSubject && !mb.wasNewline(startMatch) {
								startMatch++
								startMatch = acrossChar(subject, startMatch, endSubject)
							}
						} else {
							for startMatch < endSubject && !mb.wasNewline(startMatch) {
								startMatch++
							}
						}

						// Just passed a CR with newline ANY/ANYCRLF and now at
						// a LF: advance one more.
						if subject[startMatch-1] == xCHAR_CR &&
							(mb.nltype == xNLTYPE_ANY || mb.nltype == xNLTYPE_ANYCRLF) &&
							startMatch < endSubject && subject[startMatch] == xCHAR_NL {
							startMatch++
						}
					}
				} else if startBits != nil {
					// pcre2_match.c:7356: advance to a non-unique first code
					// unit from the bitmap.
					for startMatch < endSubject {
						c := subject[startMatch]
						if startBits[c/8]&(1<<(c&7)) != 0 {
							break
						}
						startMatch++
					}
					if mb.partial == 0 && startMatch >= mb.endSubject {
						rc = xMATCH_NOMATCH
						break
					}
				}
			} // End first code unit handling

			// pcre2_match.c:7380: restore the fudged endSubject.
			endSubject = mb.endSubject

			// pcre2_match.c:7384: the next two optimizations are disabled for
			// partial matching.
			if mb.partial == 0 {
				// pcre2_match.c:7393: minimum matching length (a lower bound,
				// used as code units).
				if endSubject-startMatch < int(re.minlength) {
					rc = xMATCH_NOMATCH
					break
				}

				// pcre2_match.c:7421: the required code unit must appear in
				// the subject; the search is skipped if it was found beyond
				// the current start earlier. Very long subjects are not
				// searched for anchored patterns.
				p := startMatch
				if hasFirstCU {
					p++
				}
				if hasReqCU && p > reqCUPtr {
					checkLength := endSubject - startMatch

					if checkLength < xREQ_CU_MAX || (!anchored && checkLength < xREQ_CU_MAX*1000) {
						if reqCU != reqCU2 { // Caseless
							pp := p
							k := bytes.IndexByte(subject[pp:endSubject], reqCU)
							if k < 0 {
								k = bytes.IndexByte(subject[pp:endSubject], reqCU2)
							}
							if k < 0 {
								p = endSubject
							} else {
								p = pp + k
							}
						} else {
							k := bytes.IndexByte(subject[p:endSubject], reqCU)
							if k < 0 {
								p = endSubject
							} else {
								p += k
							}
						}

						// Not found: break the bumpalong loop.
						if p >= endSubject {
							rc = xMATCH_NOMATCH
							break
						}

						// Found: remember where, so the next iteration does
						// not search again until startMatch passes it.
						reqCUPtr = p
					}
				}
			}
		}

		// pcre2_match.c:7485: no match if past the bumpalong limit.
		if startMatch > bumpalongLimit {
			rc = xMATCH_NOMATCH
			break
		}

		// pcre2_match.c:7496: run the match. If hitend is set afterwards,
		// remember the first starting point for which a partial match was
		// found.
		cb.StartMatch = uint64(startMatch)
		cb.CalloutFlags |= PCRE2_CALLOUT_STARTMATCH

		mb.startUsedPtr = startMatch
		mb.lastUsedPtr = startMatch
		mb.moptions = options | fragmentOptions
		mb.matchCallCount = 0
		mb.endOffsetTop = 0
		mb.skipArgCount = 0

		rc = match(startMatch, 0, re.topBracket, int(frameSize), md, mb)

		if mb.hitend && startPartial < 0 {
			startPartial = mb.startUsedPtr
			matchPartial = startMatch
		}

		switch rc {
		// pcre2_match.c:7536: MATCH_SKIP_ARG reaching here means that a MARK
		// matching the SKIP's argument was not found; Perl ignores the SKIP
		// entirely, so redo the match at the same point with a flag that
		// forces SKIP with an argument to be ignored.
		case xMATCH_SKIP_ARG:
			newStartMatch = startMatch
			mb.ignoreSkipArg = mb.skipArgCount

		// pcre2_match.c:7544: SKIP passes back the next starting point, but if
		// it is no greater than the match just done, treat it as NOMATCH.
		case xMATCH_SKIP:
			if mb.verbSkipPtr > startMatch {
				newStartMatch = mb.verbSkipPtr
				break
			}
			fallthrough

		// pcre2_match.c:7555: NOMATCH and PRUNE advance by one character; THEN
		// at this level acts like PRUNE. Unset ignore SKIP-with-argument.
		case xMATCH_NOMATCH, xMATCH_PRUNE, xMATCH_THEN:
			mb.ignoreSkipArg = 0
			newStartMatch = startMatch + 1
			if utf {
				newStartMatch = acrossChar(subject, newStartMatch, endSubject)
			}

		// pcre2_match.c:7569: COMMIT disables the bumpalong, otherwise it
		// behaves as NOMATCH.
		case xMATCH_COMMIT:
			rc = xMATCH_NOMATCH
			goto endloop

		// pcre2_match.c:7575: a match or some kind of error.
		default:
			goto endloop
		}

		// pcre2_match.c:7582: "no match at this point" results.
		rc = xMATCH_NOMATCH

		// pcre2_match.c:7588: with FIRSTLINE the match must start at or before
		// the first newline, so stop after failing at a newline.
		if firstline && mb.isNewline(startMatch) {
			break
		}

		startMatch = newStartMatch

		// pcre2_match.c:7597: stop if anchored or past the end of the subject.
		if anchored || startMatch > endSubject {
			break
		}

		// pcre2_match.c:7606: just passed a CR, now at a LF, the pattern has no
		// explicit \r or \n, and newlines may be CRLF/ANY/ANYCRLF: advance one
		// more unit. (A failed *SKIP can return at the same point, hence the
		// first test.)
		if startMatch > startOffset &&
			subject[startMatch-1] == xCHAR_CR &&
			startMatch < endSubject &&
			subject[startMatch] == xCHAR_NL &&
			re.flags&PCRE2_HASCRORLF == 0 &&
			(mb.nltype == xNLTYPE_ANY || mb.nltype == xNLTYPE_ANYCRLF || mb.nllen == 2) {
			startMatch++
		}

		mb.mark = -1 // Reset for start of next match attempt
	}

	// pcre2_match.c:7637: ENDLOOP. Here the match succeeded (wholly or
	// partially), or the pattern is anchored or failed after (*COMMIT), or we
	// are past the end or the bumpalong limit, or FIRSTLINE failed at a
	// newline, or there was an error.
endloop:

	// pcre2_match.c:7647: if endSubject != trueEndSubject we are handling
	// invalid UTF and have just processed a non-terminal fragment. After no
	// match or a partial match carry on with the next fragment.
	if utf && endSubject != trueEndSubject && (rc == xMATCH_NOMATCH || rc == PCRE2_ERROR_PARTIAL) {
		for {
			// Advance past the first bad code unit, then skip invalid
			// character starts.
			startMatch = endSubject + 1
			for startMatch < trueEndSubject && notFirstCU(subject[startMatch]) {
				startMatch++
			}

			// At the end of the subject there is no other non-empty fragment.
			if startMatch >= trueEndSubject {
				rc = xMATCH_NOMATCH // In case it was partial
				matchPartial = -1
				break
			}

			// Check the rest of the subject.
			mb.checkSubject = startMatch
			var eo uint64
			rc, eo = valid_utf(subject[startMatch:], length-uint64(startMatch))
			md.startchar = eo

			if rc == 0 {
				// The rest is valid UTF.
				endSubject = trueEndSubject
				mb.endSubject = endSubject
				fragmentOptions = PCRE2_NOTBOL
				goto fragmentRestart
			} else if rc < 0 {
				// A later UTF error: process the next fragment if non-empty,
				// else let the loop advance.
				endSubject = startMatch + int(md.startchar)
				mb.endSubject = endSubject
				if endSubject > startMatch {
					fragmentOptions = PCRE2_NOTBOL | PCRE2_NOTEOL
					goto fragmentRestart
				}
			}
		}
	}

	// pcre2_match.c:7705: fields that are always returned in the match data.
	md.code = re
	md.mark = mb.markName(mb.mark)
	md.matchedby = PCRE2_MATCHEDBY_INTERPRETER

	// pcre2_match.c:7714: a fully successful match. The return code is the
	// number of captured strings, or 0 if they do not all fit in the ovector.
	// (match() has already filled md.ovector.)
	if rc == xMATCH_MATCH {
		if mb.endOffsetTop >= 2*int(md.oveccount) {
			md.rc = 0
		} else {
			md.rc = mb.endOffsetTop/2 + 1
		}
		md.subjectLength = length
		md.startchar = uint64(startMatch)
		md.leftchar = uint64(mb.startUsedPtr)
		right := mb.endMatchPtr
		if mb.lastUsedPtr > right {
			right = mb.lastUsedPtr
		}
		md.rightchar = uint64(right)
		if options&PCRE2_COPY_MATCHED_SUBJECT != 0 {
			md.subject = append([]byte(nil), subject...)
			md.flags |= PCRE2_MD_COPIED_SUBJECT
		} else {
			md.subject = subject
		}
		return md.rc
	}

	// pcre2_match.c:7741: a partial match, an error, or failure at every
	// permitted start. Any mark data is in nomatchMark.
	md.mark = mb.markName(mb.nomatchMark)

	if rc != xMATCH_NOMATCH && rc != PCRE2_ERROR_PARTIAL {
		// Anything other than nomatch or partial: just the code.
		md.rc = rc
	} else if matchPartial >= 0 {
		// pcre2_match.c:7752: a partial match. With PARTIAL_SOFT the search for
		// a complete match continued and rc is MATCH_NOMATCH here; with
		// PARTIAL_HARD it is already PCRE2_ERROR_PARTIAL.
		md.subject = subject
		md.subjectLength = length
		md.ovector[0] = uint64(matchPartial)
		md.ovector[1] = uint64(endSubject)
		md.startchar = uint64(matchPartial)
		md.leftchar = uint64(startPartial)
		md.rightchar = uint64(endSubject)
		md.rc = PCRE2_ERROR_PARTIAL
	} else {
		// The classic nomatch case.
		md.rc = PCRE2_ERROR_NOMATCH
	}

	return md.rc
}
