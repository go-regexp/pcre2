package pcre2

// compileImpl is pcre2_compile() (pcre2_compile.c:10125-10993). The C goto
// labels EXIT, HAD_CB_ERROR, HAD_EARLY_ERROR and HAD_ERROR become the closures
// below; a panic from a bug in the port (an index out of range in a table or
// buffer) is turned into PCRE2_ERROR_INTERNAL so that Compile never panics.
func compileImpl(pattern []byte, options uint32, ccontext *CompileContext) (rcode *Code, rerrorcode int, rerroroffset uint64) {
	defer func() {
		if r := recover(); r != nil {
			rcode, rerrorcode, rerroroffset = nil, PCRE2_ERROR_INTERNAL, 0
		}
	}()

	var cb compile_block
	var has_lookbehind bool
	var re *Code
	patlen := uint64(len(pattern))
	length := uint64(1) // Allow for final END opcode
	var firstcuflags, reqcuflags uint32
	var firstcu, reqcu uint32
	var setflags uint32
	limit_heap := uint32(0xffffffff)
	limit_match := uint32(0xffffffff)
	limit_depth := uint32(0xffffffff)
	newline := 0
	bsr := 0
	errorcode := 0

	failEarly := func(code int, ptr int) (*Code, int, uint64) {
		return nil, code, uint64(ptr)
	}

	// pcre2_compile.c:10187: a NULL pattern is allowed with zero length.
	if pattern == nil {
		pattern = []byte{}
	}

	// PCRE2_MATCH_INVALID_UTF implies UTF
	if options&PCRE2_MATCH_INVALID_UTF != 0 {
		options |= PCRE2_UTF
	}

	if options&^uint32(PUBLIC_COMPILE_OPTIONS) != 0 ||
		ccontext.extraOptions&^uint32(PUBLIC_COMPILE_EXTRA_OPTIONS) != 0 {
		return nil, ERR17, 0
	}
	if options&PCRE2_LITERAL != 0 &&
		(options&^uint32(PUBLIC_LITERAL_COMPILE_OPTIONS) != 0 ||
			ccontext.extraOptions&^uint32(PUBLIC_LITERAL_COMPILE_EXTRA_OPTIONS) != 0) {
		return nil, ERR92, 0
	}

	if patlen > ccontext.maxPatternLength {
		return nil, ERR88, 0
	}

	// ------------ Initialize the "static" compile data --------------
	tables := ccontext.tables
	if tables == nil {
		tables = default_tables[:]
	}
	cb.lcc = tables[lcc_offset:]
	cb.fcc = tables[fcc_offset:]
	cb.cbits = tables[cbits_offset:]
	cb.ctypes = tables[ctypes_offset:]

	cworkspace := make([]byte, COMPILE_WORK_SIZE*4)

	cb.assertDepth = 0
	cb.bracount = 0
	cb.cx = ccontext
	cb.dupnames = false
	cb.endPattern = int(patlen)
	cb.erroroffset = 0
	cb.externalFlags = 0
	cb.externalOptions = options
	cb.groupinfo = make([]uint32, GROUPINFO_DEFAULT_SIZE)
	cb.hadRecurse = false
	cb.lastcapture = 0
	cb.maxLookbehind = 0
	cb.maxVarlookbehind = ccontext.maxVarlookbehind
	cb.nameEntrySize = 0
	cb.nameTable = nil
	cb.namedGroups = make([]named_group, NAMED_GROUP_LIST_SIZE)
	cb.namedGroupListSize = NAMED_GROUP_LIST_SIZE
	cb.namesFound = 0
	cb.parensDepth = 0
	cb.reqVaryopt = 0
	cb.startCode = cworkspace
	cb.startPattern = pattern
	cb.startWorkspace = cworkspace
	cb.workspaceSize = COMPILE_WORK_SIZE

	cb.topBackref = 0
	cb.backrefMap = 0
	for i := 0; i < 10; i++ {
		cb.smallRefOffset[i] = PCRE2_UNSET
	}

	// --------------- Start looking at the pattern ---------------
	ptr := 0 // offset of "ptr" from the pattern start
	skipatstart := 0

	if options&PCRE2_LITERAL == 0 {
		for int(patlen)-skipatstart >= 2 &&
			pattern[skipatstart] == CHAR_LEFT_PARENTHESIS &&
			pattern[skipatstart+1] == CHAR_ASTERISK {
			found := false
			for i := range pso_list {
				p := &pso_list[i]
				if int(patlen)-skipatstart-2 >= int(p.length) &&
					strncmp_c8(pattern[skipatstart+2:], p.name, uint64(p.length)) == 0 {
					skipatstart += int(p.length) + 2
					switch p.typ {
					case PSO_OPT:
						cb.externalOptions |= p.value
					case PSO_FLG:
						setflags |= p.value
					case PSO_NL:
						newline = int(p.value)
						setflags |= PCRE2_NL_SET
					case PSO_BSR:
						bsr = int(p.value)
						setflags |= PCRE2_BSR_SET
					case PSO_LIMM, PSO_LIMD, PSO_LIMH:
						var c uint32
						pp := skipatstart
						if !IS_DIGIT(uint32(cuAt(pattern, pp))) {
							return failEarly(ERR60, pp)
						}
						for IS_DIGIT(uint32(cuAt(pattern, pp))) {
							if c > 0xffffffff/10-1 {
								break
							}
							c = c*10 + (uint32(pattern[pp]) - CHAR_0)
							pp++
						}
						pp++
						if cuAt(pattern, pp-1) != CHAR_RIGHT_PARENTHESIS {
							return failEarly(ERR60, pp)
						}
						if p.typ == PSO_LIMH {
							limit_heap = c
						} else if p.typ == PSO_LIMM {
							limit_match = c
						} else {
							limit_depth = c
						}
						skipatstart += pp - skipatstart
					}
					found = true
					break
				}
			}
			if !found {
				break
			}
		}
	}

	ptr += skipatstart

	utf := cb.externalOptions&PCRE2_UTF != 0
	if utf {
		if options&PCRE2_NEVER_UTF != 0 {
			return failEarly(ERR74, ptr)
		}
		if options&PCRE2_NO_UTF_CHECK == 0 {
			rc, off := valid_utf(pattern, patlen)
			if rc != 0 {
				return nil, rc, off
			}
		}
	}

	ucp := cb.externalOptions&PCRE2_UCP != 0
	if ucp && cb.externalOptions&PCRE2_NEVER_UCP != 0 {
		return failEarly(ERR75, ptr)
	}

	if bsr == 0 {
		bsr = int(ccontext.bsrConvention)
	}
	if newline == 0 {
		newline = int(ccontext.newlineConvention)
	}
	cb.nltype = NLTYPE_FIXED
	switch newline {
	case PCRE2_NEWLINE_CR:
		cb.nllen = 1
		cb.nl[0] = CHAR_CR
	case PCRE2_NEWLINE_LF:
		cb.nllen = 1
		cb.nl[0] = CHAR_NL
	case PCRE2_NEWLINE_NUL:
		cb.nllen = 1
		cb.nl[0] = CHAR_NUL
	case PCRE2_NEWLINE_CRLF:
		cb.nllen = 2
		cb.nl[0] = CHAR_CR
		cb.nl[1] = CHAR_NL
	case PCRE2_NEWLINE_ANY:
		cb.nltype = NLTYPE_ANY
	case PCRE2_NEWLINE_ANYCRLF:
		cb.nltype = NLTYPE_ANYCRLF
	default:
		return failEarly(ERR56, ptr)
	}

	parsed_size_needed := patlen - uint64(skipatstart)
	if ccontext.extraOptions&(PCRE2_EXTRA_MATCH_WORD|PCRE2_EXTRA_MATCH_LINE) != 0 {
		parsed_size_needed += 4
	}
	if options&PCRE2_AUTO_CALLOUT != 0 {
		parsed_size_needed = (parsed_size_needed + 1) * 5
	}
	psize := uint64(PARSED_PATTERN_DEFAULT_SIZE)
	if parsed_size_needed >= PARSED_PATTERN_DEFAULT_SIZE {
		psize = parsed_size_needed + 1
	}
	cb.parsedPattern = make([]uint32, psize)
	cb.parsedPatternEnd = int(parsed_size_needed + 1)

	hadCBError := func() (*Code, int, uint64) {
		return nil, errorcode, cb.erroroffset
	}

	errorcode = parse_regex(pattern, ptr, cb.externalOptions, &has_lookbehind, &cb)
	if errorcode != 0 {
		return hadCBError()
	}

	if has_lookbehind {
		loopcount := 0
		if cb.bracount >= GROUPINFO_DEFAULT_SIZE/2 {
			cb.groupinfo = make([]uint32, 2*(cb.bracount+1))
		}
		for i := range cb.groupinfo {
			cb.groupinfo[i] = 0
		}
		errorcode = check_lookbehinds(0, nil, nil, &cb, &loopcount)
		if errorcode != 0 {
			return hadCBError()
		}
	}

	// First pass: compute the length (pcre2_compile.c:10587).
	cb.erroroffset = patlen
	pptr := 0
	cc := 0
	cworkspace[0] = OP_BRA
	_ = compile_regex(cb.externalOptions, ccontext.extraOptions, cworkspace, &cc, &pptr,
		&errorcode, 0, &firstcu, &firstcuflags, &reqcu, &reqcuflags, nil, nil, &cb, &length)
	if errorcode != 0 {
		return hadCBError()
	}

	if length > MAX_PATTERN_SIZE {
		errorcode = ERR20
		return hadCBError()
	}

	nametab := uint64(cb.namesFound) * uint64(cb.nameEntrySize)
	re_blocksize := uint64(pcre2RealCodeSize) + length + nametab
	if re_blocksize > ccontext.maxPatternCompiledLength {
		errorcode = ERR101
		return hadCBError()
	}

	re = &Code{}
	re.tables = ccontext.tables
	re.blocksize = re_blocksize
	re.magicNumber = MAGIC_NUMBER
	re.compileOptions = options
	re.overallOptions = cb.externalOptions
	re.extraOptions = ccontext.extraOptions
	re.flags = PCRE2_MODE8 | cb.externalFlags | setflags
	re.limitHeap = limit_heap
	re.limitMatch = limit_match
	re.limitDepth = limit_depth
	re.bsrConvention = uint16(bsr)
	re.newlineConvention = uint16(newline)
	re.nameEntrySize = cb.nameEntrySize
	re.nameCount = cb.namesFound
	re.code = make([]byte, nametab+length)

	codestart := re.code[nametab:]

	cb.parensDepth = 0
	cb.assertDepth = 0
	cb.lastcapture = 0
	cb.nameTable = re.code[:nametab]
	cb.startCode = codestart
	cb.reqVaryopt = 0
	cb.hadAccept = false
	cb.hadPruneorskip = false

	if cb.namesFound > 0 {
		for i := uint32(0); i < uint32(cb.namesFound); i++ {
			ng := &cb.namedGroups[i]
			add_name_to_table(&cb, pattern, indexOfName(pattern, ng.name), int(ng.length), uint(ng.number), i)
		}
	}

	pptr = 0
	cc = 0
	codestart[0] = OP_BRA
	regexrc := compile_regex(re.overallOptions, ccontext.extraOptions, codestart, &cc,
		&pptr, &errorcode, 0, &firstcu, &firstcuflags, &reqcu, &reqcuflags, nil,
		nil, &cb, nil)
	if regexrc < 0 {
		re.flags |= PCRE2_MATCH_EMPTY
	}
	re.topBracket = uint16(cb.bracount)
	re.topBackref = uint16(cb.topBackref)
	re.maxLookbehind = uint16(cb.maxLookbehind)

	if cb.hadAccept {
		reqcu = 0
		reqcuflags = REQ_NONE
		re.flags |= PCRE2_HASACCEPT
	}

	codestart[cc] = OP_END
	cc++
	usedlength := uint64(cc)
	if usedlength > length {
		errorcode = ERR23
	} else {
		re.blocksize -= length - usedlength
	}

	// Recursion/subroutine call offsets (pcre2_compile.c:10731).
	const RSCAN_CACHE_SIZE = 8
	if errorcode == 0 && cb.hadRecurse {
		var rc [RSCAN_CACHE_SIZE]recurse_cache
		ccount := 0
		start := RSCAN_CACHE_SIZE

		for rc0 := find_recurse(codestart, 0, utf); rc0 >= 0; rc0 = find_recurse(codestart, rc0+1+LINK_SIZE, utf) {
			rgroup := -1
			groupnumber := GET(codestart, rc0+1)
			if groupnumber == 0 {
				rgroup = 0
			} else {
				search_from := 0
				p := start
				for i := 0; i < ccount; i, p = i+1, (p+1)&7 {
					if groupnumber == rc[p].groupnumber {
						rgroup = rc[p].group
						break
					}
					if groupnumber > rc[p].groupnumber {
						search_from = rc[p].group
					}
				}
				if rgroup < 0 {
					rgroup = find_bracket(codestart, search_from, utf, groupnumber)
					if rgroup < 0 {
						errorcode = ERR53
						break
					}
					start--
					if start < 0 {
						start = RSCAN_CACHE_SIZE - 1
					}
					rc[start].groupnumber = groupnumber
					rc[start].group = rgroup
					if ccount < RSCAN_CACHE_SIZE {
						ccount++
					}
				}
			}
			PUT(codestart, rc0+1, rgroup)
		}
	}

	if errorcode == 0 && re.overallOptions&PCRE2_NO_AUTO_POSSESS == 0 {
		if auto_possessify(codestart, &cb) != 0 {
			errorcode = ERR80
		}
	}

	if errorcode != 0 {
		return hadCBError()
	}

	if re.overallOptions&PCRE2_ANCHORED == 0 && is_anchored(codestart, 0, 0, &cb, 0, false) {
		re.overallOptions |= PCRE2_ANCHORED
	}

	if re.overallOptions&PCRE2_NO_START_OPTIMIZE == 0 {
		minminlength := 0

		if firstcuflags >= REQ_NONE {
			firstcu = find_firstassertedcu(codestart, 0, &firstcuflags, 0)
		}

		if firstcuflags < REQ_NONE {
			re.firstCodeunit = firstcu
			re.flags |= PCRE2_FIRSTSET
			minminlength++

			if firstcuflags&REQ_CASELESS != 0 {
				if firstcu < 128 || (!utf && !ucp && firstcu < 255) {
					if uint32(cb.fcc[firstcu]) != firstcu {
						re.flags |= PCRE2_FIRSTCASELESS
					}
				} else if ucp && !utf && UCD_OTHERCASE(firstcu) != firstcu {
					re.flags |= PCRE2_FIRSTCASELESS
				}
			}
		} else if re.overallOptions&PCRE2_ANCHORED == 0 &&
			is_startline(codestart, 0, 0, &cb, 0, false) {
			re.flags |= PCRE2_STARTLINE
		}

		if reqcuflags < REQ_NONE {
			if re.overallOptions&PCRE2_UTF == 0 ||
				firstcuflags >= REQ_NONE ||
				firstcu&0x80 == 0 ||
				reqcu&0x80 == 0 {
				minminlength++
			}

			if re.overallOptions&PCRE2_ANCHORED == 0 || reqcuflags&REQ_VARY != 0 {
				re.lastCodeunit = reqcu
				re.flags |= PCRE2_LASTSET

				if reqcuflags&REQ_CASELESS != 0 {
					if reqcu < 128 || (!utf && !ucp && reqcu < 255) {
						if uint32(cb.fcc[reqcu]) != reqcu {
							re.flags |= PCRE2_LASTCASELESS
						}
					} else if ucp && !utf && UCD_OTHERCASE(reqcu) != reqcu {
						re.flags |= PCRE2_LASTCASELESS
					}
				}
			}
		}

		if study(re) != 0 {
			errorcode = ERR31
			return hadCBError()
		}

		if re.flags&PCRE2_FIRSTMAPSET != 0 && minminlength == 0 {
			minminlength = 1
		}
		if int(re.minlength) < minminlength {
			re.minlength = uint16(minminlength)
		}
	}

	return re, 0, 0
}

// indexOfName returns the offset of name inside pattern. named_group.name is a
// sub-slice of the pattern (the C pointer); recover the index by capacity.
func indexOfName(pattern, name []byte) int {
	return cap(pattern) - cap(name)
}
