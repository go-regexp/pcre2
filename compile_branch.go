// Port of compile_branch() of pcre2_compile.c (PCRE2 10.44, 8-bit, LINK_SIZE 2,
// Unicode support), pcre2_compile.c:5604-8341, and of the structures
// branch_chain (pcre2_intmodedep.h:704) and open_capitem (pcre2_internal.h:1833).
//
// Conventions (see the package doc in internal.go): the pattern is
// cb.startPattern, the parsed pattern is cb.parsedPattern and "pptr" is an
// index into it; the code being built is the slice code with the index cc
// (C: PCRE2_UCHAR *code); a C NULL code pointer is -1.
package pcre2

// branch_chain is a chain of pointers to the currently incomplete branches,
// used to test for left recursion while compiling (pcre2_intmodedep.h:704).
type branch_chain struct {
	outer         *branch_chain
	currentBranch int // index in the code buffer of the current branch
}

// open_capitem is a chain of the capturing groups that are currently open, so
// that OP_CLOSE can be compiled for (*ACCEPT) (pcre2_internal.h:1833).
type open_capitem struct {
	next        *open_capitem
	number      uint16
	assertDepth uint16
}

// compile_branch scans the parsed pattern and compiles one branch into code at
// *codeptr. It is used during the pre-compile phase (lengthptr != nil) as well
// as during the real compile phase. Returns 0 for an error (*errorcodeptr set),
// +1 if the branch must match at least one character, -1 if it may match the
// empty string. (pcre2_compile.c:5635)
func compile_branch(optionsptr *uint32, xoptionsptr *uint32, code []byte, codeptr *int,
	pptrptr *int, errorcodeptr *int, firstcuptr *uint32, firstcuflagsptr *uint32,
	reqcuptr *uint32, reqcuflagsptr *uint32, bcptr *branch_chain,
	open_caps *open_capitem, cb *compile_block, lengthptr *uint64) int {

	bravalue := 0
	okreturn := -1
	group_return := 0
	var repeat_min, repeat_max uint32
	var greedy_default, greedy_non_default uint32
	var repeat_type, op_type uint32
	options := *optionsptr
	xoptions := *xoptionsptr
	var firstcu, reqcu uint32
	var zeroreqcu, zerofirstcu uint32
	var escape uint32
	pp := cb.parsedPattern
	pptr := *pptrptr
	var meta, meta_arg uint32
	var firstcuflags, reqcuflags uint32
	var zeroreqcuflags, zerofirstcuflags uint32
	var req_caseopt, reqvary, tempreqvary uint32
	var offset uint64
	var length_prevgroup uint64
	cc := *codeptr
	last_code := cc
	orig_code := cc
	tempcode := 0
	previous := -1
	var op_previous byte
	groupsetfirstcu := false
	had_accept := false
	matched_char := false
	previous_matched_char := false
	reset_caseful := false
	cbits := cb.cbits
	var classbits [32]byte

	utf := options&PCRE2_UTF != 0
	ucp := options&PCRE2_UCP != 0

	// Helper variables for OP_XCLASS.
	class_uchardata := 0
	xclass := false
	class_uchardata_base := 0

	greedy_default = b2u32(options&PCRE2_UNGREEDY != 0)
	greedy_non_default = greedy_default ^ 1

	firstcu, reqcu, zerofirstcu, zeroreqcu = 0, 0, 0, 0
	firstcuflags, reqcuflags, zerofirstcuflags, zeroreqcuflags = REQ_UNSET, REQ_UNSET, REQ_UNSET, REQ_UNSET

	if options&PCRE2_CASELESS != 0 {
		req_caseopt = REQ_CASELESS
	}

	emit := func(b uint32) { code[cc] = byte(b); cc++ }
	// GETPLUSOFFSET and SKIPOFFSET for 64-bit PCRE2_SIZE (pcre2_compile.c:103).
	getPlusOffset := func() {
		offset = uint64(pp[pptr+1])<<32 | uint64(pp[pptr+2])
		pptr += 2
	}

	// Per-item variables (C declares them inside the loop).
	var xclass_has_prop bool
	var negate_class, should_flip_negation, match_all_or_no_wide_chars bool
	var possessive_quantifier, note_group_empty bool
	var class_has_8bitchar int
	var mclength, skipunits uint32
	var subreqcu, subfirstcu uint32
	var groupnumber uint32
	var verbarglen, verbculen uint32
	var subreqcuflags, subfirstcuflags uint32
	var oc *open_capitem
	var mcbuffer [8]byte
	// Temporaries of the nested blocks.
	var dcount, dindex int
	var di uint32
	var dname int
	var dlength uint32
	var is_dupname bool
	var prop_type, prop_value int
	var oldcode int
	var rlen int
	var bralink, brazeroptr int

mainloop:
	for ; ; pptr++ {
		meta = META_CODE(pp[pptr])
		meta_arg = META_DATA(pp[pptr])

		// In the pre-compile phase, accumulate the length used for the previous
		// cycle of this loop, unless the next item is a quantifier.
		if lengthptr != nil {
			if uint64(cc) > cb.workspaceSize-WORK_SIZE_SAFETY_MARGIN {
				if uint64(cc) >= cb.workspaceSize {
					*errorcodeptr = ERR52
				} else {
					*errorcodeptr = ERR86
				}
				return 0
			}
			if cc < last_code {
				cc = last_code
			}
			if meta < META_ASTERISK || meta > META_MINMAX_QUERY {
				if uint64(OFLOW_MAX)-*lengthptr < uint64(cc-orig_code) {
					*errorcodeptr = ERR20
					return 0
				}
				*lengthptr += uint64(cc - orig_code)
				if *lengthptr > MAX_PATTERN_SIZE {
					*errorcodeptr = ERR20
					return 0
				}
				cc = orig_code
			}
			last_code = cc
		}

		if meta < META_ASTERISK || meta > META_MINMAX_QUERY {
			previous = cc
			if matched_char && !had_accept {
				okreturn = 1
			}
		}

		previous_matched_char = matched_char
		matched_char = false
		note_group_empty = false
		skipunits = 0

		switch meta {
		// The branch terminates at pattern end or | or ). (5816)
		case META_END, META_ALT, META_KET:
			*firstcuptr = firstcu
			*firstcuflagsptr = firstcuflags
			*reqcuptr = reqcu
			*reqcuflagsptr = reqcuflags
			*codeptr = cc
			*pptrptr = pptr
			return okreturn

		// Single-character metacharacters. (5832)
		case META_CIRCUMFLEX:
			if options&PCRE2_MULTILINE != 0 {
				if firstcuflags == REQ_UNSET {
					firstcuflags = REQ_NONE
					zerofirstcuflags = REQ_NONE
				}
				emit(OP_CIRCM)
			} else {
				emit(OP_CIRC)
			}
			continue mainloop

		case META_DOLLAR:
			if options&PCRE2_MULTILINE != 0 {
				emit(OP_DOLLM)
			} else {
				emit(OP_DOLL)
			}
			continue mainloop

		case META_DOT:
			matched_char = true
			if firstcuflags == REQ_UNSET {
				firstcuflags = REQ_NONE
			}
			zerofirstcu = firstcu
			zerofirstcuflags = firstcuflags
			zeroreqcu = reqcu
			zeroreqcuflags = reqcuflags
			if options&PCRE2_DOTALL != 0 {
				emit(OP_ALLANY)
			} else {
				emit(OP_ANY)
			}
			continue mainloop

		// Empty classes. (5866)
		case META_CLASS_EMPTY, META_CLASS_EMPTY_NOT:
			matched_char = true
			if meta == META_CLASS_EMPTY_NOT {
				emit(OP_ALLANY)
			} else {
				emit(OP_FAIL)
			}
			if firstcuflags == REQ_UNSET {
				firstcuflags = REQ_NONE
			}
			zerofirstcu = firstcu
			zerofirstcuflags = firstcuflags
			continue mainloop

		// Non-empty character class. (5889)
		case META_CLASS_NOT, META_CLASS:
			matched_char = true
			negate_class = meta == META_CLASS_NOT

			// One-character class optimization.
			if pp[pptr+1] < META_END && pp[pptr+2] == META_CLASS_END {
				c := pp[pptr+1]
				pptr += 2
				if meta == META_CLASS {
					meta = c
					goto NORMAL_CHAR_SET
				}

				// Negative one-character class.
				zeroreqcu = reqcu
				zeroreqcuflags = reqcuflags
				if firstcuflags == REQ_UNSET {
					firstcuflags = REQ_NONE
				}
				zerofirstcu = firstcu
				zerofirstcuflags = firstcuflags

				if d := UCD_CASESET(c); (utf || ucp) && options&PCRE2_CASELESS != 0 &&
					d != 0 &&
					(xoptions&PCRE2_EXTRA_CASELESS_RESTRICT == 0 ||
						ucd_caseless_sets[d] > 127) {
					emit(OP_NOTPROP)
					emit(PT_CLIST)
					emit(uint32(d))
					continue mainloop
				}
				if options&PCRE2_CASELESS != 0 {
					emit(OP_NOTI)
				} else {
					emit(OP_NOT)
				}
				cc += PUTCHAR(utf, c, code[cc:])
				continue mainloop
			}

			// Exactly two characters in a positive class that are case partners.
			if meta == META_CLASS && pp[pptr+1] < META_END && pp[pptr+2] < META_END &&
				pp[pptr+3] == META_CLASS_END {
				c := pp[pptr+1]
				if UCD_CASESET(c) == 0 ||
					(xoptions&PCRE2_EXTRA_CASELESS_RESTRICT != 0 && c < 128 && pp[pptr+2] < 128) {
					var d uint32
					if (utf || ucp) && c > 127 {
						d = UCD_OTHERCASE(c)
					} else if c > 255 {
						d = c
					} else {
						d = uint32(cb.fcc[c])
					}
					if c != d && pp[pptr+2] == d {
						pptr += 3
						meta = c
						if options&PCRE2_CASELESS == 0 {
							reset_caseful = true
							options |= PCRE2_CASELESS
							req_caseopt = REQ_CASELESS
						}
						goto CLASS_CASELESS_CHAR
					}
				}
			}

			should_flip_negation = false
			match_all_or_no_wide_chars = false

			xclass = false
			class_uchardata = cc + LINK_SIZE + 2
			class_uchardata_base = class_uchardata

			class_has_8bitchar = 0
			xclass_has_prop = false

			classbits = [32]byte{}

			// Process items until META_CLASS_END is reached. (6030)
			for {
				isLiteral := false
				pptr++
				meta = pp[pptr]
				if meta == META_CLASS_END {
					break
				}

				// POSIX classes.
				if meta == META_POSIX || meta == META_POSIX_NEG {
					local_negate := meta == META_POSIX_NEG
					pptr++
					posix_class := int(pp[pptr])
					var pbits [32]byte

					should_flip_negation = local_negate

					if options&PCRE2_CASELESS != 0 && posix_class <= 2 {
						posix_class = 0
					}

					if options&PCRE2_UCP != 0 && xoptions&PCRE2_EXTRA_ASCII_POSIX == 0 {
						switch posix_class {
						case PC_GRAPH, PC_PRINT, PC_PUNCT:
							if local_negate {
								code[class_uchardata] = XCL_NOTPROP
							} else {
								code[class_uchardata] = XCL_PROP
							}
							class_uchardata++
							switch posix_class {
							case PC_GRAPH:
								code[class_uchardata] = PT_PXGRAPH
							case PC_PRINT:
								code[class_uchardata] = PT_PXPRINT
							default:
								code[class_uchardata] = PT_PXPUNCT
							}
							class_uchardata++
							code[class_uchardata] = 0
							class_uchardata++
							xclass_has_prop = true
							goto CONTINUE_CLASS

						default:
							if utf {
								match_all_or_no_wide_chars = match_all_or_no_wide_chars || local_negate
							}
						}
					}

					posix_class *= 3
					copy(pbits[:], cbits[posix_class_maps[posix_class]:posix_class_maps[posix_class]+32])

					taboffset := posix_class_maps[posix_class+1]
					tabopt := posix_class_maps[posix_class+2]

					if taboffset >= 0 {
						if tabopt >= 0 {
							for i := 0; i < 32; i++ {
								pbits[i] |= cbits[i+taboffset]
							}
						} else {
							for i := 0; i < 32; i++ {
								pbits[i] &^= cbits[i+taboffset]
							}
						}
					}

					if tabopt < 0 {
						tabopt = -tabopt
					}
					if tabopt == 1 {
						pbits[1] &^= 0x3c
					} else if tabopt == 2 {
						pbits[11] &= 0x7f
					}

					if local_negate {
						for i := 0; i < 32; i++ {
							classbits[i] |= ^pbits[i]
						}
					} else {
						for i := 0; i < 32; i++ {
							classbits[i] |= pbits[i]
						}
					}

					class_has_8bitchar = 1
					goto CONTINUE_CLASS
				}

				if meta == META_BIGVALUE {
					pptr++
					meta = pp[pptr]
					isLiteral = true // CLASS_LITERAL
				}

				if !isLiteral && meta >= META_END {
					if META_CODE(meta) != META_ESCAPE {
						*errorcodeptr = ERR89
						return 0
					}
					escape = META_DATA(meta)

					class_has_8bitchar++

					switch escape {
					case ESC_d:
						for i := 0; i < 32; i++ {
							classbits[i] |= cbits[i+cbit_digit]
						}
					case ESC_D:
						should_flip_negation = true
						for i := 0; i < 32; i++ {
							classbits[i] |= ^cbits[i+cbit_digit]
						}
					case ESC_w:
						for i := 0; i < 32; i++ {
							classbits[i] |= cbits[i+cbit_word]
						}
					case ESC_W:
						should_flip_negation = true
						for i := 0; i < 32; i++ {
							classbits[i] |= ^cbits[i+cbit_word]
						}
					case ESC_s:
						for i := 0; i < 32; i++ {
							classbits[i] |= cbits[i+cbit_space]
						}
					case ESC_S:
						should_flip_negation = true
						for i := 0; i < 32; i++ {
							classbits[i] |= ^cbits[i+cbit_space]
						}
					case ESC_h:
						add_list_to_class(classbits[:], code, &class_uchardata,
							options&^PCRE2_CASELESS, xoptions, cb, hspace_list, NOTACHAR)
					case ESC_H:
						add_not_list_to_class(classbits[:], code, &class_uchardata,
							options&^PCRE2_CASELESS, xoptions, cb, hspace_list)
					case ESC_v:
						add_list_to_class(classbits[:], code, &class_uchardata,
							options&^PCRE2_CASELESS, xoptions, cb, vspace_list, NOTACHAR)
					case ESC_V:
						add_not_list_to_class(classbits[:], code, &class_uchardata,
							options&^PCRE2_CASELESS, xoptions, cb, vspace_list)
					case ESC_p, ESC_P:
						pptr++
						ptype := pp[pptr] >> 16
						pdata := pp[pptr] & 0xffff
						if escape == ESC_p {
							code[class_uchardata] = XCL_PROP
						} else {
							code[class_uchardata] = XCL_NOTPROP
						}
						class_uchardata++
						code[class_uchardata] = byte(ptype)
						class_uchardata++
						code[class_uchardata] = byte(pdata)
						class_uchardata++
						xclass_has_prop = true
						class_has_8bitchar-- // Undo!
					}
					goto CONTINUE_CLASS
				} else {
					// A literal character, possibly a range. (6267)
					c := meta
					d := meta

					if c == CHAR_CR || c == CHAR_NL {
						cb.externalFlags |= PCRE2_HASCRORLF
					}

					if pp[pptr+1] == META_RANGE_LITERAL || pp[pptr+1] == META_RANGE_ESCAPED {
						pptr += 2
						d = pp[pptr]
						if d == META_BIGVALUE {
							pptr++
							d = pp[pptr]
						}
						if d == CHAR_CR || d == CHAR_NL {
							cb.externalFlags |= PCRE2_HASCRORLF
						}
						class_has_8bitchar += int(add_to_class(classbits[:], code, &class_uchardata,
							options, xoptions, cb, c, d))
						goto CONTINUE_CLASS
					}

					class_has_8bitchar += int(add_to_class(classbits[:], code, &class_uchardata,
						options, xoptions, cb, meta, meta))
				}

			CONTINUE_CLASS:
				// If any wide characters or Unicode properties have been
				// encountered, set xclass = TRUE. (6359)
				if class_uchardata > class_uchardata_base {
					xclass = true
					if lengthptr != nil {
						*lengthptr += uint64(class_uchardata - class_uchardata_base)
						class_uchardata = class_uchardata_base
					}
				}
			}

			// No first char for a class, whatever the repeat count. (6377)
			if firstcuflags == REQ_UNSET {
				firstcuflags = REQ_NONE
			}
			zerofirstcu = firstcu
			zerofirstcuflags = firstcuflags
			zeroreqcu = reqcu
			zeroreqcuflags = reqcuflags

			// Extended class. (6407)
			if xclass && (options&PCRE2_UCP != 0 || xclass_has_prop || !should_flip_negation) {
				if match_all_or_no_wide_chars ||
					(utf && should_flip_negation && !negate_class && options&PCRE2_UCP == 0) {
					code[class_uchardata] = XCL_RANGE
					class_uchardata++
					class_uchardata += int(ord2utf(0x100, code[class_uchardata:]))
					class_uchardata += int(ord2utf(MAX_UTF_CODE_POINT, code[class_uchardata:]))
				}
				code[class_uchardata] = XCL_END
				class_uchardata++
				code[cc] = OP_XCLASS
				cc++
				cc += LINK_SIZE
				if negate_class {
					code[cc] = XCL_NOT
				} else {
					code[cc] = 0
				}
				if xclass_has_prop {
					code[cc] |= XCL_HASPROP
				}

				if class_has_8bitchar > 0 {
					code[cc] |= XCL_MAP
					cc++
					copy(code[cc+32:], code[cc:class_uchardata])
					if negate_class && !xclass_has_prop {
						for i := 0; i < 32; i++ {
							classbits[i] = 255 ^ classbits[i]
						}
					}
					copy(code[cc:cc+32], classbits[:])
					cc = class_uchardata + 32
				} else {
					cc = class_uchardata
				}

				PUT(code, previous+1, cc-previous)
				continue mainloop
			}

			if negate_class == should_flip_negation {
				emit(OP_CLASS)
			} else {
				emit(OP_NCLASS)
			}
			if lengthptr == nil {
				if negate_class {
					for i := 0; i < 32; i++ {
						classbits[i] = 255 ^ classbits[i]
					}
				}
				copy(code[cc:cc+32], classbits[:])
			}
			cc += 32
			continue mainloop

		// Verbs. (6496)
		case META_ACCEPT:
			cb.hadAccept = true
			had_accept = true
			for oc = open_caps; oc != nil && uint16(oc.assertDepth) >= cb.assertDepth; oc = oc.next {
				if lengthptr != nil {
					*lengthptr += 1 + IMM2_SIZE
				} else {
					emit(OP_CLOSE)
					cc = PUT2INC(code, cc, int(oc.number))
				}
			}
			if cb.assertDepth > 0 {
				emit(OP_ASSERT_ACCEPT)
			} else {
				emit(OP_ACCEPT)
			}
			if firstcuflags == REQ_UNSET {
				firstcuflags = REQ_NONE
			}
			continue mainloop

		case META_PRUNE, META_SKIP:
			cb.hadPruneorskip = true
			emit(verbops[(meta-META_MARK)>>16])
			continue mainloop

		case META_COMMIT, META_FAIL:
			emit(verbops[(meta-META_MARK)>>16])
			continue mainloop

		case META_THEN:
			cb.externalFlags |= PCRE2_HASTHEN
			emit(OP_THEN)
			continue mainloop

		case META_THEN_ARG:
			cb.externalFlags |= PCRE2_HASTHEN
			goto VERB_ARG

		case META_PRUNE_ARG, META_SKIP_ARG:
			cb.hadPruneorskip = true
			goto VERB_ARG

		case META_MARK, META_COMMIT_ARG:
			goto VERB_ARG

		// Options change. (6581)
		case META_OPTIONS:
			pptr++
			options = pp[pptr]
			*optionsptr = options
			pptr++
			xoptions = pp[pptr]
			*xoptionsptr = xoptions
			greedy_default = b2u32(options&PCRE2_UNGREEDY != 0)
			greedy_non_default = greedy_default ^ 1
			if options&PCRE2_CASELESS != 0 {
				req_caseopt = REQ_CASELESS
			} else {
				req_caseopt = 0
			}
			continue mainloop

		// Conditional subpatterns. (6597)
		case META_COND_RNUMBER, META_COND_NAME, META_COND_RNAME:
			bravalue = OP_COND
			pptr++
			dlength = pp[pptr]
			getPlusOffset()
			dname = int(offset)
			{
				ngi := 0
				for di = 0; di < uint32(cb.namesFound); di, ngi = di+1, ngi+1 {
					ng := &cb.namedGroups[ngi]
					if dlength == uint32(ng.length) &&
						strncmp(cb.startPattern[dname:], ng.name, uint64(dlength)) == 0 {
						if ng.isdup == 0 {
							if meta == META_COND_RNAME {
								code[cc+1+LINK_SIZE] = OP_RREF
							} else {
								code[cc+1+LINK_SIZE] = OP_CREF
							}
							PUT2(code, cc+2+LINK_SIZE, int(ng.number))
							if ng.number > cb.topBackref {
								cb.topBackref = ng.number
							}
							skipunits = 1 + IMM2_SIZE
							goto GROUP_PROCESS_NOTE_EMPTY
						}
						break // Found a duplicated name
					}
				}
			}

			// Name not found: a bad reference, unless R<digits>.
			if di >= uint32(cb.namesFound) {
				groupnumber = 0
				if meta == META_COND_RNUMBER {
					for di = 1; di < dlength; di++ {
						groupnumber = groupnumber*10 + uint32(cb.startPattern[dname+int(di)]) - CHAR_0
						if groupnumber > MAX_GROUP_NUMBER {
							*errorcodeptr = ERR61
							cb.erroroffset = offset + uint64(di)
							return 0
						}
					}
				}

				if meta != META_COND_RNUMBER || groupnumber > cb.bracount {
					*errorcodeptr = ERR15
					cb.erroroffset = offset
					return 0
				}

				if groupnumber == 0 {
					groupnumber = RREF_ANY
				}
				code[cc+1+LINK_SIZE] = OP_RREF
				PUT2(code, cc+2+LINK_SIZE, int(groupnumber))
				skipunits = 1 + IMM2_SIZE
				goto GROUP_PROCESS_NOTE_EMPTY
			}

			// A duplicated name was found.
			if meta == META_COND_RNAME {
				code[cc+1+LINK_SIZE] = OP_RREF
			} else {
				code[cc+1+LINK_SIZE] = OP_CREF
			}

			dcount = 0
			dindex = 0
			if lengthptr == nil && !find_dupname_details(cb.startPattern, dname, dlength, &dindex,
				&dcount, errorcodeptr, cb) {
				return 0
			}

			code[cc+1+LINK_SIZE]++
			skipunits = 1 + 2*IMM2_SIZE
			PUT2(code, cc+2+LINK_SIZE, dindex)
			PUT2(code, cc+2+LINK_SIZE+IMM2_SIZE, dcount)
			goto GROUP_PROCESS_NOTE_EMPTY

		// The DEFINE condition is always false. (6700)
		case META_COND_DEFINE:
			bravalue = OP_COND
			getPlusOffset()
			code[cc+1+LINK_SIZE] = OP_DEFINE
			skipunits = 1
			goto GROUP_PROCESS

		case META_COND_NUMBER:
			bravalue = OP_COND
			getPlusOffset()
			pptr++
			groupnumber = pp[pptr]
			if groupnumber > cb.bracount {
				*errorcodeptr = ERR15
				cb.erroroffset = offset
				return 0
			}
			if groupnumber > cb.topBackref {
				cb.topBackref = groupnumber
			}
			offset -= 2 // Point at initial ( for too many branches error
			code[cc+1+LINK_SIZE] = OP_CREF
			skipunits = 1 + IMM2_SIZE
			PUT2(code, cc+2+LINK_SIZE, int(groupnumber))
			goto GROUP_PROCESS_NOTE_EMPTY

		case META_COND_VERSION:
			bravalue = OP_COND
			if pp[pptr+1] > 0 {
				if PCRE2_MAJOR > pp[pptr+2] || (PCRE2_MAJOR == pp[pptr+2] && PCRE2_MINOR >= pp[pptr+3]) {
					code[cc+1+LINK_SIZE] = OP_TRUE
				} else {
					code[cc+1+LINK_SIZE] = OP_FALSE
				}
			} else {
				if PCRE2_MAJOR == pp[pptr+2] && PCRE2_MINOR == pp[pptr+3] {
					code[cc+1+LINK_SIZE] = OP_TRUE
				} else {
					code[cc+1+LINK_SIZE] = OP_FALSE
				}
			}
			skipunits = 1
			pptr += 3
			goto GROUP_PROCESS_NOTE_EMPTY

		case META_COND_ASSERT:
			bravalue = OP_COND
			goto GROUP_PROCESS_NOTE_EMPTY

		// Nested bracketed groups. (6752)
		case META_LOOKAHEAD:
			bravalue = OP_ASSERT
			cb.assertDepth++
			goto GROUP_PROCESS

		case META_LOOKAHEAD_NA:
			bravalue = OP_ASSERT_NA
			cb.assertDepth++
			goto GROUP_PROCESS

		case META_LOOKAHEADNOT:
			if pp[pptr+1] == META_KET && (pp[pptr+2] < META_ASTERISK || pp[pptr+2] > META_MINMAX_QUERY) {
				emit(OP_FAIL)
				pptr++
				continue mainloop
			}
			bravalue = OP_ASSERT_NOT
			cb.assertDepth++
			goto GROUP_PROCESS

		case META_LOOKBEHIND:
			bravalue = OP_ASSERTBACK
			cb.assertDepth++
			goto GROUP_PROCESS

		case META_LOOKBEHINDNOT:
			bravalue = OP_ASSERTBACK_NOT
			cb.assertDepth++
			goto GROUP_PROCESS

		case META_LOOKBEHIND_NA:
			bravalue = OP_ASSERTBACK_NA
			cb.assertDepth++
			goto GROUP_PROCESS

		case META_ATOMIC:
			bravalue = OP_ONCE
			goto GROUP_PROCESS_NOTE_EMPTY

		case META_SCRIPT_RUN:
			bravalue = OP_SCRIPT_RUN
			goto GROUP_PROCESS_NOTE_EMPTY

		case META_NOCAPTURE:
			bravalue = OP_BRA
			goto GROUP_PROCESS_NOTE_EMPTY

		// Named backreferences and recursions. (7021)
		case META_BACKREF_BYNAME, META_RECURSE_BYNAME:
			is_dupname = false
			pptr++
			dlength = pp[pptr]
			getPlusOffset()
			dname = int(offset)

			groupnumber = 0
			for i := 0; i < int(cb.namesFound); i++ {
				ng := &cb.namedGroups[i]
				if dlength == uint32(ng.length) &&
					strncmp(cb.startPattern[dname:], ng.name, uint64(dlength)) == 0 {
					is_dupname = ng.isdup != 0
					groupnumber = ng.number

					if meta == META_RECURSE_BYNAME {
						meta_arg = groupnumber
						goto HANDLE_NUMERICAL_RECURSION
					}

					if groupnumber < 32 {
						cb.backrefMap |= 1 << groupnumber
					} else {
						cb.backrefMap |= 1
					}
					if groupnumber > cb.topBackref {
						cb.topBackref = groupnumber
					}
				}
			}

			if groupnumber == 0 {
				*errorcodeptr = ERR15
				cb.erroroffset = offset
				return 0
			}

			if !is_dupname {
				meta_arg = groupnumber
				goto HANDLE_SINGLE_REFERENCE
			}

			dcount = 0
			dindex = 0
			if lengthptr == nil && !find_dupname_details(cb.startPattern, dname, dlength, &dindex,
				&dcount, errorcodeptr, cb) {
				return 0
			}

			if firstcuflags == REQ_UNSET {
				firstcuflags = REQ_NONE
			}
			if options&PCRE2_CASELESS != 0 {
				emit(OP_DNREFI)
			} else {
				emit(OP_DNREF)
			}
			cc = PUT2INC(code, cc, dindex)
			cc = PUT2INC(code, cc, dcount)
			continue mainloop

		// Numerical callout. (7104)
		case META_CALLOUT_NUMBER:
			code[cc] = OP_CALLOUT
			PUT(code, cc+1, int(pp[pptr+1]))
			PUT(code, cc+1+LINK_SIZE, int(pp[pptr+2]))
			code[cc+1+2*LINK_SIZE] = byte(pp[pptr+3])
			pptr += 3
			cc += int(OP_lengths[OP_CALLOUT])
			continue mainloop

		// Callout with a string argument. (7121)
		case META_CALLOUT_STRING:
			if lengthptr != nil {
				*lengthptr += uint64(pp[pptr+3]) + (1 + 4*LINK_SIZE)
				pptr += 3
				pptr += 2 // SKIPOFFSET
			} else {
				length := pp[pptr+3]
				callout_string := cc + (1 + 4*LINK_SIZE)

				code[cc] = OP_CALLOUT_STR
				PUT(code, cc+1, int(pp[pptr+1]))
				PUT(code, cc+1+LINK_SIZE, int(pp[pptr+2]))

				pptr += 3
				getPlusOffset()
				ppi := int(offset)
				delimiter := uint32(cb.startPattern[ppi])
				code[callout_string] = byte(delimiter)
				callout_string++
				ppi++
				if delimiter == CHAR_LEFT_CURLY_BRACKET {
					delimiter = CHAR_RIGHT_CURLY_BRACKET
				}
				PUT(code, cc+1+3*LINK_SIZE, int(offset+1))

				for {
					length--
					if length <= 1 {
						break
					}
					if uint32(cb.startPattern[ppi]) == delimiter && uint32(cb.startPattern[ppi+1]) == delimiter {
						code[callout_string] = byte(delimiter)
						callout_string++
						ppi += 2
						length--
					} else {
						code[callout_string] = cb.startPattern[ppi]
						callout_string++
						ppi++
					}
				}
				code[callout_string] = CHAR_NUL
				callout_string++

				PUT(code, cc+1+2*LINK_SIZE, callout_string-cc)
				cc = callout_string
			}
			continue mainloop

		// Repetition. (7182)
		case META_MINMAX_PLUS, META_MINMAX_QUERY, META_MINMAX:
			pptr++
			repeat_min = pp[pptr]
			pptr++
			repeat_max = pp[pptr]
			goto REPEAT

		case META_ASTERISK, META_ASTERISK_PLUS, META_ASTERISK_QUERY:
			repeat_min = 0
			repeat_max = REPEAT_UNLIMITED
			goto REPEAT

		case META_PLUS, META_PLUS_PLUS, META_PLUS_QUERY:
			repeat_min = 1
			repeat_max = REPEAT_UNLIMITED
			goto REPEAT

		case META_QUERY, META_QUERY_PLUS, META_QUERY_QUERY:
			repeat_min = 0
			repeat_max = 1
			goto REPEAT

		// 32-bit data character greater than META_END. (8017)
		case META_BIGVALUE:
			pptr++
			goto NORMAL_CHAR

		// Back reference by number. (8029)
		case META_BACKREF:
			if meta_arg < 10 {
				offset = cb.smallRefOffset[meta_arg]
			} else {
				getPlusOffset()
			}
			if meta_arg > cb.bracount {
				cb.erroroffset = offset
				*errorcodeptr = ERR15
				return 0
			}
			goto HANDLE_SINGLE_REFERENCE

		// Recursion. (8070)
		case META_RECURSE:
			getPlusOffset()
			if meta_arg > cb.bracount {
				cb.erroroffset = offset
				*errorcodeptr = ERR15
				return 0
			}
			goto HANDLE_NUMERICAL_RECURSION

		// Capturing parentheses. (8093)
		case META_CAPTURE:
			bravalue = OP_CBRA
			skipunits = IMM2_SIZE
			PUT2(code, cc+1+LINK_SIZE, int(meta_arg))
			cb.lastcapture = meta_arg
			goto GROUP_PROCESS_NOTE_EMPTY

		// Escape sequence items. (8113)
		case META_ESCAPE:
			if meta_arg > ESC_b && meta_arg < ESC_Z {
				matched_char = true
				if firstcuflags == REQ_UNSET {
					firstcuflags = REQ_NONE
				}
			}

			zerofirstcu = firstcu
			zerofirstcuflags = firstcuflags
			zeroreqcu = reqcu
			zeroreqcuflags = reqcuflags

			if meta_arg == ESC_P || meta_arg == ESC_p {
				pptr++
				ptype := pp[pptr] >> 16
				pdata := pp[pptr] & 0xffff

				if meta_arg == ESC_p && ptype == PT_ANY {
					emit(OP_ALLANY)
				} else {
					if meta_arg == ESC_p {
						emit(OP_PROP)
					} else {
						emit(OP_NOTPROP)
					}
					emit(ptype)
					emit(pdata)
				}
				continue mainloop
			}

			// \K is forbidden in lookarounds since 10.38.
			if cb.assertDepth > 0 && meta_arg == ESC_K &&
				xoptions&PCRE2_EXTRA_ALLOW_LOOKAROUND_BSK == 0 {
				*errorcodeptr = ERR99
				return 0
			}

			switch meta_arg {
			case ESC_C:
				cb.externalFlags |= PCRE2_HASBKC
				if !utf {
					meta_arg = OP_ALLANY
				}

			case ESC_B, ESC_b:
				if options&PCRE2_UCP != 0 && xoptions&PCRE2_EXTRA_ASCII_BSW == 0 {
					if meta_arg == ESC_B {
						meta_arg = OP_NOT_UCP_WORD_BOUNDARY
					} else {
						meta_arg = OP_UCP_WORD_BOUNDARY
					}
				}
				if cb.maxLookbehind == 0 {
					cb.maxLookbehind = 1
				}

			case ESC_A:
				if cb.maxLookbehind == 0 {
					cb.maxLookbehind = 1
				}
			}

			emit(meta_arg)
			continue mainloop

		// Unrecognized meta value or a literal character. (8213)
		default:
			if meta >= META_END {
				*errorcodeptr = ERR89
				return 0
			}
			goto NORMAL_CHAR
		}

		// ---------------------------------------------------------------
		// Code reached by goto from the switch above (C labels).

	VERB_ARG: // (6547)
		emit(verbops[(meta-META_MARK)>>16])
		pptr++
		verbarglen = pp[pptr] // The length is in characters.
		verbculen = 0
		tempcode = cc
		cc++
		for i := 0; i < int(verbarglen); i++ {
			pptr++
			meta = pp[pptr]
			if utf {
				mclength = uint32(ord2utf(meta, mcbuffer[:]))
			} else {
				mclength = 1
				mcbuffer[0] = byte(meta)
			}
			if lengthptr != nil {
				*lengthptr += uint64(mclength)
			} else {
				copy(code[cc:], mcbuffer[:mclength])
				cc += int(mclength)
				verbculen += mclength
			}
		}
		code[tempcode] = byte(verbculen)
		emit(0)
		continue mainloop

	GROUP_PROCESS_NOTE_EMPTY: // (6816)
		note_group_empty = true

	GROUP_PROCESS: // (6819)
		cb.parensDepth++
		code[cc] = byte(bravalue)
		pptr++
		tempcode = cc
		tempreqvary = cb.reqVaryopt
		length_prevgroup = 0

		{
			var lp *uint64
			if lengthptr != nil {
				lp = &length_prevgroup
			}
			group_return = compile_regex(options, xoptions, code, &tempcode, &pptr, errorcodeptr,
				skipunits, &subfirstcu, &subfirstcuflags, &subreqcu, &subreqcuflags,
				bcptr, open_caps, cb, lp)
		}
		if group_return == 0 {
			return 0
		}

		cb.parensDepth--

		if note_group_empty && bravalue != OP_COND && group_return > 0 {
			matched_char = true
		}

		if bravalue >= OP_ASSERT && bravalue <= OP_ASSERTBACK_NA {
			cb.assertDepth--
		}

		// Conditional group branch counting, real compile phase only. (6870)
		if bravalue == OP_COND && lengthptr == nil {
			tc := cc
			condcount := 0

			for {
				condcount++
				tc += GET(code, tc+1)
				if code[tc] == OP_KET {
					break
				}
			}

			if code[cc+LINK_SIZE+1] == OP_DEFINE {
				if condcount > 1 {
					cb.erroroffset = offset
					*errorcodeptr = ERR54
					return 0
				}
				code[cc+LINK_SIZE+1] = OP_FALSE
				bravalue = OP_DEFINE // A flag to suppress char handling below
			} else {
				if condcount > 2 {
					cb.erroroffset = offset
					*errorcodeptr = ERR27
					return 0
				}
				if condcount == 1 {
					subfirstcuflags = REQ_NONE
					subreqcuflags = REQ_NONE
				} else if group_return > 0 {
					matched_char = true
				}
			}
		}

		// Pre-compile phase: update the length and shrink the group. (6920)
		if lengthptr != nil {
			if uint64(OFLOW_MAX)-*lengthptr < length_prevgroup-2-2*LINK_SIZE {
				*errorcodeptr = ERR20
				return 0
			}
			*lengthptr += length_prevgroup - 2 - 2*LINK_SIZE
			cc++ // This already contains bravalue
			cc = PUTINC(code, cc, 1+LINK_SIZE)
			emit(OP_KET)
			cc = PUTINC(code, cc, 1+LINK_SIZE)
			continue mainloop
		}

		cc = tempcode

		if bravalue == OP_DEFINE {
			continue mainloop
		}

		zeroreqcu = reqcu
		zeroreqcuflags = reqcuflags
		zerofirstcu = firstcu
		zerofirstcuflags = firstcuflags
		groupsetfirstcu = false

		if bravalue >= OP_ONCE { // Not an assertion
			if firstcuflags == REQ_UNSET && subfirstcuflags != REQ_UNSET {
				if subfirstcuflags < REQ_NONE {
					firstcu = subfirstcu
					firstcuflags = subfirstcuflags
					groupsetfirstcu = true
				} else {
					firstcuflags = REQ_NONE
				}
				zerofirstcuflags = REQ_NONE
			} else if subfirstcuflags < REQ_NONE && subreqcuflags >= REQ_NONE {
				subreqcu = subfirstcu
				subreqcuflags = subfirstcuflags | tempreqvary
			}

			if subreqcuflags < REQ_NONE {
				reqcu = subreqcu
				reqcuflags = subreqcuflags
			}
		} else if (bravalue == OP_ASSERT || bravalue == OP_ASSERT_NA) &&
			subreqcuflags < REQ_NONE && subfirstcuflags < REQ_NONE {
			reqcu = subreqcu
			reqcuflags = subreqcuflags
		}
		continue mainloop

	HANDLE_SINGLE_REFERENCE: // (8046)
		if firstcuflags == REQ_UNSET {
			firstcuflags = REQ_NONE
			zerofirstcuflags = REQ_NONE
		}
		if options&PCRE2_CASELESS != 0 {
			emit(OP_REFI)
		} else {
			emit(OP_REF)
		}
		cc = PUT2INC(code, cc, int(meta_arg))

		if meta_arg < 32 {
			cb.backrefMap |= 1 << meta_arg
		} else {
			cb.backrefMap |= 1
		}
		if meta_arg > cb.topBackref {
			cb.topBackref = meta_arg
		}
		continue mainloop

	HANDLE_NUMERICAL_RECURSION: // (8078)
		code[cc] = OP_RECURSE
		PUT(code, cc+1, int(meta_arg))
		cc += 1 + LINK_SIZE
		groupsetfirstcu = false
		cb.hadRecurse = true
		if firstcuflags == REQ_UNSET {
			firstcuflags = REQ_NONE
		}
		zerofirstcu = firstcu
		zerofirstcuflags = firstcuflags
		continue mainloop

	REPEAT: // (7209)
		if previous_matched_char && repeat_min > 0 {
			matched_char = true
		}

		if repeat_min == repeat_max {
			reqvary = 0
		} else {
			reqvary = REQ_VARY
		}
		op_type = 0

		if repeat_min == 0 {
			firstcu = zerofirstcu
			firstcuflags = zerofirstcuflags
			reqcu = zeroreqcu
			reqcuflags = zeroreqcuflags
		}

		switch meta {
		case META_MINMAX_PLUS, META_ASTERISK_PLUS, META_PLUS_PLUS, META_QUERY_PLUS:
			repeat_type = 0
			possessive_quantifier = true
		case META_MINMAX_QUERY, META_ASTERISK_QUERY, META_PLUS_QUERY, META_QUERY_QUERY:
			repeat_type = greedy_non_default
			possessive_quantifier = false
		default:
			repeat_type = greedy_default
			possessive_quantifier = false
		}

		tempcode = previous
		op_previous = code[previous]

		switch op_previous {
		case OP_CHAR, OP_CHARI, OP_NOT, OP_NOTI:
			if repeat_max == 1 && repeat_min == 1 {
				goto END_REPEAT
			}
			op_type = chartypeoffset[op_previous-OP_CHAR]

			if utf && NOT_FIRSTCU(uint32(code[cc-1])) {
				lastchar := BACKCHAR(code, cc-1)
				mclength = uint32(cc - lastchar)
				copy(mcbuffer[:], code[lastchar:cc])
			} else {
				mcbuffer[0] = code[cc-1]
				mclength = 1
				if op_previous <= OP_CHARI && repeat_min > 1 {
					reqcu = uint32(mcbuffer[0])
					reqcuflags = cb.reqVaryopt
					if op_previous == OP_CHARI {
						reqcuflags |= REQ_CASELESS
					}
				}
			}
			prop_type = -1
			prop_value = -1
			goto SINGLE_REPEAT_BODY

		case OP_XCLASS, OP_CLASS, OP_NCLASS, OP_REF, OP_REFI, OP_DNREF, OP_DNREFI:
			if repeat_max == 0 {
				cc = previous
				goto END_REPEAT
			}
			if repeat_max == 1 && repeat_min == 1 {
				goto END_REPEAT
			}

			if repeat_min == 0 && repeat_max == REPEAT_UNLIMITED {
				emit(OP_CRSTAR + repeat_type)
			} else if repeat_min == 1 && repeat_max == REPEAT_UNLIMITED {
				emit(OP_CRPLUS + repeat_type)
			} else if repeat_min == 0 && repeat_max == 1 {
				emit(OP_CRQUERY + repeat_type)
			} else {
				emit(OP_CRRANGE + repeat_type)
				cc = PUT2INC(code, cc, int(repeat_min))
				if repeat_max == REPEAT_UNLIMITED {
					repeat_max = 0
				}
				cc = PUT2INC(code, cc, int(repeat_max))
			}

		case OP_FAIL:
			goto END_REPEAT

		case OP_RECURSE:
			if repeat_max == 1 && repeat_min == 1 && !possessive_quantifier {
				goto END_REPEAT
			}

			if repeat_min > 0 && (repeat_min != 1 || repeat_max != REPEAT_UNLIMITED) {
				replicate := int32(repeat_min)
				if repeat_min == repeat_max {
					replicate--
				}

				if lengthptr != nil {
					var delta uint64
					if ckd_smul(&delta, replicate, 1+LINK_SIZE) ||
						uint64(OFLOW_MAX)-*lengthptr < delta {
						*errorcodeptr = ERR20
						return 0
					}
					*lengthptr += delta
				} else {
					for i := int32(0); i < replicate; i++ {
						copy(code[cc:cc+1+LINK_SIZE], code[previous:previous+1+LINK_SIZE])
						previous = cc
						cc += 1 + LINK_SIZE
					}
				}

				if repeat_min == repeat_max {
					goto POSSESSIVE
				}
				if repeat_max != REPEAT_UNLIMITED {
					repeat_max -= repeat_min
				}
				repeat_min = 0
			}

			// Wrap the recursion call in OP_BRA brackets.
			copy(code[previous+1+LINK_SIZE:previous+2+2*LINK_SIZE], code[previous:previous+1+LINK_SIZE])
			code[previous] = OP_BRA
			op_previous = OP_BRA
			PUT(code, previous+1, 2+2*LINK_SIZE)
			code[previous+2+2*LINK_SIZE] = OP_KET
			PUT(code, previous+3+2*LINK_SIZE, 2+2*LINK_SIZE)
			cc += 2 + 2*LINK_SIZE
			length_prevgroup = 3 + 3*LINK_SIZE
			group_return = -1 // Set "may match empty string"
			fallthrough

		case OP_ASSERT, OP_ASSERT_NOT, OP_ASSERT_NA, OP_ASSERTBACK, OP_ASSERTBACK_NOT,
			OP_ASSERTBACK_NA, OP_ONCE, OP_SCRIPT_RUN, OP_BRA, OP_CBRA, OP_COND:
			rlen = cc - previous
			bralink = -1
			brazeroptr = -1

			if repeat_max == 1 && repeat_min == 1 && !possessive_quantifier {
				goto END_REPEAT
			}

			// Repeating a DEFINE group is pointless.
			if op_previous == OP_COND && code[previous+LINK_SIZE+1] == OP_FALSE &&
				code[previous+GET(code, previous+1)] != OP_ALT {
				goto END_REPEAT
			}

			if op_previous < OP_ONCE { // Assertion
				if repeat_max == REPEAT_UNLIMITED {
					repeat_max = repeat_min + 1
				}
			}

			if repeat_min == 0 {
				if repeat_max <= 1 || repeat_max == REPEAT_UNLIMITED {
					copy(code[previous+1:previous+1+rlen], code[previous:previous+rlen])
					cc++
					if repeat_max == 0 {
						code[previous] = OP_SKIPZERO
						previous++
						goto END_REPEAT
					}
					brazeroptr = previous // Save for possessive optimizing
					code[previous] = byte(OP_BRAZERO + repeat_type)
					previous++
				} else {
					copy(code[previous+2+LINK_SIZE:previous+2+LINK_SIZE+rlen], code[previous:previous+rlen])
					cc += 2 + LINK_SIZE
					code[previous] = byte(OP_BRAZERO + repeat_type)
					previous++
					code[previous] = OP_BRA
					previous++

					linkoffset := 0
					if bralink >= 0 {
						linkoffset = previous - bralink
					}
					bralink = previous
					previous = PUTINC(code, previous, linkoffset)
				}

				if repeat_max != REPEAT_UNLIMITED {
					repeat_max--
				}
			} else {
				if repeat_min > 1 {
					if lengthptr != nil {
						var delta uint64
						if ckd_smul(&delta, int32(repeat_min-1), int32(length_prevgroup)) ||
							uint64(OFLOW_MAX)-*lengthptr < delta {
							*errorcodeptr = ERR20
							return 0
						}
						*lengthptr += delta
					} else {
						if groupsetfirstcu && reqcuflags >= REQ_NONE {
							reqcu = firstcu
							reqcuflags = firstcuflags
						}
						for i := uint32(1); i < repeat_min; i++ {
							copy(code[cc:cc+rlen], code[previous:previous+rlen])
							cc += rlen
						}
					}
				}

				if repeat_max != REPEAT_UNLIMITED {
					repeat_max -= repeat_min
				}
			}

			if repeat_max != REPEAT_UNLIMITED {
				if lengthptr != nil && repeat_max > 0 {
					var delta uint64
					if ckd_smul(&delta, int32(repeat_max), int32(length_prevgroup)+1+2+2*LINK_SIZE) ||
						uint64(OFLOW_MAX)+(2+2*LINK_SIZE)-*lengthptr < delta {
						*errorcodeptr = ERR20
						return 0
					}
					delta -= 2 + 2*LINK_SIZE // Last one doesn't nest
					*lengthptr += delta
				} else {
					for i := repeat_max; i >= 1; i-- {
						code[cc] = byte(OP_BRAZERO + repeat_type)
						cc++

						if i != 1 {
							code[cc] = OP_BRA
							cc++
							linkoffset := 0
							if bralink >= 0 {
								linkoffset = cc - bralink
							}
							bralink = cc
							cc = PUTINC(code, cc, linkoffset)
						}

						copy(code[cc:cc+rlen], code[previous:previous+rlen])
						cc += rlen
					}
				}

				// pcre2_compile.c:7639: runs in both phases.
				for bralink >= 0 {
					linkoffset := cc - bralink + 1
					bra := cc - linkoffset
					oldlinkoffset := GET(code, bra+1)
					if oldlinkoffset == 0 {
						bralink = -1
					} else {
						bralink -= oldlinkoffset
					}
					code[cc] = OP_KET
					cc++
					cc = PUTINC(code, cc, linkoffset)
					PUT(code, bra+1, linkoffset)
				}
			} else {
				// Unlimited maximum: set a repeater in the final copy. (7678)
				ketcode := cc - 1 - LINK_SIZE
				bracode := ketcode - GET(code, ketcode+1)

				// Convert possessive ONCE brackets to non-capturing.
				if code[bracode] == OP_ONCE && possessive_quantifier {
					code[bracode] = OP_BRA
				}

				if code[bracode] == OP_ONCE || code[bracode] == OP_SCRIPT_RUN {
					code[ketcode] = byte(OP_KETRMAX + repeat_type)
				} else {
					if lengthptr == nil {
						if group_return < 0 {
							code[bracode] += OP_SBRA - OP_BRA
						}
						if code[bracode] == OP_COND && code[bracode+GET(code, bracode+1)] != OP_ALT {
							code[bracode] = OP_SCOND
						}
					}

					if possessive_quantifier {
						if code[bracode] == OP_COND || code[bracode] == OP_SCOND {
							nlen := cc - bracode
							copy(code[bracode+1+LINK_SIZE:bracode+1+LINK_SIZE+nlen], code[bracode:bracode+nlen])
							cc += 1 + LINK_SIZE
							nlen += 1 + LINK_SIZE
							if code[bracode] == OP_COND {
								code[bracode] = OP_BRAPOS
							} else {
								code[bracode] = OP_SBRAPOS
							}
							code[cc] = OP_KETRPOS
							cc++
							cc = PUTINC(code, cc, nlen)
							PUT(code, bracode+1, nlen)
						} else {
							code[bracode]++ // Switch to xxxPOS opcodes
							code[ketcode] = OP_KETRPOS
						}

						if brazeroptr >= 0 {
							code[brazeroptr] = OP_BRAPOSZERO
						}
						if repeat_min < 2 {
							possessive_quantifier = false
						}
					} else {
						code[ketcode] = byte(OP_KETRMAX + repeat_type)
					}
				}
			}

		default:
			// Character type match (\d or similar), or an internal error. (7760)
			if op_previous >= OP_EODN {
				*errorcodeptr = ERR10
				return 0
			}
			if repeat_max == 1 && repeat_min == 1 {
				goto END_REPEAT
			}

			op_type = OP_TYPESTAR - OP_STAR // Use type opcodes
			mclength = 0                    // Not a character

			if op_previous == OP_PROP || op_previous == OP_NOTPROP {
				prop_type = int(code[previous+1])
				prop_value = int(code[previous+2])
			} else {
				prop_type = -1
				prop_value = -1
			}
			goto SINGLE_REPEAT_BODY
		}
		goto POSSESSIVE

	SINGLE_REPEAT_BODY: // (7794): a character in mcbuffer/mclength or a type in op_previous
		oldcode = cc
		cc = previous

		if repeat_max == 0 {
			goto END_REPEAT
		}

		repeat_type += op_type

		if repeat_min == 0 {
			if repeat_max == REPEAT_UNLIMITED {
				emit(OP_STAR + repeat_type)
			} else if repeat_max == 1 {
				emit(OP_QUERY + repeat_type)
			} else {
				emit(OP_UPTO + repeat_type)
				cc = PUT2INC(code, cc, int(repeat_max))
			}
		} else if repeat_min == 1 {
			if repeat_max == REPEAT_UNLIMITED {
				emit(OP_PLUS + repeat_type)
			} else {
				cc = oldcode // Leave previous item in place
				if repeat_max == 1 {
					goto END_REPEAT
				}
				emit(OP_UPTO + repeat_type)
				cc = PUT2INC(code, cc, int(repeat_max-1))
			}
		} else {
			emit(OP_EXACT + op_type) // NB EXACT doesn't have repeat_type
			cc = PUT2INC(code, cc, int(repeat_min))

			if repeat_max != repeat_min {
				if mclength > 0 {
					copy(code[cc:], mcbuffer[:mclength])
					cc += int(mclength)
				} else {
					code[cc] = op_previous
					cc++
					if prop_type >= 0 {
						code[cc] = byte(prop_type)
						cc++
						code[cc] = byte(prop_value)
						cc++
					}
				}

				if repeat_max == REPEAT_UNLIMITED {
					emit(OP_STAR + repeat_type)
				} else {
					repeat_max -= repeat_min
					if repeat_max == 1 {
						emit(OP_QUERY + repeat_type)
					} else {
						emit(OP_UPTO + repeat_type)
						cc = PUT2INC(code, cc, int(repeat_max))
					}
				}
			}
		}

		// Fill in the character or character type for the final opcode.
		if mclength > 0 {
			copy(code[cc:], mcbuffer[:mclength])
			cc += int(mclength)
		} else {
			code[cc] = op_previous
			cc++
			if prop_type >= 0 {
				code[cc] = byte(prop_type)
				cc++
				code[cc] = byte(prop_value)
				cc++
			}
		}

	POSSESSIVE: // (7909)
		if possessive_quantifier {
			switch code[tempcode] {
			case OP_TYPEEXACT:
				add := 0
				if code[tempcode+1+IMM2_SIZE] == OP_PROP || code[tempcode+1+IMM2_SIZE] == OP_NOTPROP {
					add = 2
				}
				tempcode += int(OP_lengths[code[tempcode]]) + add

			case OP_CHAR, OP_CHARI, OP_NOT, OP_NOTI, OP_EXACT, OP_EXACTI, OP_NOTEXACT, OP_NOTEXACTI:
				tempcode += int(OP_lengths[code[tempcode]])
				if utf && HAS_EXTRALEN(uint32(code[tempcode-1])) {
					tempcode += GET_EXTRALEN(uint32(code[tempcode-1]))
				}

			case OP_CLASS, OP_NCLASS:
				tempcode += 1 + 32

			case OP_XCLASS:
				tempcode += GET(code, tempcode+1)
			}

			rlen = cc - tempcode
			if rlen > 0 {
				repcode := uint32(code[tempcode])

				if repcode < OP_CALLOUT && opcode_possessify[repcode] > 0 {
					code[tempcode] = opcode_possessify[repcode]
				} else {
					copy(code[tempcode+1+LINK_SIZE:tempcode+1+LINK_SIZE+rlen], code[tempcode:tempcode+rlen])
					cc += 1 + LINK_SIZE
					rlen += 1 + LINK_SIZE
					code[tempcode] = OP_ONCE
					code[cc] = OP_KET
					cc++
					cc = PUTINC(code, cc, rlen)
					PUT(code, tempcode+1, rlen)
				}
			}
		}

	END_REPEAT: // (8009)
		cb.reqVaryopt |= reqvary
		continue mainloop

	NORMAL_CHAR: // (8226)
		meta = pp[pptr] // Get the full 32 bits

	NORMAL_CHAR_SET: // Character is already in meta
		matched_char = true

		if (utf || ucp) && options&PCRE2_CASELESS != 0 {
			caseset := uint32(UCD_CASESET(meta))
			if caseset != 0 &&
				(xoptions&PCRE2_EXTRA_CASELESS_RESTRICT == 0 || ucd_caseless_sets[caseset] > 127) {
				emit(OP_PROP)
				emit(PT_CLIST)
				emit(caseset)
				if firstcuflags == REQ_UNSET {
					firstcuflags = REQ_NONE
					zerofirstcuflags = REQ_NONE
				}
				continue mainloop
			}
		}

	CLASS_CASELESS_CHAR: // (8259)
		if utf {
			mclength = uint32(ord2utf(meta, mcbuffer[:]))
		} else {
			mclength = 1
			mcbuffer[0] = byte(meta)
		}

		if options&PCRE2_CASELESS != 0 {
			emit(OP_CHARI)
		} else {
			emit(OP_CHAR)
		}
		copy(code[cc:], mcbuffer[:mclength])
		cc += int(mclength)

		if mcbuffer[0] == CHAR_CR || mcbuffer[0] == CHAR_NL {
			cb.externalFlags |= PCRE2_HASCRORLF
		}

		if firstcuflags == REQ_UNSET {
			zerofirstcuflags = REQ_NONE
			zeroreqcu = reqcu
			zeroreqcuflags = reqcuflags

			if mclength == 1 || req_caseopt == 0 {
				firstcu = uint32(mcbuffer[0])
				firstcuflags = req_caseopt
				if mclength != 1 {
					reqcu = uint32(code[cc-1])
					reqcuflags = cb.reqVaryopt
				}
			} else {
				firstcuflags = REQ_NONE
				reqcuflags = REQ_NONE
			}
		} else {
			zerofirstcu = firstcu
			zerofirstcuflags = firstcuflags
			zeroreqcu = reqcu
			zeroreqcuflags = reqcuflags
			if mclength == 1 || req_caseopt == 0 {
				reqcu = uint32(code[cc-1])
				reqcuflags = req_caseopt | cb.reqVaryopt
			}
		}

		if reset_caseful {
			options &^= PCRE2_CASELESS
			req_caseopt = 0
			reset_caseful = false
		}
		continue mainloop
	}
}

// b2u32 converts a bool to 0 or 1.
func b2u32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}
