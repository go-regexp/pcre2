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
	firstcuflags, reqcuflags, zerofirstcuflags, zeroreqcuflags = xREQ_UNSET, xREQ_UNSET, xREQ_UNSET, xREQ_UNSET

	if options&PCRE2_CASELESS != 0 {
		req_caseopt = xREQ_CASELESS
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
		meta = xMETA_CODE(pp[pptr])
		meta_arg = xMETA_DATA(pp[pptr])

		// In the pre-compile phase, accumulate the length used for the previous
		// cycle of this loop, unless the next item is a quantifier.
		if lengthptr != nil {
			if uint64(cc) > cb.workspaceSize-xWORK_SIZE_SAFETY_MARGIN {
				if uint64(cc) >= cb.workspaceSize {
					*errorcodeptr = xERR52
				} else {
					*errorcodeptr = xERR86
				}
				return 0
			}
			if cc < last_code {
				cc = last_code
			}
			if meta < xMETA_ASTERISK || meta > xMETA_MINMAX_QUERY {
				if uint64(xOFLOW_MAX)-*lengthptr < uint64(cc-orig_code) {
					*errorcodeptr = xERR20
					return 0
				}
				*lengthptr += uint64(cc - orig_code)
				if *lengthptr > xMAX_PATTERN_SIZE {
					*errorcodeptr = xERR20
					return 0
				}
				cc = orig_code
			}
			last_code = cc
		}

		if meta < xMETA_ASTERISK || meta > xMETA_MINMAX_QUERY {
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
		case xMETA_END, xMETA_ALT, xMETA_KET:
			*firstcuptr = firstcu
			*firstcuflagsptr = firstcuflags
			*reqcuptr = reqcu
			*reqcuflagsptr = reqcuflags
			*codeptr = cc
			*pptrptr = pptr
			return okreturn

		// Single-character metacharacters. (5832)
		case xMETA_CIRCUMFLEX:
			if options&PCRE2_MULTILINE != 0 {
				if firstcuflags == xREQ_UNSET {
					firstcuflags = xREQ_NONE
					zerofirstcuflags = xREQ_NONE
				}
				emit(xOP_CIRCM)
			} else {
				emit(xOP_CIRC)
			}
			continue mainloop

		case xMETA_DOLLAR:
			if options&PCRE2_MULTILINE != 0 {
				emit(xOP_DOLLM)
			} else {
				emit(xOP_DOLL)
			}
			continue mainloop

		case xMETA_DOT:
			matched_char = true
			if firstcuflags == xREQ_UNSET {
				firstcuflags = xREQ_NONE
			}
			zerofirstcu = firstcu
			zerofirstcuflags = firstcuflags
			zeroreqcu = reqcu
			zeroreqcuflags = reqcuflags
			if options&PCRE2_DOTALL != 0 {
				emit(xOP_ALLANY)
			} else {
				emit(xOP_ANY)
			}
			continue mainloop

		// Empty classes. (5866)
		case xMETA_CLASS_EMPTY, xMETA_CLASS_EMPTY_NOT:
			matched_char = true
			if meta == xMETA_CLASS_EMPTY_NOT {
				emit(xOP_ALLANY)
			} else {
				emit(xOP_FAIL)
			}
			if firstcuflags == xREQ_UNSET {
				firstcuflags = xREQ_NONE
			}
			zerofirstcu = firstcu
			zerofirstcuflags = firstcuflags
			continue mainloop

		// Non-empty character class. (5889)
		case xMETA_CLASS_NOT, xMETA_CLASS:
			matched_char = true
			negate_class = meta == xMETA_CLASS_NOT

			// One-character class optimization.
			if pp[pptr+1] < xMETA_END && pp[pptr+2] == xMETA_CLASS_END {
				c := pp[pptr+1]
				pptr += 2
				if meta == xMETA_CLASS {
					meta = c
					goto NORMAL_CHAR_SET
				}

				// Negative one-character class.
				zeroreqcu = reqcu
				zeroreqcuflags = reqcuflags
				if firstcuflags == xREQ_UNSET {
					firstcuflags = xREQ_NONE
				}
				zerofirstcu = firstcu
				zerofirstcuflags = firstcuflags

				if d := xUCD_CASESET(c); (utf || ucp) && options&PCRE2_CASELESS != 0 &&
					d != 0 &&
					(xoptions&PCRE2_EXTRA_CASELESS_RESTRICT == 0 ||
						ucd_caseless_sets[d] > 127) {
					emit(xOP_NOTPROP)
					emit(xPT_CLIST)
					emit(uint32(d))
					continue mainloop
				}
				if options&PCRE2_CASELESS != 0 {
					emit(xOP_NOTI)
				} else {
					emit(xOP_NOT)
				}
				cc += xPUTCHAR(utf, c, code[cc:])
				continue mainloop
			}

			// Exactly two characters in a positive class that are case partners.
			if meta == xMETA_CLASS && pp[pptr+1] < xMETA_END && pp[pptr+2] < xMETA_END &&
				pp[pptr+3] == xMETA_CLASS_END {
				c := pp[pptr+1]
				if xUCD_CASESET(c) == 0 ||
					(xoptions&PCRE2_EXTRA_CASELESS_RESTRICT != 0 && c < 128 && pp[pptr+2] < 128) {
					var d uint32
					if (utf || ucp) && c > 127 {
						d = xUCD_OTHERCASE(c)
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
							req_caseopt = xREQ_CASELESS
						}
						goto CLASS_CASELESS_CHAR
					}
				}
			}

			should_flip_negation = false
			match_all_or_no_wide_chars = false

			xclass = false
			class_uchardata = cc + xLINK_SIZE + 2
			class_uchardata_base = class_uchardata

			class_has_8bitchar = 0
			xclass_has_prop = false

			classbits = [32]byte{}

			// Process items until META_CLASS_END is reached. (6030)
			for {
				isLiteral := false
				pptr++
				meta = pp[pptr]
				if meta == xMETA_CLASS_END {
					break
				}

				// POSIX classes.
				if meta == xMETA_POSIX || meta == xMETA_POSIX_NEG {
					local_negate := meta == xMETA_POSIX_NEG
					pptr++
					posix_class := int(pp[pptr])
					var pbits [32]byte

					should_flip_negation = local_negate

					if options&PCRE2_CASELESS != 0 && posix_class <= 2 {
						posix_class = 0
					}

					if options&PCRE2_UCP != 0 && xoptions&PCRE2_EXTRA_ASCII_POSIX == 0 {
						switch posix_class {
						case xPC_GRAPH, xPC_PRINT, xPC_PUNCT:
							if local_negate {
								code[class_uchardata] = xXCL_NOTPROP
							} else {
								code[class_uchardata] = xXCL_PROP
							}
							class_uchardata++
							switch posix_class {
							case xPC_GRAPH:
								code[class_uchardata] = xPT_PXGRAPH
							case xPC_PRINT:
								code[class_uchardata] = xPT_PXPRINT
							default:
								code[class_uchardata] = xPT_PXPUNCT
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

				if meta == xMETA_BIGVALUE {
					pptr++
					meta = pp[pptr]
					isLiteral = true // CLASS_LITERAL
				}

				if !isLiteral && meta >= xMETA_END {
					if xMETA_CODE(meta) != xMETA_ESCAPE {
						*errorcodeptr = xERR89
						return 0
					}
					escape = xMETA_DATA(meta)

					class_has_8bitchar++

					switch escape {
					case xESC_d:
						for i := 0; i < 32; i++ {
							classbits[i] |= cbits[i+cbit_digit]
						}
					case xESC_D:
						should_flip_negation = true
						for i := 0; i < 32; i++ {
							classbits[i] |= ^cbits[i+cbit_digit]
						}
					case xESC_w:
						for i := 0; i < 32; i++ {
							classbits[i] |= cbits[i+cbit_word]
						}
					case xESC_W:
						should_flip_negation = true
						for i := 0; i < 32; i++ {
							classbits[i] |= ^cbits[i+cbit_word]
						}
					case xESC_s:
						for i := 0; i < 32; i++ {
							classbits[i] |= cbits[i+cbit_space]
						}
					case xESC_S:
						should_flip_negation = true
						for i := 0; i < 32; i++ {
							classbits[i] |= ^cbits[i+cbit_space]
						}
					case xESC_h:
						add_list_to_class(classbits[:], code, &class_uchardata,
							options&^PCRE2_CASELESS, xoptions, cb, hspace_list, xNOTACHAR)
					case xESC_H:
						add_not_list_to_class(classbits[:], code, &class_uchardata,
							options&^PCRE2_CASELESS, xoptions, cb, hspace_list)
					case xESC_v:
						add_list_to_class(classbits[:], code, &class_uchardata,
							options&^PCRE2_CASELESS, xoptions, cb, vspace_list, xNOTACHAR)
					case xESC_V:
						add_not_list_to_class(classbits[:], code, &class_uchardata,
							options&^PCRE2_CASELESS, xoptions, cb, vspace_list)
					case xESC_p, xESC_P:
						pptr++
						ptype := pp[pptr] >> 16
						pdata := pp[pptr] & 0xffff
						if escape == xESC_p {
							code[class_uchardata] = xXCL_PROP
						} else {
							code[class_uchardata] = xXCL_NOTPROP
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

					if c == xCHAR_CR || c == xCHAR_NL {
						cb.externalFlags |= PCRE2_HASCRORLF
					}

					if pp[pptr+1] == xMETA_RANGE_LITERAL || pp[pptr+1] == xMETA_RANGE_ESCAPED {
						pptr += 2
						d = pp[pptr]
						if d == xMETA_BIGVALUE {
							pptr++
							d = pp[pptr]
						}
						if d == xCHAR_CR || d == xCHAR_NL {
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
			if firstcuflags == xREQ_UNSET {
				firstcuflags = xREQ_NONE
			}
			zerofirstcu = firstcu
			zerofirstcuflags = firstcuflags
			zeroreqcu = reqcu
			zeroreqcuflags = reqcuflags

			// Extended class. (6407)
			if xclass && (options&PCRE2_UCP != 0 || xclass_has_prop || !should_flip_negation) {
				if match_all_or_no_wide_chars ||
					(utf && should_flip_negation && !negate_class && options&PCRE2_UCP == 0) {
					code[class_uchardata] = xXCL_RANGE
					class_uchardata++
					class_uchardata += int(ord2utf(0x100, code[class_uchardata:]))
					class_uchardata += int(ord2utf(xMAX_UTF_CODE_POINT, code[class_uchardata:]))
				}
				code[class_uchardata] = xXCL_END
				class_uchardata++
				code[cc] = xOP_XCLASS
				cc++
				cc += xLINK_SIZE
				if negate_class {
					code[cc] = xXCL_NOT
				} else {
					code[cc] = 0
				}
				if xclass_has_prop {
					code[cc] |= xXCL_HASPROP
				}

				if class_has_8bitchar > 0 {
					code[cc] |= xXCL_MAP
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

				xPUT(code, previous+1, cc-previous)
				continue mainloop
			}

			if negate_class == should_flip_negation {
				emit(xOP_CLASS)
			} else {
				emit(xOP_NCLASS)
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
		case xMETA_ACCEPT:
			cb.hadAccept = true
			had_accept = true
			for oc = open_caps; oc != nil && uint16(oc.assertDepth) >= cb.assertDepth; oc = oc.next {
				if lengthptr != nil {
					*lengthptr += 1 + xIMM2_SIZE
				} else {
					emit(xOP_CLOSE)
					cc = xPUT2INC(code, cc, int(oc.number))
				}
			}
			if cb.assertDepth > 0 {
				emit(xOP_ASSERT_ACCEPT)
			} else {
				emit(xOP_ACCEPT)
			}
			if firstcuflags == xREQ_UNSET {
				firstcuflags = xREQ_NONE
			}
			continue mainloop

		case xMETA_PRUNE, xMETA_SKIP:
			cb.hadPruneorskip = true
			emit(verbops[(meta-xMETA_MARK)>>16])
			continue mainloop

		case xMETA_COMMIT, xMETA_FAIL:
			emit(verbops[(meta-xMETA_MARK)>>16])
			continue mainloop

		case xMETA_THEN:
			cb.externalFlags |= PCRE2_HASTHEN
			emit(xOP_THEN)
			continue mainloop

		case xMETA_THEN_ARG:
			cb.externalFlags |= PCRE2_HASTHEN
			goto VERB_ARG

		case xMETA_PRUNE_ARG, xMETA_SKIP_ARG:
			cb.hadPruneorskip = true
			goto VERB_ARG

		case xMETA_MARK, xMETA_COMMIT_ARG:
			goto VERB_ARG

		// Options change. (6581)
		case xMETA_OPTIONS:
			pptr++
			options = pp[pptr]
			*optionsptr = options
			pptr++
			xoptions = pp[pptr]
			*xoptionsptr = xoptions
			greedy_default = b2u32(options&PCRE2_UNGREEDY != 0)
			greedy_non_default = greedy_default ^ 1
			if options&PCRE2_CASELESS != 0 {
				req_caseopt = xREQ_CASELESS
			} else {
				req_caseopt = 0
			}
			continue mainloop

		// Conditional subpatterns. (6597)
		case xMETA_COND_RNUMBER, xMETA_COND_NAME, xMETA_COND_RNAME:
			bravalue = xOP_COND
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
							if meta == xMETA_COND_RNAME {
								code[cc+1+xLINK_SIZE] = xOP_RREF
							} else {
								code[cc+1+xLINK_SIZE] = xOP_CREF
							}
							xPUT2(code, cc+2+xLINK_SIZE, int(ng.number))
							if ng.number > cb.topBackref {
								cb.topBackref = ng.number
							}
							skipunits = 1 + xIMM2_SIZE
							goto GROUP_PROCESS_NOTE_EMPTY
						}
						break // Found a duplicated name
					}
				}
			}

			// Name not found: a bad reference, unless R<digits>.
			if di >= uint32(cb.namesFound) {
				groupnumber = 0
				if meta == xMETA_COND_RNUMBER {
					for di = 1; di < dlength; di++ {
						groupnumber = groupnumber*10 + uint32(cb.startPattern[dname+int(di)]) - xCHAR_0
						if groupnumber > xMAX_GROUP_NUMBER {
							*errorcodeptr = xERR61
							cb.erroroffset = offset + uint64(di)
							return 0
						}
					}
				}

				if meta != xMETA_COND_RNUMBER || groupnumber > cb.bracount {
					*errorcodeptr = xERR15
					cb.erroroffset = offset
					return 0
				}

				if groupnumber == 0 {
					groupnumber = xRREF_ANY
				}
				code[cc+1+xLINK_SIZE] = xOP_RREF
				xPUT2(code, cc+2+xLINK_SIZE, int(groupnumber))
				skipunits = 1 + xIMM2_SIZE
				goto GROUP_PROCESS_NOTE_EMPTY
			}

			// A duplicated name was found.
			if meta == xMETA_COND_RNAME {
				code[cc+1+xLINK_SIZE] = xOP_RREF
			} else {
				code[cc+1+xLINK_SIZE] = xOP_CREF
			}

			dcount = 0
			dindex = 0
			if lengthptr == nil && !find_dupname_details(cb.startPattern, dname, dlength, &dindex,
				&dcount, errorcodeptr, cb) {
				return 0
			}

			code[cc+1+xLINK_SIZE]++
			skipunits = 1 + 2*xIMM2_SIZE
			xPUT2(code, cc+2+xLINK_SIZE, dindex)
			xPUT2(code, cc+2+xLINK_SIZE+xIMM2_SIZE, dcount)
			goto GROUP_PROCESS_NOTE_EMPTY

		// The DEFINE condition is always false. (6700)
		case xMETA_COND_DEFINE:
			bravalue = xOP_COND
			getPlusOffset()
			code[cc+1+xLINK_SIZE] = xOP_DEFINE
			skipunits = 1
			goto GROUP_PROCESS

		case xMETA_COND_NUMBER:
			bravalue = xOP_COND
			getPlusOffset()
			pptr++
			groupnumber = pp[pptr]
			if groupnumber > cb.bracount {
				*errorcodeptr = xERR15
				cb.erroroffset = offset
				return 0
			}
			if groupnumber > cb.topBackref {
				cb.topBackref = groupnumber
			}
			offset -= 2 // Point at initial ( for too many branches error
			code[cc+1+xLINK_SIZE] = xOP_CREF
			skipunits = 1 + xIMM2_SIZE
			xPUT2(code, cc+2+xLINK_SIZE, int(groupnumber))
			goto GROUP_PROCESS_NOTE_EMPTY

		case xMETA_COND_VERSION:
			bravalue = xOP_COND
			if pp[pptr+1] > 0 {
				if PCRE2_MAJOR > pp[pptr+2] || (PCRE2_MAJOR == pp[pptr+2] && PCRE2_MINOR >= pp[pptr+3]) {
					code[cc+1+xLINK_SIZE] = xOP_TRUE
				} else {
					code[cc+1+xLINK_SIZE] = xOP_FALSE
				}
			} else {
				if PCRE2_MAJOR == pp[pptr+2] && PCRE2_MINOR == pp[pptr+3] {
					code[cc+1+xLINK_SIZE] = xOP_TRUE
				} else {
					code[cc+1+xLINK_SIZE] = xOP_FALSE
				}
			}
			skipunits = 1
			pptr += 3
			goto GROUP_PROCESS_NOTE_EMPTY

		case xMETA_COND_ASSERT:
			bravalue = xOP_COND
			goto GROUP_PROCESS_NOTE_EMPTY

		// Nested bracketed groups. (6752)
		case xMETA_LOOKAHEAD:
			bravalue = xOP_ASSERT
			cb.assertDepth++
			goto GROUP_PROCESS

		case xMETA_LOOKAHEAD_NA:
			bravalue = xOP_ASSERT_NA
			cb.assertDepth++
			goto GROUP_PROCESS

		case xMETA_LOOKAHEADNOT:
			if pp[pptr+1] == xMETA_KET && (pp[pptr+2] < xMETA_ASTERISK || pp[pptr+2] > xMETA_MINMAX_QUERY) {
				emit(xOP_FAIL)
				pptr++
				continue mainloop
			}
			bravalue = xOP_ASSERT_NOT
			cb.assertDepth++
			goto GROUP_PROCESS

		case xMETA_LOOKBEHIND:
			bravalue = xOP_ASSERTBACK
			cb.assertDepth++
			goto GROUP_PROCESS

		case xMETA_LOOKBEHINDNOT:
			bravalue = xOP_ASSERTBACK_NOT
			cb.assertDepth++
			goto GROUP_PROCESS

		case xMETA_LOOKBEHIND_NA:
			bravalue = xOP_ASSERTBACK_NA
			cb.assertDepth++
			goto GROUP_PROCESS

		case xMETA_ATOMIC:
			bravalue = xOP_ONCE
			goto GROUP_PROCESS_NOTE_EMPTY

		case xMETA_SCRIPT_RUN:
			bravalue = xOP_SCRIPT_RUN
			goto GROUP_PROCESS_NOTE_EMPTY

		case xMETA_NOCAPTURE:
			bravalue = xOP_BRA
			goto GROUP_PROCESS_NOTE_EMPTY

		// Named backreferences and recursions. (7021)
		case xMETA_BACKREF_BYNAME, xMETA_RECURSE_BYNAME:
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

					if meta == xMETA_RECURSE_BYNAME {
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
				*errorcodeptr = xERR15
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

			if firstcuflags == xREQ_UNSET {
				firstcuflags = xREQ_NONE
			}
			if options&PCRE2_CASELESS != 0 {
				emit(xOP_DNREFI)
			} else {
				emit(xOP_DNREF)
			}
			cc = xPUT2INC(code, cc, dindex)
			cc = xPUT2INC(code, cc, dcount)
			continue mainloop

		// Numerical callout. (7104)
		case xMETA_CALLOUT_NUMBER:
			code[cc] = xOP_CALLOUT
			xPUT(code, cc+1, int(pp[pptr+1]))
			xPUT(code, cc+1+xLINK_SIZE, int(pp[pptr+2]))
			code[cc+1+2*xLINK_SIZE] = byte(pp[pptr+3])
			pptr += 3
			cc += int(xOP_lengths[xOP_CALLOUT])
			continue mainloop

		// Callout with a string argument. (7121)
		case xMETA_CALLOUT_STRING:
			if lengthptr != nil {
				*lengthptr += uint64(pp[pptr+3]) + (1 + 4*xLINK_SIZE)
				pptr += 3
				pptr += 2 // SKIPOFFSET
			} else {
				length := pp[pptr+3]
				callout_string := cc + (1 + 4*xLINK_SIZE)

				code[cc] = xOP_CALLOUT_STR
				xPUT(code, cc+1, int(pp[pptr+1]))
				xPUT(code, cc+1+xLINK_SIZE, int(pp[pptr+2]))

				pptr += 3
				getPlusOffset()
				ppi := int(offset)
				delimiter := uint32(cb.startPattern[ppi])
				code[callout_string] = byte(delimiter)
				callout_string++
				ppi++
				if delimiter == xCHAR_LEFT_CURLY_BRACKET {
					delimiter = xCHAR_RIGHT_CURLY_BRACKET
				}
				xPUT(code, cc+1+3*xLINK_SIZE, int(offset+1))

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
				code[callout_string] = xCHAR_NUL
				callout_string++

				xPUT(code, cc+1+2*xLINK_SIZE, callout_string-cc)
				cc = callout_string
			}
			continue mainloop

		// Repetition. (7182)
		case xMETA_MINMAX_PLUS, xMETA_MINMAX_QUERY, xMETA_MINMAX:
			pptr++
			repeat_min = pp[pptr]
			pptr++
			repeat_max = pp[pptr]
			goto REPEAT

		case xMETA_ASTERISK, xMETA_ASTERISK_PLUS, xMETA_ASTERISK_QUERY:
			repeat_min = 0
			repeat_max = xREPEAT_UNLIMITED
			goto REPEAT

		case xMETA_PLUS, xMETA_PLUS_PLUS, xMETA_PLUS_QUERY:
			repeat_min = 1
			repeat_max = xREPEAT_UNLIMITED
			goto REPEAT

		case xMETA_QUERY, xMETA_QUERY_PLUS, xMETA_QUERY_QUERY:
			repeat_min = 0
			repeat_max = 1
			goto REPEAT

		// 32-bit data character greater than META_END. (8017)
		case xMETA_BIGVALUE:
			pptr++
			goto NORMAL_CHAR

		// Back reference by number. (8029)
		case xMETA_BACKREF:
			if meta_arg < 10 {
				offset = cb.smallRefOffset[meta_arg]
			} else {
				getPlusOffset()
			}
			if meta_arg > cb.bracount {
				cb.erroroffset = offset
				*errorcodeptr = xERR15
				return 0
			}
			goto HANDLE_SINGLE_REFERENCE

		// Recursion. (8070)
		case xMETA_RECURSE:
			getPlusOffset()
			if meta_arg > cb.bracount {
				cb.erroroffset = offset
				*errorcodeptr = xERR15
				return 0
			}
			goto HANDLE_NUMERICAL_RECURSION

		// Capturing parentheses. (8093)
		case xMETA_CAPTURE:
			bravalue = xOP_CBRA
			skipunits = xIMM2_SIZE
			xPUT2(code, cc+1+xLINK_SIZE, int(meta_arg))
			cb.lastcapture = meta_arg
			goto GROUP_PROCESS_NOTE_EMPTY

		// Escape sequence items. (8113)
		case xMETA_ESCAPE:
			if meta_arg > xESC_b && meta_arg < xESC_Z {
				matched_char = true
				if firstcuflags == xREQ_UNSET {
					firstcuflags = xREQ_NONE
				}
			}

			zerofirstcu = firstcu
			zerofirstcuflags = firstcuflags
			zeroreqcu = reqcu
			zeroreqcuflags = reqcuflags

			if meta_arg == xESC_P || meta_arg == xESC_p {
				pptr++
				ptype := pp[pptr] >> 16
				pdata := pp[pptr] & 0xffff

				if meta_arg == xESC_p && ptype == xPT_ANY {
					emit(xOP_ALLANY)
				} else {
					if meta_arg == xESC_p {
						emit(xOP_PROP)
					} else {
						emit(xOP_NOTPROP)
					}
					emit(ptype)
					emit(pdata)
				}
				continue mainloop
			}

			// \K is forbidden in lookarounds since 10.38.
			if cb.assertDepth > 0 && meta_arg == xESC_K &&
				xoptions&PCRE2_EXTRA_ALLOW_LOOKAROUND_BSK == 0 {
				*errorcodeptr = xERR99
				return 0
			}

			switch meta_arg {
			case xESC_C:
				cb.externalFlags |= PCRE2_HASBKC
				if !utf {
					meta_arg = xOP_ALLANY
				}

			case xESC_B, xESC_b:
				if options&PCRE2_UCP != 0 && xoptions&PCRE2_EXTRA_ASCII_BSW == 0 {
					if meta_arg == xESC_B {
						meta_arg = xOP_NOT_UCP_WORD_BOUNDARY
					} else {
						meta_arg = xOP_UCP_WORD_BOUNDARY
					}
				}
				if cb.maxLookbehind == 0 {
					cb.maxLookbehind = 1
				}

			case xESC_A:
				if cb.maxLookbehind == 0 {
					cb.maxLookbehind = 1
				}
			}

			emit(meta_arg)
			continue mainloop

		// Unrecognized meta value or a literal character. (8213)
		default:
			if meta >= xMETA_END {
				*errorcodeptr = xERR89
				return 0
			}
			goto NORMAL_CHAR
		}

		// ---------------------------------------------------------------
		// Code reached by goto from the switch above (C labels).

	VERB_ARG: // (6547)
		emit(verbops[(meta-xMETA_MARK)>>16])
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

		if note_group_empty && bravalue != xOP_COND && group_return > 0 {
			matched_char = true
		}

		if bravalue >= xOP_ASSERT && bravalue <= xOP_ASSERTBACK_NA {
			cb.assertDepth--
		}

		// Conditional group branch counting, real compile phase only. (6870)
		if bravalue == xOP_COND && lengthptr == nil {
			tc := cc
			condcount := 0

			for {
				condcount++
				tc += xGET(code, tc+1)
				if code[tc] == xOP_KET {
					break
				}
			}

			if code[cc+xLINK_SIZE+1] == xOP_DEFINE {
				if condcount > 1 {
					cb.erroroffset = offset
					*errorcodeptr = xERR54
					return 0
				}
				code[cc+xLINK_SIZE+1] = xOP_FALSE
				bravalue = xOP_DEFINE // A flag to suppress char handling below
			} else {
				if condcount > 2 {
					cb.erroroffset = offset
					*errorcodeptr = xERR27
					return 0
				}
				if condcount == 1 {
					subfirstcuflags = xREQ_NONE
					subreqcuflags = xREQ_NONE
				} else if group_return > 0 {
					matched_char = true
				}
			}
		}

		// Pre-compile phase: update the length and shrink the group. (6920)
		if lengthptr != nil {
			if uint64(xOFLOW_MAX)-*lengthptr < length_prevgroup-2-2*xLINK_SIZE {
				*errorcodeptr = xERR20
				return 0
			}
			*lengthptr += length_prevgroup - 2 - 2*xLINK_SIZE
			cc++ // This already contains bravalue
			cc = xPUTINC(code, cc, 1+xLINK_SIZE)
			emit(xOP_KET)
			cc = xPUTINC(code, cc, 1+xLINK_SIZE)
			continue mainloop
		}

		cc = tempcode

		if bravalue == xOP_DEFINE {
			continue mainloop
		}

		zeroreqcu = reqcu
		zeroreqcuflags = reqcuflags
		zerofirstcu = firstcu
		zerofirstcuflags = firstcuflags
		groupsetfirstcu = false

		if bravalue >= xOP_ONCE { // Not an assertion
			if firstcuflags == xREQ_UNSET && subfirstcuflags != xREQ_UNSET {
				if subfirstcuflags < xREQ_NONE {
					firstcu = subfirstcu
					firstcuflags = subfirstcuflags
					groupsetfirstcu = true
				} else {
					firstcuflags = xREQ_NONE
				}
				zerofirstcuflags = xREQ_NONE
			} else if subfirstcuflags < xREQ_NONE && subreqcuflags >= xREQ_NONE {
				subreqcu = subfirstcu
				subreqcuflags = subfirstcuflags | tempreqvary
			}

			if subreqcuflags < xREQ_NONE {
				reqcu = subreqcu
				reqcuflags = subreqcuflags
			}
		} else if (bravalue == xOP_ASSERT || bravalue == xOP_ASSERT_NA) &&
			subreqcuflags < xREQ_NONE && subfirstcuflags < xREQ_NONE {
			reqcu = subreqcu
			reqcuflags = subreqcuflags
		}
		continue mainloop

	HANDLE_SINGLE_REFERENCE: // (8046)
		if firstcuflags == xREQ_UNSET {
			firstcuflags = xREQ_NONE
			zerofirstcuflags = xREQ_NONE
		}
		if options&PCRE2_CASELESS != 0 {
			emit(xOP_REFI)
		} else {
			emit(xOP_REF)
		}
		cc = xPUT2INC(code, cc, int(meta_arg))

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
		code[cc] = xOP_RECURSE
		xPUT(code, cc+1, int(meta_arg))
		cc += 1 + xLINK_SIZE
		groupsetfirstcu = false
		cb.hadRecurse = true
		if firstcuflags == xREQ_UNSET {
			firstcuflags = xREQ_NONE
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
			reqvary = xREQ_VARY
		}
		op_type = 0

		if repeat_min == 0 {
			firstcu = zerofirstcu
			firstcuflags = zerofirstcuflags
			reqcu = zeroreqcu
			reqcuflags = zeroreqcuflags
		}

		switch meta {
		case xMETA_MINMAX_PLUS, xMETA_ASTERISK_PLUS, xMETA_PLUS_PLUS, xMETA_QUERY_PLUS:
			repeat_type = 0
			possessive_quantifier = true
		case xMETA_MINMAX_QUERY, xMETA_ASTERISK_QUERY, xMETA_PLUS_QUERY, xMETA_QUERY_QUERY:
			repeat_type = greedy_non_default
			possessive_quantifier = false
		default:
			repeat_type = greedy_default
			possessive_quantifier = false
		}

		tempcode = previous
		op_previous = code[previous]

		switch op_previous {
		case xOP_CHAR, xOP_CHARI, xOP_NOT, xOP_NOTI:
			if repeat_max == 1 && repeat_min == 1 {
				goto END_REPEAT
			}
			op_type = chartypeoffset[op_previous-xOP_CHAR]

			if utf && xNOT_FIRSTCU(uint32(code[cc-1])) {
				lastchar := xBACKCHAR(code, cc-1)
				mclength = uint32(cc - lastchar)
				copy(mcbuffer[:], code[lastchar:cc])
			} else {
				mcbuffer[0] = code[cc-1]
				mclength = 1
				if op_previous <= xOP_CHARI && repeat_min > 1 {
					reqcu = uint32(mcbuffer[0])
					reqcuflags = cb.reqVaryopt
					if op_previous == xOP_CHARI {
						reqcuflags |= xREQ_CASELESS
					}
				}
			}
			prop_type = -1
			prop_value = -1
			goto SINGLE_REPEAT_BODY

		case xOP_XCLASS, xOP_CLASS, xOP_NCLASS, xOP_REF, xOP_REFI, xOP_DNREF, xOP_DNREFI:
			if repeat_max == 0 {
				cc = previous
				goto END_REPEAT
			}
			if repeat_max == 1 && repeat_min == 1 {
				goto END_REPEAT
			}

			if repeat_min == 0 && repeat_max == xREPEAT_UNLIMITED {
				emit(xOP_CRSTAR + repeat_type)
			} else if repeat_min == 1 && repeat_max == xREPEAT_UNLIMITED {
				emit(xOP_CRPLUS + repeat_type)
			} else if repeat_min == 0 && repeat_max == 1 {
				emit(xOP_CRQUERY + repeat_type)
			} else {
				emit(xOP_CRRANGE + repeat_type)
				cc = xPUT2INC(code, cc, int(repeat_min))
				if repeat_max == xREPEAT_UNLIMITED {
					repeat_max = 0
				}
				cc = xPUT2INC(code, cc, int(repeat_max))
			}

		case xOP_FAIL:
			goto END_REPEAT

		case xOP_RECURSE:
			if repeat_max == 1 && repeat_min == 1 && !possessive_quantifier {
				goto END_REPEAT
			}

			if repeat_min > 0 && (repeat_min != 1 || repeat_max != xREPEAT_UNLIMITED) {
				replicate := int32(repeat_min)
				if repeat_min == repeat_max {
					replicate--
				}

				if lengthptr != nil {
					var delta uint64
					if ckd_smul(&delta, replicate, 1+xLINK_SIZE) ||
						uint64(xOFLOW_MAX)-*lengthptr < delta {
						*errorcodeptr = xERR20
						return 0
					}
					*lengthptr += delta
				} else {
					for i := int32(0); i < replicate; i++ {
						copy(code[cc:cc+1+xLINK_SIZE], code[previous:previous+1+xLINK_SIZE])
						previous = cc
						cc += 1 + xLINK_SIZE
					}
				}

				if repeat_min == repeat_max {
					goto POSSESSIVE
				}
				if repeat_max != xREPEAT_UNLIMITED {
					repeat_max -= repeat_min
				}
				repeat_min = 0
			}

			// Wrap the recursion call in OP_BRA brackets.
			copy(code[previous+1+xLINK_SIZE:previous+2+2*xLINK_SIZE], code[previous:previous+1+xLINK_SIZE])
			code[previous] = xOP_BRA
			op_previous = xOP_BRA
			xPUT(code, previous+1, 2+2*xLINK_SIZE)
			code[previous+2+2*xLINK_SIZE] = xOP_KET
			xPUT(code, previous+3+2*xLINK_SIZE, 2+2*xLINK_SIZE)
			cc += 2 + 2*xLINK_SIZE
			length_prevgroup = 3 + 3*xLINK_SIZE
			group_return = -1 // Set "may match empty string"
			fallthrough

		case xOP_ASSERT, xOP_ASSERT_NOT, xOP_ASSERT_NA, xOP_ASSERTBACK, xOP_ASSERTBACK_NOT,
			xOP_ASSERTBACK_NA, xOP_ONCE, xOP_SCRIPT_RUN, xOP_BRA, xOP_CBRA, xOP_COND:
			rlen = cc - previous
			bralink = -1
			brazeroptr = -1

			if repeat_max == 1 && repeat_min == 1 && !possessive_quantifier {
				goto END_REPEAT
			}

			// Repeating a DEFINE group is pointless.
			if op_previous == xOP_COND && code[previous+xLINK_SIZE+1] == xOP_FALSE &&
				code[previous+xGET(code, previous+1)] != xOP_ALT {
				goto END_REPEAT
			}

			if op_previous < xOP_ONCE { // Assertion
				if repeat_max == xREPEAT_UNLIMITED {
					repeat_max = repeat_min + 1
				}
			}

			if repeat_min == 0 {
				if repeat_max <= 1 || repeat_max == xREPEAT_UNLIMITED {
					copy(code[previous+1:previous+1+rlen], code[previous:previous+rlen])
					cc++
					if repeat_max == 0 {
						code[previous] = xOP_SKIPZERO
						previous++
						goto END_REPEAT
					}
					brazeroptr = previous // Save for possessive optimizing
					code[previous] = byte(xOP_BRAZERO + repeat_type)
					previous++
				} else {
					copy(code[previous+2+xLINK_SIZE:previous+2+xLINK_SIZE+rlen], code[previous:previous+rlen])
					cc += 2 + xLINK_SIZE
					code[previous] = byte(xOP_BRAZERO + repeat_type)
					previous++
					code[previous] = xOP_BRA
					previous++

					linkoffset := 0
					if bralink >= 0 {
						linkoffset = previous - bralink
					}
					bralink = previous
					previous = xPUTINC(code, previous, linkoffset)
				}

				if repeat_max != xREPEAT_UNLIMITED {
					repeat_max--
				}
			} else {
				if repeat_min > 1 {
					if lengthptr != nil {
						var delta uint64
						if ckd_smul(&delta, int32(repeat_min-1), int32(length_prevgroup)) ||
							uint64(xOFLOW_MAX)-*lengthptr < delta {
							*errorcodeptr = xERR20
							return 0
						}
						*lengthptr += delta
					} else {
						if groupsetfirstcu && reqcuflags >= xREQ_NONE {
							reqcu = firstcu
							reqcuflags = firstcuflags
						}
						for i := uint32(1); i < repeat_min; i++ {
							copy(code[cc:cc+rlen], code[previous:previous+rlen])
							cc += rlen
						}
					}
				}

				if repeat_max != xREPEAT_UNLIMITED {
					repeat_max -= repeat_min
				}
			}

			if repeat_max != xREPEAT_UNLIMITED {
				if lengthptr != nil && repeat_max > 0 {
					var delta uint64
					if ckd_smul(&delta, int32(repeat_max), int32(length_prevgroup)+1+2+2*xLINK_SIZE) ||
						uint64(xOFLOW_MAX)+(2+2*xLINK_SIZE)-*lengthptr < delta {
						*errorcodeptr = xERR20
						return 0
					}
					delta -= 2 + 2*xLINK_SIZE // Last one doesn't nest
					*lengthptr += delta
				} else {
					for i := repeat_max; i >= 1; i-- {
						code[cc] = byte(xOP_BRAZERO + repeat_type)
						cc++

						if i != 1 {
							code[cc] = xOP_BRA
							cc++
							linkoffset := 0
							if bralink >= 0 {
								linkoffset = cc - bralink
							}
							bralink = cc
							cc = xPUTINC(code, cc, linkoffset)
						}

						copy(code[cc:cc+rlen], code[previous:previous+rlen])
						cc += rlen
					}
				}

				// pcre2_compile.c:7639: runs in both phases.
				for bralink >= 0 {
					linkoffset := cc - bralink + 1
					bra := cc - linkoffset
					oldlinkoffset := xGET(code, bra+1)
					if oldlinkoffset == 0 {
						bralink = -1
					} else {
						bralink -= oldlinkoffset
					}
					code[cc] = xOP_KET
					cc++
					cc = xPUTINC(code, cc, linkoffset)
					xPUT(code, bra+1, linkoffset)
				}
			} else {
				// Unlimited maximum: set a repeater in the final copy. (7678)
				ketcode := cc - 1 - xLINK_SIZE
				bracode := ketcode - xGET(code, ketcode+1)

				// Convert possessive ONCE brackets to non-capturing.
				if code[bracode] == xOP_ONCE && possessive_quantifier {
					code[bracode] = xOP_BRA
				}

				if code[bracode] == xOP_ONCE || code[bracode] == xOP_SCRIPT_RUN {
					code[ketcode] = byte(xOP_KETRMAX + repeat_type)
				} else {
					if lengthptr == nil {
						if group_return < 0 {
							code[bracode] += xOP_SBRA - xOP_BRA
						}
						if code[bracode] == xOP_COND && code[bracode+xGET(code, bracode+1)] != xOP_ALT {
							code[bracode] = xOP_SCOND
						}
					}

					if possessive_quantifier {
						if code[bracode] == xOP_COND || code[bracode] == xOP_SCOND {
							nlen := cc - bracode
							copy(code[bracode+1+xLINK_SIZE:bracode+1+xLINK_SIZE+nlen], code[bracode:bracode+nlen])
							cc += 1 + xLINK_SIZE
							nlen += 1 + xLINK_SIZE
							if code[bracode] == xOP_COND {
								code[bracode] = xOP_BRAPOS
							} else {
								code[bracode] = xOP_SBRAPOS
							}
							code[cc] = xOP_KETRPOS
							cc++
							cc = xPUTINC(code, cc, nlen)
							xPUT(code, bracode+1, nlen)
						} else {
							code[bracode]++ // Switch to xxxPOS opcodes
							code[ketcode] = xOP_KETRPOS
						}

						if brazeroptr >= 0 {
							code[brazeroptr] = xOP_BRAPOSZERO
						}
						if repeat_min < 2 {
							possessive_quantifier = false
						}
					} else {
						code[ketcode] = byte(xOP_KETRMAX + repeat_type)
					}
				}
			}

		default:
			// Character type match (\d or similar), or an internal error. (7760)
			if op_previous >= xOP_EODN {
				*errorcodeptr = xERR10
				return 0
			}
			if repeat_max == 1 && repeat_min == 1 {
				goto END_REPEAT
			}

			op_type = xOP_TYPESTAR - xOP_STAR // Use type opcodes
			mclength = 0                      // Not a character

			if op_previous == xOP_PROP || op_previous == xOP_NOTPROP {
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
			if repeat_max == xREPEAT_UNLIMITED {
				emit(xOP_STAR + repeat_type)
			} else if repeat_max == 1 {
				emit(xOP_QUERY + repeat_type)
			} else {
				emit(xOP_UPTO + repeat_type)
				cc = xPUT2INC(code, cc, int(repeat_max))
			}
		} else if repeat_min == 1 {
			if repeat_max == xREPEAT_UNLIMITED {
				emit(xOP_PLUS + repeat_type)
			} else {
				cc = oldcode // Leave previous item in place
				if repeat_max == 1 {
					goto END_REPEAT
				}
				emit(xOP_UPTO + repeat_type)
				cc = xPUT2INC(code, cc, int(repeat_max-1))
			}
		} else {
			emit(xOP_EXACT + op_type) // NB EXACT doesn't have repeat_type
			cc = xPUT2INC(code, cc, int(repeat_min))

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

				if repeat_max == xREPEAT_UNLIMITED {
					emit(xOP_STAR + repeat_type)
				} else {
					repeat_max -= repeat_min
					if repeat_max == 1 {
						emit(xOP_QUERY + repeat_type)
					} else {
						emit(xOP_UPTO + repeat_type)
						cc = xPUT2INC(code, cc, int(repeat_max))
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
			case xOP_TYPEEXACT:
				add := 0
				if code[tempcode+1+xIMM2_SIZE] == xOP_PROP || code[tempcode+1+xIMM2_SIZE] == xOP_NOTPROP {
					add = 2
				}
				tempcode += int(xOP_lengths[code[tempcode]]) + add

			case xOP_CHAR, xOP_CHARI, xOP_NOT, xOP_NOTI, xOP_EXACT, xOP_EXACTI, xOP_NOTEXACT, xOP_NOTEXACTI:
				tempcode += int(xOP_lengths[code[tempcode]])
				if utf && xHAS_EXTRALEN(uint32(code[tempcode-1])) {
					tempcode += xGET_EXTRALEN(uint32(code[tempcode-1]))
				}

			case xOP_CLASS, xOP_NCLASS:
				tempcode += 1 + 32

			case xOP_XCLASS:
				tempcode += xGET(code, tempcode+1)
			}

			rlen = cc - tempcode
			if rlen > 0 {
				repcode := uint32(code[tempcode])

				if repcode < xOP_CALLOUT && opcode_possessify[repcode] > 0 {
					code[tempcode] = opcode_possessify[repcode]
				} else {
					copy(code[tempcode+1+xLINK_SIZE:tempcode+1+xLINK_SIZE+rlen], code[tempcode:tempcode+rlen])
					cc += 1 + xLINK_SIZE
					rlen += 1 + xLINK_SIZE
					code[tempcode] = xOP_ONCE
					code[cc] = xOP_KET
					cc++
					cc = xPUTINC(code, cc, rlen)
					xPUT(code, tempcode+1, rlen)
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
			caseset := uint32(xUCD_CASESET(meta))
			if caseset != 0 &&
				(xoptions&PCRE2_EXTRA_CASELESS_RESTRICT == 0 || ucd_caseless_sets[caseset] > 127) {
				emit(xOP_PROP)
				emit(xPT_CLIST)
				emit(caseset)
				if firstcuflags == xREQ_UNSET {
					firstcuflags = xREQ_NONE
					zerofirstcuflags = xREQ_NONE
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
			emit(xOP_CHARI)
		} else {
			emit(xOP_CHAR)
		}
		copy(code[cc:], mcbuffer[:mclength])
		cc += int(mclength)

		if mcbuffer[0] == xCHAR_CR || mcbuffer[0] == xCHAR_NL {
			cb.externalFlags |= PCRE2_HASCRORLF
		}

		if firstcuflags == xREQ_UNSET {
			zerofirstcuflags = xREQ_NONE
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
				firstcuflags = xREQ_NONE
				reqcuflags = xREQ_NONE
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
