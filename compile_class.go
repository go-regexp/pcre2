// Port of pcre2_compile.c: first_significant_code, the "add to class" family
// and find_dupname_details (pcre2_compile.c:5043-5600).
//
// Conventions: pointers into compiled code are (code []byte, index int);
// uint8_t *classbits is a []byte; PCRE2_UCHAR **uchardptr is (buf []byte,
// uchardptr *int).
package pcre2

// first_significant_code is first_significant_code() (pcre2_compile.c:5060):
// it skips opcodes that do not influence a search for a fixed first character
// or an anchoring opcode and returns the index of the first significant one.
func first_significant_code(code []byte, cc int, skipassert bool) int {
	for {
		switch int(code[cc]) {
		case xOP_ASSERT_NOT, xOP_ASSERTBACK, xOP_ASSERTBACK_NOT, xOP_ASSERTBACK_NA:
			if !skipassert {
				return cc
			}
			for {
				cc += xGET(code, cc+1)
				if code[cc] != xOP_ALT {
					break
				}
			}
			cc += int(xOP_lengths[code[cc]])

		case xOP_WORD_BOUNDARY, xOP_NOT_WORD_BOUNDARY, xOP_UCP_WORD_BOUNDARY, xOP_NOT_UCP_WORD_BOUNDARY:
			if !skipassert {
				return cc
			}
			cc += int(xOP_lengths[code[cc]])

		case xOP_CALLOUT, xOP_CREF, xOP_DNCREF, xOP_RREF, xOP_DNRREF, xOP_FALSE, xOP_TRUE:
			cc += int(xOP_lengths[code[cc]])

		case xOP_CALLOUT_STR:
			cc += xGET(code, cc+1+2*xLINK_SIZE)

		case xOP_SKIPZERO:
			cc += 2 + xGET(code, cc+2) + xLINK_SIZE

		case xOP_COND, xOP_SCOND:
			if code[cc+1+xLINK_SIZE] != xOP_FALSE || // Not DEFINE
				code[cc+xGET(code, cc+1)] != xOP_KET { // More than one branch
				return cc
			}
			cc += xGET(code, cc+1) + 1 + xLINK_SIZE

		case xOP_MARK, xOP_COMMIT_ARG, xOP_PRUNE_ARG, xOP_SKIP_ARG, xOP_THEN_ARG:
			cc += int(code[cc+1]) + int(xOP_lengths[code[cc]])

		default:
			return cc
		}
	}
}

// get_othercase_range is get_othercase_range() (pcre2_compile.c:5150). cptr
// is updated; it returns -1 when no more, 0 when a range is returned, >0 the
// CASESET offset for a character with multiple other cases (*ocptr then holds
// the original).
func get_othercase_range(cptr *uint32, d uint32, ocptr *uint32, odptr *uint32, restricted bool) int {
	var c, othercase, next uint32
	var co uint32

	for c = *cptr; c <= d; c++ {
		co = uint32(xUCD_CASESET(c))
		if co != 0 && (!restricted || ucd_caseless_sets[co] > 127) {
			*ocptr = c // Character that has the set
			c++
			*cptr = c // Rest of input range
			return int(co)
		}

		othercase = xUCD_OTHERCASE(c)
		if othercase != c {
			break
		}
	}

	if c > d {
		return -1 // Reached end of range
	}

	*ocptr = othercase
	next = othercase + 1

	for c++; c <= d; c++ {
		if xUCD_CASESET(c) != 0 || xUCD_OTHERCASE(c) != next {
			break
		}
		next++
	}

	*odptr = next - 1 // End of othercase range
	*cptr = c         // Rest of input range
	return 0
}

// add_to_class_internal is add_to_class_internal() (pcre2_compile.c:5230).
// It returns the number of < 256 characters added; *uchardptr is advanced
// over the extra data written to buf.
func add_to_class_internal(classbits []byte, buf []byte, uchardptr *int, options uint32,
	xoptions uint32, cb *compile_block, start uint32, end uint32) uint {
	var c uint32
	classbitsEnd := end
	if end > 0xff {
		classbitsEnd = 0xff
	}
	var n8 uint

	if options&PCRE2_CASELESS != 0 {
		if options&(PCRE2_UTF|PCRE2_UCP) != 0 {
			var rc int
			var oc, od uint32

			options &^= PCRE2_CASELESS // Remove for recursive calls
			c = start

			for {
				rc = get_othercase_range(&c, end, &oc, &od, xoptions&PCRE2_EXTRA_CASELESS_RESTRICT != 0)
				if rc < 0 {
					break
				}
				if rc > 0 {
					// A single character that has more than one other case.
					n8 += add_list_to_class_internal(classbits, buf, uchardptr, options, xoptions, cb,
						ucd_caseless_sets[rc:], uint(oc))
				} else if oc >= cb.classRangeStart && od <= cb.classRangeEnd {
					// The other case range is within the original range.
					continue
				} else if oc < start && od >= start-1 {
					start = oc // Extend downwards
				} else if od > end && oc <= end+1 {
					end = od // Extend upwards
					if end > classbitsEnd {
						if end <= 0xff {
							classbitsEnd = end
						} else {
							classbitsEnd = 0xff
						}
					}
				} else {
					n8 += add_to_class_internal(classbits, buf, uchardptr, options, xoptions, cb, oc, od)
				}
			}
		} else {
			// Not UTF mode
			for c = start; c <= classbitsEnd; c++ {
				f := uint32(cb.fcc[c])
				classbits[f/8] |= byte(1 << (f & 7))
				n8++
			}
		}
	}

	// Now handle the originally supplied range.
	if options&PCRE2_UTF == 0 && end > xMAX_NON_UTF_CHAR {
		end = xMAX_NON_UTF_CHAR
	}

	if start > cb.classRangeStart && end < cb.classRangeEnd {
		return n8
	}

	// Use the bitmap for characters < 256. Otherwise use extra data.
	for c = start; c <= classbitsEnd; c++ {
		classbits[c/8] |= byte(1 << (c & 7))
		n8++
	}

	if start <= 0xff {
		start = 0xff + 1
	}

	if end >= start {
		p := *uchardptr
		if options&PCRE2_UTF != 0 {
			if start < end {
				buf[p] = xXCL_RANGE
				p++
				p += int(ord2utf(start, buf[p:]))
				p += int(ord2utf(end, buf[p:]))
			} else if start == end {
				buf[p] = xXCL_SINGLE
				p++
				p += int(ord2utf(start, buf[p:]))
			}
		}
		// 8-bit, no UTF: nothing (character values cannot exceed 255).
		*uchardptr = p // Update extra data pointer
	}

	return n8 // Number of 8-bit characters
}

// add_list_to_class_internal is add_list_to_class_internal()
// (pcre2_compile.c:5393). p is a row of 32-bit values terminated by NOTACHAR.
func add_list_to_class_internal(classbits []byte, buf []byte, uchardptr *int, options uint32,
	xoptions uint32, cb *compile_block, p []uint32, except uint) uint {
	var n8 uint
	for p[0] < xNOTACHAR {
		n := 0
		if uint(p[0]) != except {
			for p[n+1] == p[0]+uint32(n)+1 {
				n++
			}
			n8 += add_to_class_internal(classbits, buf, uchardptr, options, xoptions, cb, p[0], p[n])
		}
		p = p[n+1:]
	}
	return n8
}

// add_to_class is add_to_class() (pcre2_compile.c:5436), the external entry
// point for adding a range to a class.
func add_to_class(classbits []byte, buf []byte, uchardptr *int, options uint32,
	xoptions uint32, cb *compile_block, start uint32, end uint32) uint {
	cb.classRangeStart = start
	cb.classRangeEnd = end
	return add_to_class_internal(classbits, buf, uchardptr, options, xoptions, cb, start, end)
}

// add_list_to_class is add_list_to_class() (pcre2_compile.c:5472): adds a
// list of (horizontal or vertical whitespace) characters to a class.
func add_list_to_class(classbits []byte, buf []byte, uchardptr *int, options uint32,
	xoptions uint32, cb *compile_block, p []uint32, except uint) uint {
	var n8 uint
	for p[0] < xNOTACHAR {
		n := 0
		if uint(p[0]) != except {
			for p[n+1] == p[0]+uint32(n)+1 {
				n++
			}
			cb.classRangeStart = p[0]
			cb.classRangeEnd = p[n]
			n8 += add_to_class_internal(classbits, buf, uchardptr, options, xoptions, cb, p[0], p[n])
		}
		p = p[n+1:]
	}
	return n8
}

// add_not_list_to_class is add_not_list_to_class() (pcre2_compile.c:5514):
// adds the complement of a list to a class.
func add_not_list_to_class(classbits []byte, buf []byte, uchardptr *int, options uint32,
	xoptions uint32, cb *compile_block, p []uint32) uint {
	utf := options&PCRE2_UTF != 0
	var n8 uint
	if p[0] > 0 {
		n8 += add_to_class(classbits, buf, uchardptr, options, xoptions, cb, 0, p[0]-1)
	}
	for p[0] < xNOTACHAR {
		for p[1] == p[0]+1 {
			p = p[1:]
		}
		var e uint32
		if p[1] == xNOTACHAR {
			if utf {
				e = 0x10ffff
			} else {
				e = 0xffffffff
			}
		} else {
			e = p[1] - 1
		}
		n8 += add_to_class(classbits, buf, uchardptr, options, xoptions, cb, p[0]+1, e)
		p = p[1:]
	}
	return n8
}

// find_dupname_details is find_dupname_details() (pcre2_compile.c:5553). name
// is the index in pat of the name (pat is the pattern, cb.startPattern).
func find_dupname_details(pat []byte, name int, length uint32, indexptr *int,
	countptr *int, errorcodeptr *int, cb *compile_block) bool {
	var i, groupnumber uint32
	var count int
	slot := 0
	nt := cb.nameTable

	// Find the first entry in the table
	for i = 0; i < uint32(cb.namesFound); i++ {
		if strncmp(pat[name:], nt[slot+xIMM2_SIZE:], uint64(length)) == 0 &&
			nt[slot+xIMM2_SIZE+int(length)] == 0 {
			break
		}
		slot += int(cb.nameEntrySize)
	}

	// This should not occur, because this function is called only when we know
	// we have duplicate names. Give an internal error.
	if i >= uint32(cb.namesFound) {
		*errorcodeptr = xERR53
		cb.erroroffset = uint64(name)
		return false
	}

	// Record the index and then see how many duplicates there are, updating
	// the backref map and maximum back reference as we do.
	*indexptr = int(i)
	count = 0

	for {
		count++
		groupnumber = uint32(xGET2(nt, slot))
		if groupnumber < 32 {
			cb.backrefMap |= 1 << groupnumber
		} else {
			cb.backrefMap |= 1
		}
		if groupnumber > cb.topBackref {
			cb.topBackref = groupnumber
		}
		i++
		if i >= uint32(cb.namesFound) {
			break
		}
		slot += int(cb.nameEntrySize)
		if strncmp(pat[name:], nt[slot+xIMM2_SIZE:], uint64(length)) != 0 ||
			nt[slot+xIMM2_SIZE+int(length)] != 0 {
			break
		}
	}

	*countptr = count
	return true
}
