// Port of pcre2_substring.c: extracting captured substrings. The C "size in /
// size out" buffer parameter becomes len(buffer) and the returned size; the
// functions that allocate return a fresh []byte (without the C trailing zero:
// the length is the slice length). Names are Go strings.
package pcre2

// SubstringCopyByName is pcre2_substring_copy_byname(): it copies the named
// substring into buffer, zero terminated, and returns its length. If the
// pattern permits duplicate names the first set group is used.
// (pcre2_substring.c:73)
func SubstringCopyByName(md *MatchData, stringname string, buffer []byte) (uint64, int) {
	if md.matchedby == PCRE2_MATCHEDBY_DFA_INTERPRETER {
		return 0, PCRE2_ERROR_DFA_UFUNC
	}
	entrysize, first, last := SubstringNametableScan(md.code, stringname)
	if entrysize < 0 {
		return 0, entrysize
	}
	failrc := PCRE2_ERROR_UNAVAILABLE
	nt := md.code.nameTable()
	for entry := first; entry <= last; entry += entrysize {
		n := uint32(GET2(nt, entry))
		if n < uint32(md.oveccount) {
			if md.ovector[n*2] != PCRE2_UNSET {
				return SubstringCopyByNumber(md, n, buffer)
			}
			failrc = PCRE2_ERROR_UNSET
		}
	}
	return 0, failrc
}

// SubstringCopyByNumber is pcre2_substring_copy_bynumber(): the substring is
// copied into buffer followed by a zero; PCRE2_ERROR_NOMEMORY if buffer is too
// small. It returns the substring length. (pcre2_substring.c:121)
func SubstringCopyByNumber(md *MatchData, stringnumber uint32, buffer []byte) (uint64, int) {
	size, rc := SubstringLengthByNumber(md, stringnumber)
	if rc < 0 {
		return 0, rc
	}
	if size+1 > uint64(len(buffer)) {
		return 0, PCRE2_ERROR_NOMEMORY
	}
	copyFromSubject(buffer, md, stringnumber, size)
	buffer[size] = 0
	return size, 0
}

// copyFromSubject copies size bytes of the substring; an unset or empty group
// copies nothing (C avoids adding PCRE2_UNSET to the subject pointer).
func copyFromSubject(dst []byte, md *MatchData, n uint32, size uint64) {
	if size != 0 {
		start := md.ovector[n*2]
		copy(dst[:size], md.subject[start:start+size])
	}
}

// SubstringGetByName is pcre2_substring_get_byname(): the named substring in a
// new slice. (pcre2_substring.c:161)
func SubstringGetByName(md *MatchData, stringname string) ([]byte, int) {
	if md.matchedby == PCRE2_MATCHEDBY_DFA_INTERPRETER {
		return nil, PCRE2_ERROR_DFA_UFUNC
	}
	entrysize, first, last := SubstringNametableScan(md.code, stringname)
	if entrysize < 0 {
		return nil, entrysize
	}
	failrc := PCRE2_ERROR_UNAVAILABLE
	nt := md.code.nameTable()
	for entry := first; entry <= last; entry += entrysize {
		n := uint32(GET2(nt, entry))
		if n < uint32(md.oveccount) {
			if md.ovector[n*2] != PCRE2_UNSET {
				return SubstringGetByNumber(md, n)
			}
			failrc = PCRE2_ERROR_UNSET
		}
	}
	return nil, failrc
}

// SubstringGetByNumber is pcre2_substring_get_bynumber(): the substring in a
// new slice. (pcre2_substring.c:209)
func SubstringGetByNumber(md *MatchData, stringnumber uint32) ([]byte, int) {
	size, rc := SubstringLengthByNumber(md, stringnumber)
	if rc < 0 {
		return nil, rc
	}
	yield := make([]byte, size)
	copyFromSubject(yield, md, stringnumber, size)
	return yield, 0
}

// SubstringFree is pcre2_substring_free(); a no-op (garbage collected).
func SubstringFree(s []byte) {}

// SubstringLengthByName is pcre2_substring_length_byname().
// (pcre2_substring.c:268)
func SubstringLengthByName(md *MatchData, stringname string) (uint64, int) {
	if md.matchedby == PCRE2_MATCHEDBY_DFA_INTERPRETER {
		return 0, PCRE2_ERROR_DFA_UFUNC
	}
	entrysize, first, last := SubstringNametableScan(md.code, stringname)
	if entrysize < 0 {
		return 0, entrysize
	}
	failrc := PCRE2_ERROR_UNAVAILABLE
	nt := md.code.nameTable()
	for entry := first; entry <= last; entry += entrysize {
		n := uint32(GET2(nt, entry))
		if n < uint32(md.oveccount) {
			if md.ovector[n*2] != PCRE2_UNSET {
				return SubstringLengthByNumber(md, n)
			}
			failrc = PCRE2_ERROR_UNSET
		}
	}
	return 0, failrc
}

// SubstringLengthByNumber is pcre2_substring_length_bynumber(). If the start is
// beyond the end (which can happen when \K is used in an assertion), the
// length is zero. (pcre2_substring.c:316)
func SubstringLengthByNumber(md *MatchData, stringnumber uint32) (uint64, int) {
	count := md.rc
	if count == PCRE2_ERROR_PARTIAL {
		if stringnumber > 0 {
			return 0, PCRE2_ERROR_PARTIAL
		}
		count = 0
	} else if count < 0 {
		return 0, count // Match failed
	}

	if md.matchedby != PCRE2_MATCHEDBY_DFA_INTERPRETER {
		if stringnumber > uint32(md.code.topBracket) {
			return 0, PCRE2_ERROR_NOSUBSTRING
		}
		if stringnumber >= uint32(md.oveccount) {
			return 0, PCRE2_ERROR_UNAVAILABLE
		}
		if md.ovector[stringnumber*2] == PCRE2_UNSET {
			return 0, PCRE2_ERROR_UNSET
		}
	} else { // Matched using pcre2_dfa_match()
		if stringnumber >= uint32(md.oveccount) {
			return 0, PCRE2_ERROR_UNAVAILABLE
		}
		if count != 0 && stringnumber >= uint32(count) {
			return 0, PCRE2_ERROR_UNSET
		}
	}

	left := md.ovector[stringnumber*2]
	right := md.ovector[stringnumber*2+1]
	if left > md.subjectLength || right > md.subjectLength {
		return 0, PCRE2_ERROR_INVALIDOFFSET
	}
	if left > right {
		return 0, 0
	}
	return right - left, 0
}

// SubstringListGet is pcre2_substring_list_get(): all captured substrings (a
// group that is unset gives an empty one) and their lengths. (pcre2_substring.c:375)
func SubstringListGet(md *MatchData) (list [][]byte, lengths []uint64, rc int) {
	count := md.rc
	if count < 0 {
		return nil, nil, count // Match failed
	}
	if count == 0 {
		count = int(md.oveccount) // Ovector too small
	}
	ovector := md.ovector
	list = make([][]byte, count)
	lengths = make([]uint64, count)
	for i := 0; i < count; i++ {
		var size uint64
		if ovector[2*i+1] > ovector[2*i] {
			size = ovector[2*i+1] - ovector[2*i]
		}
		// Size == 0 includes the case when the capture is unset.
		sp := make([]byte, size)
		if size != 0 {
			copy(sp, md.subject[ovector[2*i]:ovector[2*i]+size])
		}
		list[i] = sp
		lengths[i] = size
	}
	return list, lengths, 0
}

// SubstringListFree is pcre2_substring_list_free(); a no-op.
func SubstringListFree(list [][]byte) {}

// SubstringNametableScan is pcre2_substring_nametable_scan() with firstptr and
// lastptr: it finds the entries for stringname by binary chop and returns the
// entry size and the byte offsets (in the name table) of the first and last
// entry, or entrysize PCRE2_ERROR_NOSUBSTRING if the name is not found.
// (pcre2_substring.c:483)
func SubstringNametableScan(code *Code, stringname string) (entrysize, first, last int) {
	entry, f, l, rc := nametableScan(code, stringname)
	_ = entry
	if rc < 0 {
		return rc, 0, 0
	}
	return int(code.nameEntrySize), f, l
}

// nametableScan is the shared body: it returns the matching entry, first and
// last duplicate offsets, or a negative code in rc.
func nametableScan(code *Code, stringname string) (entry, first, last, rc int) {
	var bot uint16
	top := code.nameCount
	entrysize := int(code.nameEntrySize)
	nametable := code.nameTable()
	name := []byte(stringname)

	for top > bot {
		mid := (top + bot) / 2
		entry = entrysize * int(mid)
		c := strcmp(name, nametable[entry+IMM2_SIZE:])
		if c == 0 {
			lastentry := entrysize * (int(code.nameCount) - 1)
			first, last = entry, entry
			for first > 0 {
				if strcmp(name, nametable[first-entrysize+IMM2_SIZE:]) != 0 {
					break
				}
				first -= entrysize
			}
			for last < lastentry {
				if strcmp(name, nametable[last+entrysize+IMM2_SIZE:]) != 0 {
					break
				}
				last += entrysize
			}
			return entry, first, last, 0
		}
		if c > 0 {
			bot = mid + 1
		} else {
			top = mid
		}
	}
	return 0, 0, 0, PCRE2_ERROR_NOSUBSTRING
}

// SubstringNumberFromName is pcre2_substring_number_from_name(): the group
// number of the named parenthesis, PCRE2_ERROR_NOSUBSTRING if not found, or
// PCRE2_ERROR_NOUNIQUESUBSTRING if the name is not unique.
// (pcre2_substring.c:544)
func SubstringNumberFromName(code *Code, stringname string) int {
	entry, first, last, rc := nametableScan(code, stringname)
	if rc < 0 {
		return rc
	}
	if first == last {
		return GET2(code.nameTable(), entry)
	}
	return PCRE2_ERROR_NOUNIQUESUBSTRING
}
