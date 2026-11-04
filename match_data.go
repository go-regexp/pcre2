// Port of pcre2_match_data.c: match data blocks.
package pcre2

// matchDataOvectorOffset is offsetof(pcre2_match_data, ovector) on a 64-bit
// target: memctl(24) + code, subject, mark, heapframes, heapframes_size,
// subject_length, leftchar, rightchar, startchar (9*8) + matchedby, flags,
// oveccount, rc (1+1+2+4) = 104.
const matchDataOvectorOffset = 104

// NewMatchDataSize is pcre2_match_data_create(oveccount, NULL). A minimum of 1
// is imposed on the number of ovector pairs, and a maximum of 65535 because
// the oveccount field is 16 bits. (pcre2_match_data.c:58)
func NewMatchDataSize(oveccount uint32) *MatchData {
	if oveccount < 1 {
		oveccount = 1
	}
	if oveccount > 0xffff {
		oveccount = 0xffff
	}
	return &MatchData{
		oveccount: uint16(oveccount),
		ovector:   make([]uint64, 2*int(oveccount)),
	}
}

// NewMatchData is pcre2_match_data_create_from_pattern(). (pcre2_match_data.c:83)
func NewMatchData(c *Code) *MatchData {
	return NewMatchDataSize(uint32(c.topBracket) + 1)
}

// Free is pcre2_match_data_free(); the garbage collector does the work, the
// references are dropped to release the subject and frames early.
func (md *MatchData) Free() {
	if md == nil {
		return
	}
	md.heapframes = nil
	md.heapframesSz = 0
	md.subject = nil
	md.mark = nil
	md.flags &^= PCRE2_MD_COPIED_SUBJECT
}

// GetMark is pcre2_get_mark(): the last mark name seen, or nil.
func (md *MatchData) GetMark() []byte { return md.mark }

// Ovector is pcre2_get_ovector_pointer(): 2*OvectorCount() offsets, start and
// end of each group; PCRE2_UNSET marks an unset group. It aliases the block.
func (md *MatchData) Ovector() []uint64 { return md.ovector }

// OvectorCount is pcre2_get_ovector_count(): the number of pairs.
func (md *MatchData) OvectorCount() uint32 { return uint32(md.oveccount) }

// GetStartchar is pcre2_get_startchar().
func (md *MatchData) GetStartchar() uint64 { return md.startchar }

// GetMatchDataSize is pcre2_get_match_data_size(), as the C block would be.
func (md *MatchData) GetMatchDataSize() uint64 {
	return matchDataOvectorOffset + 2*uint64(md.oveccount)*8
}

// GetMatchDataHeapframesSize is pcre2_get_match_data_heapframes_size().
func (md *MatchData) GetMatchDataHeapframesSize() uint64 { return md.heapframesSz }

// Subject returns the subject the last match used (valid after a match).
func (md *MatchData) Subject() []byte { return md.subject }

// Code returns the pattern of the last match.
func (md *MatchData) Code() *Code { return md.code }

// Rc returns the return code of the last match.
func (md *MatchData) Rc() int { return md.rc }
