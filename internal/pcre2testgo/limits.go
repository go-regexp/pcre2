package pcre2testgo

import (
	"github.com/go-regexp/pcre2/internal/pcre2testgo/mods"
)

const (
	errMatchLimit = -47
	errDepthLimit = -53
	errHeapLimit  = -63

	// dfaStartRWSSize is DFA_START_RWS_SIZE of pcre2_dfa_match.c (bytes).
	dfaStartRWSSize = 30720
)

// HeapFramesFreer is implemented by a MatchData that can drop its cached
// frames vector, so that a heap-limit search starts without one.
type HeapFramesFreer interface{ FreeHeapFrames() }

// HeapFramesSizer is implemented by a MatchData that can report the size of its
// frames vector (pcre2_get_match_data_heapframes_size()).
type HeapFramesSizer interface{ HeapFramesSize() uint64 }

// checkMatchLimit ports check_match_limit(): a binary search for the smallest
// heap, match or depth limit that still lets the match succeed. It returns the
// result of the final match call.
func (r *Runner) checkMatchLimit(subj []byte, dat *mods.DatCtl, opts uint32, md MatchData, ms MatchSettings,
	dfa DFAMatcher, errnumber int, msg string) int {
	var min uint32
	mid := uint32(64)
	max := uint32(0xffffffff)
	ms.MatchLimit, ms.DepthLimit, ms.HeapLimit = max, max, max
	var capcount int
	for {
		var stackStart uint32
		switch errnumber {
		case errHeapLimit:
			ms.HeapLimit = mid
			if f, ok := md.(HeapFramesFreer); ok {
				f.FreeHeapFrames()
			}
		case errMatchLimit:
			ms.MatchLimit = mid
		default:
			ms.DepthLimit = mid
		}
		if dfa != nil {
			stackStart = dfaStartRWSSize / 1024
			if r.dfaWS == nil {
				r.dfaWS = make([]int32, DFAWorkspaceSize)
			}
			if r.dfaMatched == 0 {
				r.dfaWS[0] = -1
			}
			r.dfaMatched++
			capcount = dfa.DFAMatch(subj, uint64(dat.Offset), opts, md, ms, r.dfaWS)
		} else {
			capcount = r.code.Match(subj, uint64(dat.Offset), opts, md, ms)
		}
		switch {
		case capcount == errnumber:
			if mid&0x80000000 != 0 {
				r.printf("Can't find minimum %s limit: check pattern for restriction\n", msg)
				return capcount
			}
			min = mid
			switch {
			case mid == max-1:
				mid = max
			case max != 0xffffffff:
				mid = (min + max) / 2
			default:
				mid *= 2
			}
		case capcount >= 0 || capcount == errNoMatch || capcount == errPartial:
			if errnumber == errHeapLimit && mid < stackStart {
				r.printf("Minimum %s limit = 0\n", msg)
				return capcount
			}
			if mid == min+1 {
				r.printf("Minimum %s limit = %d\n", msg, mid)
				return capcount
			}
			max = mid
			mid = (min + max) / 2
		default:
			return capcount
		}
	}
}

// codeBlockSize is sizeof(pcre2_real_code_8) on a 64-bit target.
const codeBlockSize = 136

// showMemoryInfo ports show_memory_info() for an 8-bit build.
func (r *Runner) showMemoryInfo() {
	size, _ := r.patternInfo(infoSize, false)
	nc, _ := r.patternInfo(infoNameCount, false)
	ne, _ := r.patternInfo(infoNameEntrySize, false)
	r.printf("Memory allocation - compiled block : %d\n", size)
	r.printf("Memory allocation - code portion   : %d\n", size-nc*ne-codeBlockSize)
	if r.patCtl.Jit != 0 {
		js, _ := r.patternInfo(10, false) // PCRE2_INFO_JITSIZE
		r.printf("Memory allocation - JIT code       : %d\n", js)
	}
}

// showFrameSize ports show_framesize().
func (r *Runner) showFrameSize() {
	fs, _ := r.patternInfo(infoFrameSize, false)
	r.printf("Frame size for pcre2_match(): %d\n", fs)
}

// showHeapFramesSize ports show_heapframes_size().
func (r *Runner) showHeapFramesSize(md MatchData) {
	if s, ok := md.(HeapFramesSizer); ok {
		r.printf("Heapframes size in match_data: %d\n", s.HeapFramesSize())
		return
	}
	r.unsup("heap frames size (heapframes_size)")
}
