//go:build cgoref

// Test-rig support, compiled only with -tags cgoref: it lets the out-of-tree
// rig (go-regexp-pcre2-cgoref) build a Code from the bytecode that the real
// libpcre2 compiled, so that the Go matcher can be checked against the C one
// before the Go compiler lands.
package pcre2

// RigHeader holds the fields of pcre2_real_code.
type RigHeader struct {
	StartBitmap                                                                              [32]uint8
	Blocksize                                                                                uint64
	Magic, CompileOptions, OverallOptions, ExtraOptions, Flags                               uint32
	LimitHeap, LimitMatch, LimitDepth, FirstCodeunit, LastCodeunit                           uint32
	Bsr, Newline, MaxLookbehind, Minlength, TopBracket, TopBackref, NameEntrySize, NameCount uint16
}

// RigCode builds a Code from the header and the bytes that follow it in the C
// block (name table, then opcodes).
func RigCode(h RigHeader, code []byte) *Code {
	return &Code{
		startBitmap: h.StartBitmap, blocksize: h.Blocksize, magicNumber: h.Magic,
		compileOptions: h.CompileOptions, overallOptions: h.OverallOptions, extraOptions: h.ExtraOptions,
		flags: h.Flags, limitHeap: h.LimitHeap, limitMatch: h.LimitMatch, limitDepth: h.LimitDepth,
		firstCodeunit: h.FirstCodeunit, lastCodeunit: h.LastCodeunit,
		bsrConvention: h.Bsr, newlineConvention: h.Newline, maxLookbehind: h.MaxLookbehind,
		minlength: h.Minlength, topBracket: h.TopBracket, topBackref: h.TopBackref,
		nameEntrySize: h.NameEntrySize, nameCount: h.NameCount, code: code,
	}
}

// RigUsedChars returns leftchar and rightchar of a match data block.
func RigUsedChars(md *MatchData) (uint64, uint64) { return md.leftchar, md.rightchar }

// RigFreeHeapFrames drops the cached frame vector.
func RigFreeHeapFrames(md *MatchData) { md.heapframes = nil; md.heapframesSz = 0 }
