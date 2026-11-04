// Package libpcre2 adapts the public API of github.com/go-regexp/pcre2 to the
// pcre2testgo.Lib interface. It uses nothing but the exported, C-shaped API,
// so the few things pcre2test reads from the internals of a compiled pattern
// (caseless first/last code unit, "forced newline" flags, consulted
// characters) are reported as unavailable; a test inside package pcre2 can
// wrap this adapter and supply them (see conformance_adapter_test.go there).
package libpcre2

import (
	"github.com/go-regexp/pcre2"
	"github.com/go-regexp/pcre2/internal/pcre2testgo"
)

// Lib is the adapter. The zero value is ready to use.
type Lib struct{}

// New returns the adapter.
func New() Lib { return Lib{} }

// Compile implements pcre2testgo.Lib.
func (Lib) Compile(pattern []byte, options uint32, cs pcre2testgo.CompileSettings) (pcre2testgo.Code, int, uint64) {
	var cc *pcre2.CompileContext
	if !cs.Null {
		cc = pcre2.NewCompileContext()
		cc.SetNewline(uint32(cs.Newline))
		cc.SetBSR(uint32(cs.BSR))
		cc.SetParensNestLimit(cs.ParensNestLimit)
		cc.SetMaxPatternLength(cs.MaxPatLen)
		cc.SetMaxPatternCompiledLength(cs.MaxPatCompLen)
		cc.SetMaxVarlookbehind(cs.MaxVarLookbehind)
		cc.SetCompileExtraOptions(cs.ExtraOptions)
	}
	if cs.NullPattern {
		pattern = nil
	} else if pattern == nil {
		pattern = []byte{}
	}
	code, ec, off := pcre2.Compile(pattern, options, cc)
	if code == nil {
		return nil, ec, off
	}
	return &Code{C: code, Pat: pattern}, ec, off
}

// ErrorMessage implements pcre2testgo.Lib.
func (Lib) ErrorMessage(code int) (string, bool) {
	buf := make([]byte, 512)
	n := pcre2.GetErrorMessageBuf(code, buf)
	if n < 0 {
		return "", false
	}
	return string(buf[:n]), true
}

// Code adapts *pcre2.Code.
type Code struct {
	C *pcre2.Code
	// Pat is the pattern text, used to find the delimiter of a callout string.
	Pat []byte
}

// Info implements pcre2testgo.Code.
func (c *Code) Info(what uint32) (uint64, int) { return c.C.PatternInfo(what) }

// NameTable implements pcre2testgo.Code.
func (c *Code) NameTable() ([]byte, uint32, uint32) { return c.C.NameTable() }

// Extra implements pcre2testgo.Code with what the public API offers.
func (c *Code) Extra() pcre2testgo.CodeExtra {
	e := pcre2testgo.CodeExtra{StartBits: c.C.FirstBitmap()}
	c.C.CalloutEnumerate(func(*pcre2.CalloutEnumerateBlock, any) int { e.HasCallout = true; return 0 }, nil)
	return e
}

// NumberFromName implements pcre2testgo.Code.
func (c *Code) NumberFromName(name string) int { return pcre2.SubstringNumberFromName(c.C, name) }

// Free implements pcre2testgo.Code.
func (c *Code) Free() { c.C.Free() }

// NewMatchData implements pcre2testgo.Code.
func (c *Code) NewMatchData(oveccount uint32) pcre2testgo.MatchData {
	if oveccount == 0 {
		return &MatchData{M: pcre2.NewMatchData(c.C)}
	}
	return &MatchData{M: pcre2.NewMatchDataSize(oveccount)}
}

// Match implements pcre2testgo.Code.
func (c *Code) Match(subject []byte, start uint64, options uint32, md pcre2testgo.MatchData, ms pcre2testgo.MatchSettings) int {
	var mc *pcre2.MatchContext
	if !ms.Null {
		mc = pcre2.NewMatchContext()
		mc.SetMatchLimit(ms.MatchLimit)
		mc.SetDepthLimit(ms.DepthLimit)
		mc.SetHeapLimit(ms.HeapLimit)
		mc.SetOffsetLimit(ms.OffsetLimit)
		if ms.Callout != nil {
			mc.SetCallout(func(cb *pcre2.CalloutBlock, _ any) int { return ms.Callout(c.calloutBlock(cb)) }, nil)
		}
	}
	return pcre2.Match(c.C, subject, start, options, md.(*MatchData).M, mc)
}

// MatchData adapts *pcre2.MatchData.
type MatchData struct{ M *pcre2.MatchData }

// Ovector implements pcre2testgo.MatchData.
func (m *MatchData) Ovector() []uint64 { return m.M.Ovector() }

// OvectorCount implements pcre2testgo.MatchData.
func (m *MatchData) OvectorCount() uint32 { return m.M.OvectorCount() }

// Mark implements pcre2testgo.MatchData.
func (m *MatchData) Mark() []byte { return m.M.GetMark() }

// StartChar implements pcre2testgo.MatchData.
func (m *MatchData) StartChar() uint64 { return m.M.GetStartchar() }

// UsedChars implements pcre2testgo.MatchData: not available through the public API.
func (m *MatchData) UsedChars() (uint64, uint64, bool) { return 0, 0, false }

// CopyByNumber implements pcre2testgo.MatchData.
func (m *MatchData) CopyByNumber(n uint32, units int) ([]byte, int) {
	buf := make([]byte, units)
	l, rc := pcre2.SubstringCopyByNumber(m.M, n, buf)
	if rc < 0 {
		return nil, rc
	}
	return buf[:l], rc
}

// LengthByNumber implements pcre2testgo.MatchData.
func (m *MatchData) LengthByNumber(n uint32) (uint64, int) {
	return pcre2.SubstringLengthByNumber(m.M, n)
}

// CopyByName implements pcre2testgo.MatchData.
func (m *MatchData) CopyByName(name string, units int) ([]byte, int) {
	buf := make([]byte, units)
	l, rc := pcre2.SubstringCopyByName(m.M, name, buf)
	if rc < 0 {
		return nil, rc
	}
	return buf[:l], rc
}

// LengthByName implements pcre2testgo.MatchData.
func (m *MatchData) LengthByName(name string) (uint64, int) {
	return pcre2.SubstringLengthByName(m.M, name)
}

// GetByNumber implements pcre2testgo.MatchData.
func (m *MatchData) GetByNumber(n uint32) ([]byte, int) {
	return pcre2.SubstringGetByNumber(m.M, n)
}

// GetByName implements pcre2testgo.MatchData.
func (m *MatchData) GetByName(name string) ([]byte, int) {
	return pcre2.SubstringGetByName(m.M, name)
}

// ListGet implements pcre2testgo.MatchData.
func (m *MatchData) ListGet() ([][]byte, int) {
	list, _, rc := pcre2.SubstringListGet(m.M)
	return list, rc
}

// SupportsCallouts implements pcre2testgo.CalloutCapable.
func (c *Code) SupportsCallouts() bool { return true }

func (c *Code) delimiter(offset uint64, str []byte) byte {
	if str != nil && offset > 0 && offset-1 < uint64(len(c.Pat)) {
		return c.Pat[offset-1]
	}
	return 0
}

func (c *Code) calloutBlock(cb *pcre2.CalloutBlock) *pcre2testgo.CalloutBlock {
	return &pcre2testgo.CalloutBlock{
		Version: cb.Version, CalloutNumber: cb.CalloutNumber, CaptureTop: cb.CaptureTop, CaptureLast: cb.CaptureLast,
		OffsetVector: cb.OffsetVector, Mark: cb.Mark, Subject: cb.Subject, StartMatch: cb.StartMatch,
		CurrentPosition: cb.CurrentPosition, PatternPosition: cb.PatternPosition, NextItemLength: cb.NextItemLength,
		CalloutStringOffset: cb.CalloutStringOffset, CalloutString: cb.CalloutString,
		CalloutDelimiter: c.delimiter(cb.CalloutStringOffset, cb.CalloutString), CalloutFlags: cb.CalloutFlags,
	}
}

// CalloutEnumerate implements pcre2testgo.CalloutEnumerator.
func (c *Code) CalloutEnumerate(fn func(pcre2testgo.CalloutEnumBlock) int) int {
	return c.C.CalloutEnumerate(func(cb *pcre2.CalloutEnumerateBlock, _ any) int {
		return fn(pcre2testgo.CalloutEnumBlock{
			PatternPosition: cb.PatternPosition, NextItemLength: cb.NextItemLength, CalloutNumber: cb.CalloutNumber,
			CalloutStringOffset: cb.CalloutStringOffset, CalloutString: cb.CalloutString,
			CalloutDelimiter: c.delimiter(cb.CalloutStringOffset, cb.CalloutString),
		})
	}, nil)
}
