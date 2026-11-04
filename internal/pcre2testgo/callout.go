package pcre2testgo

import (
	"bytes"
	"io"
	"strings"

	"github.com/go-regexp/pcre2/internal/pcre2testgo/mods"
)

const (
	calloutStartDelims = "`'\"^%#${"
	calloutEndDelims   = "`'\"^%#$}"
)

func endDelimiter(d byte) byte {
	if i := strings.IndexByte(calloutStartDelims, d); i >= 0 {
		return calloutEndDelims[i]
	}
	return d
}

// calloutFunc returns the callout function pcre2test installs for a data line
// (callout_function() of pcre2test.c).
func (r *Runner) calloutFunc(dat *mods.DatCtl) func(cb *CalloutBlock) int {
	first := true
	var lastMark []byte
	lastMarkSet := false
	count := 0
	utf := r.utf
	return func(cb *CalloutBlock) int {
		capture := dat.Control&mods.CTL_CALLOUT_CAPTURE != 0
		where := dat.Control2&mods.CTL2_CALLOUT_NO_WHERE == 0

		var fdefault io.Writer
		if first || capture || cb.CalloutString != nil {
			fdefault = r.out
		}
		f := fdefault
		if dat.Control2&mods.CTL2_CALLOUT_EXTRA != 0 {
			f = r.out
			switch cb.CalloutFlags {
			case CalloutBacktrack:
				r.printf("Backtrack\n")
			case CalloutStartMatch | CalloutBacktrack:
				r.printf("Backtrack\nNo other matching paths\n")
				r.printf("New match attempt\n")
			case CalloutStartMatch:
				r.printf("New match attempt\n")
			default:
				f = fdefault
			}
		}

		if cb.CalloutString != nil {
			r.printf("Callout (%d): %c", cb.CalloutStringOffset, cb.CalloutDelimiter)
			pchars(cb.CalloutString, utf, r.out)
			r.printf("%c", endDelimiter(cb.CalloutDelimiter))
			if !capture {
				r.printf("\n")
			}
		}

		if capture {
			if cb.CalloutString == nil {
				r.printf("Callout %d:", cb.CalloutNumber)
			}
			r.printf(" last capture = %d\n", cb.CaptureLast)
			for i := uint32(2); i < cb.CaptureTop*2; i += 2 {
				r.printf("%2d: ", i/2)
				if cb.OffsetVector[i] == unsetSize {
					r.printf("<unset>")
				} else {
					pchars(cb.Subject[cb.OffsetVector[i]:cb.OffsetVector[i+1]], utf, f)
				}
				r.printf("\n")
			}
		}

		if where {
			if f != nil {
				io.WriteString(f, "--->")
			}
			preStart := pchars(cb.Subject[:cb.StartMatch], utf, f)
			cur := cb.CurrentPosition
			if cur < cb.StartMatch {
				cur = cb.StartMatch
			}
			postStart := pchars(cb.Subject[cb.StartMatch:cur], utf, f)
			pchars(cb.Subject[cur:], utf, f)
			subjectLength := pchars(cb.Subject, utf, nil)
			if f != nil {
				io.WriteString(f, "\n")
			}
			if cb.CalloutNumber == 255 {
				r.printf("%+3d ", int(cb.PatternPosition))
				if cb.PatternPosition > 99 {
					r.printf("\n    ")
				}
			} else if capture || cb.CalloutString != nil {
				r.printf("    ")
			} else {
				r.printf("%3d ", cb.CalloutNumber)
			}
			r.out.WriteString(strings.Repeat(" ", preStart))
			r.printf("^")
			if postStart > 0 {
				r.out.WriteString(strings.Repeat(" ", postStart-1))
				r.printf("^")
			}
			if pad := subjectLength - preStart - postStart + 4; pad > 0 {
				r.out.WriteString(strings.Repeat(" ", pad))
			}
			if cb.NextItemLength != 0 {
				r.out.Write(r.patItem(cb.PatternPosition, cb.NextItemLength))
			} else {
				r.printf("End of pattern")
			}
			r.printf("\n")
		}
		first = false

		if markChanged(lastMark, lastMarkSet, cb.Mark) {
			if cb.Mark == nil {
				r.printf("Latest Mark: <unset>\n")
			} else {
				r.printf("Latest Mark: ")
				pchars(cb.Mark, utf, r.out)
				r.printf("\n")
			}
			lastMark, lastMarkSet = cb.Mark, cb.Mark != nil
		}

		if dat.CalloutData != 0 {
			r.printf("Callout data = %d\n", dat.CalloutData)
			return int(dat.CalloutData)
		}

		count++
		if cb.CalloutNumber == dat.Cerror[0] && uint32(count) >= dat.Cerror[1] {
			return ErrorCallout
		}
		if cb.CalloutNumber == dat.Cfail[0] && uint32(count) >= dat.Cfail[1] {
			return 1
		}
		return 0
	}
}

func markChanged(last []byte, lastSet bool, cur []byte) bool {
	if (cur != nil) != lastSet {
		return true
	}
	return cur != nil && !bytes.Equal(last, cur)
}

// patItem returns pbuffer8 + pos for n bytes, as printf("%.*s") would.
func (r *Runner) patItem(pos, n uint64) []byte {
	if pos >= uint64(len(r.patBytes)) {
		return nil
	}
	end := pos + n
	if end > uint64(len(r.patBytes)) {
		end = uint64(len(r.patBytes))
	}
	return r.patBytes[pos:end]
}

// calloutEnumerate ports show_pattern_info()'s callout_info branch.
func (r *Runner) calloutEnumerate() int {
	en, ok := r.code.(CalloutEnumerator)
	if !ok {
		r.unsup("callout enumeration (callout_info)")
		return prOK
	}
	utf := r.utf
	rc := en.CalloutEnumerate(func(cb CalloutEnumBlock) int {
		r.printf("Callout ")
		if cb.CalloutString != nil {
			r.printf("%c", cb.CalloutDelimiter)
			pchars(cb.CalloutString, utf, r.out)
			r.printf("%c  ", endDelimiter(cb.CalloutDelimiter))
		} else {
			r.printf("%d  ", cb.CalloutNumber)
		}
		n := cb.NextItemLength
		if n == 0 {
			n = 1
		}
		r.out.Write(r.patItem(cb.PatternPosition, n))
		r.printf("\n")
		return 0
	})
	if rc != 0 {
		r.printf("Callout enumerate failed: error %d: ", rc)
		if rc < 0 && !r.printError(rc, "", "\n") {
			return prAbend
		}
		return prSkip
	}
	return prOK
}
