package pcre2testgo

import (
	"github.com/go-regexp/pcre2/internal/pcre2testgo/mods"
)

const replaceBuffSize = 1024 // REPLACE_BUFFSIZE: code units for 8-bit

// substitute ports the pcre2_substitute() branch of process_data(). It is
// called with the data line's controls, the subject and the match data.
func (r *Runner) substitute(dat *mods.DatCtl, ms MatchSettings, subject []byte, subjectIsNull bool, md MatchData, utf bool) int {
	sub, ok := r.code.(Substituter)
	if !ok {
		r.unsup("substitution (replace)")
		return prOK
	}
	ovector := md.Ovector()
	oveccount := md.OvectorCount()
	for j := range ovector {
		ovector[j] = junkOffset
	}
	if dat.Control&mods.CTL_ALTGLOBAL != 0 {
		r.printf("** Altglobal is not supported with replace: ignored\n")
	}

	var xoptions uint32
	if dat.Control2&mods.CTL2_SUBSTITUTE_MATCHED != 0 {
		xoptions |= SubstituteMatched
		r.code.Match(subject, uint64(dat.Offset), dat.Options, md, ms)
	}
	set := func(on bool, bit uint32) {
		if on {
			xoptions |= bit
		}
	}
	set(dat.Control&mods.CTL_GLOBAL != 0, SubstituteGlobal)
	set(dat.Control2&mods.CTL2_SUBSTITUTE_EXTENDED != 0, SubstituteExtended)
	set(dat.Control2&mods.CTL2_SUBSTITUTE_LITERAL != 0, SubstituteLiteral)
	set(dat.Control2&mods.CTL2_SUBSTITUTE_OVERFLOW_LENGTH != 0, SubstituteOverflowLength)
	set(dat.Control2&mods.CTL2_SUBSTITUTE_REPLACEMENT_ONLY != 0, SubstituteReplacementOnly)
	set(dat.Control2&mods.CTL2_SUBSTITUTE_UNKNOWN_UNSET != 0, SubstituteUnknownUnset)
	set(dat.Control2&mods.CTL2_SUBSTITUTE_UNSET_EMPTY != 0, SubstituteUnsetEmpty)

	repl := []byte(dat.Replacement)
	nsize := uint64(replaceBuffSize)
	if len(repl) > 0 && repl[0] == '[' {
		var n uint64
		i := 1
		for i < len(repl) && repl[i] >= '0' && repl[i] <= '9' {
			n = n*10 + uint64(repl[i]-'0')
			i++
		}
		if i >= len(repl) || repl[i] != ']' {
			r.printf("Bad buffer size in replacement string\n")
			return prOK
		}
		repl = repl[i+1:]
		if n > nsize {
			r.printf("Replacement buffer setting (%d) is too large (max %d)\n", n, nsize)
			return prOK
		}
		nsize = n
	}

	if dat.Control2&mods.CTL2_SUBSTITUTE_CALLOUT != 0 {
		r.unsup("substitute callouts")
	}

	rc, out, outlen := sub.Substitute(subject, uint64(dat.Offset), dat.Options|xoptions, md, ms, repl,
		dat.Control2&mods.CTL2_NULL_REPLACEMENT != 0, nsize)
	if rc < 0 {
		r.printf("Failed: error %d", rc)
		if rc != errNoMemory && outlen != unsetSize {
			r.printf(" at offset %d in replacement", int64(outlen))
		}
		r.printf(": ")
		if !r.printError(rc, "", "") {
			return prAbend
		}
		if rc == errNoMemory && xoptions&SubstituteOverflowLength != 0 {
			r.printf(": %d code units are needed", int64(outlen))
		}
	} else {
		r.printf("%2d: ", rc)
		pchars(out, utf, r.out)
	}
	r.printf("\n")

	if dat.Control2&mods.CTL2_ALLVECTOR != 0 {
		r.showOvector(md.Ovector(), oveccount)
	}
	return prOK
}
