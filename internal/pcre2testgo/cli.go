package pcre2testgo

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/go-regexp/pcre2/internal/pcre2testgo/mods"
)

// VersionLine is the heading pcre2test prints unless -q is given.
const VersionLine = "PCRE2 version 10.44 2024-06-07 (8-bit)\n"

// Config is the command-line configuration of pcre2test that this program
// supports.
type Config struct {
	Quiet     bool
	ErrorList string // -error n,m,...
	Pattern   string // -pattern: default pattern modifiers
	Subject   string // -subject: default subject modifiers
}

// Exit statuses.
const (
	ExitOK          = 0
	ExitAbandoned   = 1 // "** pcre2test run abandoned" or a bad option
	ExitUnsupported = 3 // the run needed something the library does not offer
)

// Execute is pcre2test's main(): it reads testinput from in and writes the
// results to out. Diagnostics about the command line go to errOut.
func Execute(lib Lib, cfg Config, in io.Reader, out, errOut io.Writer) int {
	if cfg.ErrorList != "" {
		s, err := ErrorMessages(lib, cfg.ErrorList)
		io.WriteString(out, s)
		if err != nil {
			fmt.Fprintf(errOut, "** %v\n", err)
			return ExitAbandoned
		}
		return ExitOK
	}
	r := New(lib)
	var diag bytes.Buffer
	if cfg.Pattern != "" {
		st := &mods.State{Out: &diag, Pat: &r.defPat, CC: &r.defCC, DefaultNL: mods.NEWLINE_LF, DefaultBSR: mods.BSR_UNICODE}
		if !st.Decode([]byte(cfg.Pattern), mods.CtxDefPat) {
			errOut.Write(diag.Bytes())
			return ExitAbandoned
		}
	}
	if cfg.Subject != "" {
		st := &mods.State{Out: &diag, Dat: &r.defDat, MC: &r.defMC, DefaultNL: mods.NEWLINE_LF, DefaultBSR: mods.BSR_UNICODE}
		if !st.Decode([]byte(cfg.Subject), mods.CtxDefDat) {
			errOut.Write(diag.Bytes())
			return ExitAbandoned
		}
	}
	input, err := io.ReadAll(in)
	if err != nil {
		fmt.Fprintf(errOut, "** %v\n", err)
		return ExitAbandoned
	}
	if !cfg.Quiet {
		io.WriteString(out, VersionLine)
	}
	res := r.Run(input)
	out.Write(res.Output)
	r.DiscardOpenPattern()
	if res.Abend {
		return ExitAbandoned
	}
	if len(res.Unsupported) > 0 {
		fmt.Fprintf(errOut, "pcre2test-go: needed but not offered by the library: %s\n", strings.Join(res.Unsupported, "; "))
		return ExitUnsupported
	}
	return ExitOK
}
