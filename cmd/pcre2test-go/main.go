// Command pcre2test-go is a Go reimplementation of the subset of pcre2test
// (PCRE2 10.44, 8-bit) that is needed to run the testinput files of the PCRE2
// distribution against this module, printing results in pcre2test's exact
// output format.
//
//	pcre2test-go [options] [<input file> [<output file>]]
//
// Input and output default to standard input and output. The long options of
// pcre2test, which use a single dash (-error), take two dashes here, as POSIX
// asks (--error). Exit status: 0 on success, 1 when the run was abandoned or an
// option was bad, 3 when the input needed something the library does not offer
// (listed on standard error).
package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/go-regexp/pcre2/internal/pcre2testgo"
)

// osExit is replaceable for tests.
var osExit = os.Exit

// newLib returns the library under test; tests replace it.
var newLib = defaultLib

// exitError carries a process exit status through cobra.
type exitError struct{ code int }

func (e exitError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

// RootCmd builds the command.
func RootCmd() *cobra.Command {
	var cfg pcre2testgo.Config
	var eight bool
	cmd := &cobra.Command{
		Use:   "pcre2test-go [options] [<input file> [<output file>]]",
		Short: "run PCRE2 testinput files against the Go port and print pcre2test's output",
		Long: "pcre2test-go reads pcre2test input (patterns, modifiers, subject lines) and prints what\n" +
			"pcre2test 10.44 (8-bit, no JIT) prints. Input and output default to stdin and stdout.\n" +
			"Features the library under test does not offer (DFA matching, callouts, substitution,\n" +
			"serialization, POSIX interface, pattern conversion, code dumps) are reported on stderr\n" +
			"and make the exit status 3.",
		Args:          cobra.MaximumNArgs(2),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = eight // -8 selects the 8-bit library, the only one there is
			var in io.Reader = cmd.InOrStdin()
			out := cmd.OutOrStdout()
			if len(args) > 0 && args[0] != "-" {
				f, err := os.Open(args[0])
				if err != nil {
					fmt.Fprintf(out, "** Failed to open '%s': %v\n", args[0], errors.Unwrap(err))
					return exitError{1}
				}
				defer f.Close()
				in = f
			}
			if len(args) > 1 {
				f, err := os.Create(args[1])
				if err != nil {
					fmt.Fprintf(cmd.OutOrStdout(), "** Failed to open '%s': %v\n", args[1], errors.Unwrap(err))
					return exitError{1}
				}
				defer f.Close()
				out = f
			}
			if code := pcre2testgo.Execute(newLib(), cfg, in, out, cmd.ErrOrStderr()); code != 0 {
				return exitError{code}
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.BoolVarP(&cfg.Quiet, "quiet", "q", false, "quiet: do not output the PCRE2 version number at start")
	f.BoolVarP(&eight, "8", "8", false, "use the 8-bit library (the only one; accepted for compatibility)")
	f.StringVar(&cfg.ErrorList, "error", "", "show messages for the error numbers `n,m,...`, then exit")
	f.StringVar(&cfg.Pattern, "pattern", "", "set default pattern modifier fields (`modifiers`)")
	f.StringVar(&cfg.Subject, "subject", "", "set default subject modifier fields (`modifiers`)")
	return cmd
}

func main() {
	if err := RootCmd().Execute(); err != nil {
		var ee exitError
		if errors.As(err, &ee) {
			osExit(ee.code)
			return
		}
		fmt.Fprintln(os.Stderr, "pcre2test-go:", err)
		osExit(1)
	}
}
