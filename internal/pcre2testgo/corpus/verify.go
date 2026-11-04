package corpus

import (
	"os"
	"path/filepath"
	"strings"
)

// stateCommands are the #commands whose effect carries over to later cases and
// that a stand-alone replay must therefore repeat.
var stateCommands = map[string]bool{"pattern": true, "subject": true, "newline_default": true, "forbid_utf": true, "perltest": true, "loadtables": true}

// commandName returns the name of the first #command of a command case, or "".
func commandName(c Case) string {
	for _, l := range SplitLines([]byte(c.Input)) {
		if len(l) > 1 && l[0] == '#' && !isSpace(l[1]) && l[1] != '!' {
			f := strings.Fields(string(l[1:]))
			if len(f) > 0 {
				return f[0]
			}
		}
	}
	return ""
}

// Replay runs every counted case of g stand-alone through the oracle, after
// replaying the state-setting commands that precede it, and returns the ids of
// the cases whose output differs from Expected. It is an independent check of
// the case splitter: a case that was cut at the wrong place does not
// reproduce its own expected output. Cases that depend on other state (a
// pattern stack for #pop, saved files) legitimately differ.
func Replay(g *Golden, o Oracle) (mismatched []string, err error) {
	if err := os.MkdirAll(o.WorkDir, 0o755); err != nil {
		return nil, err
	}
	var prelude, preludeOut strings.Builder
	for _, c := range g.Cases {
		if c.Kind == KindError {
			continue
		}
		if c.Kind == KindCommand {
			if stateCommands[commandName(c)] {
				prelude.WriteString(c.Input)
				preludeOut.WriteString(c.Expected)
			}
			continue
		}
		in := prelude.String() + c.Input
		path := filepath.Join(o.WorkDir, "replay-case.txt")
		if err := os.WriteFile(path, []byte(in), 0o644); err != nil {
			return nil, err
		}
		out, runErr := o.RunFile(path)
		want := preludeOut.String() + c.Expected
		if runErr != nil || string(out) != want {
			mismatched = append(mismatched, c.ID)
		}
	}
	return mismatched, nil
}
