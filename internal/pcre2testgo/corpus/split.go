// Package corpus splits PCRE2 testinput files into cases and aligns each case
// with the matching block of a testoutput file (or of the output of a real
// pcre2test run). It has no dependency on the pcre2 library itself.
//
// Reference: pcre2test.c main() in PCRE2 10.44. Every input line read from a
// file is echoed verbatim to the output, and results are printed right after
// the echo of the line that produced them. A case therefore is a run of input
// lines (pattern lines, data lines, the terminating blank line) together with
// the run of output lines that covers the same lines and their results.
package corpus

import (
	"bytes"
	"fmt"
	"strings"
)

// Kind classifies a case.
type Kind string

const (
	// KindPattern is a pattern line (possibly spanning several lines) with
	// its data lines and the blank terminator.
	KindPattern Kind = "pattern"
	// KindPop is a #pop or #popcopy command and its data lines.
	KindPop Kind = "pop"
	// KindCommand is any other #command (single line, no data).
	KindCommand Kind = "command"
	// KindInvalid is a line that is neither comment, command, blank nor a
	// pattern: pcre2test reports it and skips to the next blank line.
	KindInvalid Kind = "invalid"
	// KindError is the output of "pcre2test -error ..." appended by RunTest
	// to testoutput2.
	KindError Kind = "error"
)

// Counted reports whether cases of this kind count in pass/fail totals.
func (k Kind) Counted() bool {
	return k == KindPattern || k == KindPop || k == KindInvalid || k == KindError
}

// Case is one unit of the corpus.
type Case struct {
	ID       string `json:"id"`
	Kind     Kind   `json:"kind"`
	Line     int    `json:"line"`     // 1-based first input line (including prefix lines)
	Input    string `json:"input"`    // exact input text, newline-terminated
	Expected string `json:"expected"` // exact output text for Input
	// Excluded is non-empty when the case is excluded from conformance
	// totals, with the reason.
	Excluded string `json:"excluded,omitempty"`
}

// delimiters is the set of characters that may start a pattern (pcre2test.c).
const delimiters = "/!\"'`%&-=_:;,@~"

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}

func blank(line []byte) bool {
	for _, c := range line {
		if !isSpace(c) {
			return false
		}
	}
	return true
}

// SplitLines splits b into lines that keep their trailing newline. The last
// line may lack one.
func SplitLines(b []byte) [][]byte {
	var lines [][]byte
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			lines = append(lines, b)
			break
		}
		lines = append(lines, b[:i+1])
		b = b[i+1:]
	}
	return lines
}

type splitter struct {
	file   string
	in     [][]byte
	out    [][]byte
	ip, op int // cursors

	cases []Case
	// sink is the case currently receiving lines.
	cur     *Case
	curIn   strings.Builder
	curOut  strings.Builder
	curLine int
	prefix  bool // cur is a pending prefix (comments/blank between cases)

	defPush bool // #pattern push in force
}

// Split splits input into cases and aligns output with them. file is the
// testinput number used to build case ids ("1" -> "1:0001").
func Split(file string, input, output []byte) ([]Case, error) {
	s := &splitter{file: file, in: SplitLines(input), out: SplitLines(output)}
	if err := s.run(); err != nil {
		return nil, err
	}
	return s.cases, nil
}

// drain moves the output lines before the echo of input line l (the results
// of the previous input line) to the sink that owns them: the open case, or
// else the last closed case.
func (s *splitter) drain(l []byte) error {
	j := s.op
	for j < len(s.out) && !bytes.Equal(s.out[j], l) {
		j++
	}
	if j >= len(s.out) {
		return fmt.Errorf("input line %d %q not found in output after output line %d", s.ip+1, l, s.op+1)
	}
	if j > s.op && s.cur == nil && len(s.cases) == 0 {
		s.openPrefix()
	}
	for ; s.op < j; s.op++ {
		if s.cur != nil {
			s.curOut.Write(s.out[s.op])
		} else {
			s.cases[len(s.cases)-1].Expected += string(s.out[s.op])
		}
	}
	return nil
}

// align consumes input line l and its echo in the output.
func (s *splitter) align(l []byte) error {
	if err := s.drain(l); err != nil {
		return err
	}
	s.curOut.Write(s.out[s.op])
	s.op++
	s.curIn.Write(l)
	s.ip++
	return nil
}

// flush closes the current sink as a case (kind k) or keeps it as a prefix.
func (s *splitter) closeCase() {
	if s.cur == nil {
		return
	}
	s.cur.Input = s.curIn.String()
	s.cur.Expected = s.curOut.String()
	s.cases = append(s.cases, *s.cur)
	s.cur = nil
	s.curIn.Reset()
	s.curOut.Reset()
}

// start begins a new case of kind k whose first line is the line about to be
// consumed; pending prefix text (comments, blanks) is carried over.
func (s *splitter) start(k Kind) {
	if s.prefix {
		// keep curIn/curOut as accumulated prefix
		s.cur.Kind = k
		s.prefix = false
		return
	}
	s.cur = &Case{Kind: k, Line: s.ip + 1}
}

func (s *splitter) openPrefix() {
	if s.cur != nil {
		return
	}
	s.cur = &Case{Kind: KindCommand, Line: s.ip + 1}
	s.prefix = true
}

func (s *splitter) run() error {
	for s.ip < len(s.in) {
		l := s.in[s.ip]
		if err := s.drain(l); err != nil {
			return err
		}
		switch {
		case blank(l):
			s.openPrefix()
			if err := s.align(l); err != nil {
				return err
			}
		case l[0] == '#':
			if len(l) < 2 || isSpace(l[1]) || l[1] == '!' {
				s.openPrefix()
				if err := s.align(l); err != nil {
					return err
				}
				continue
			}
			if err := s.command(l); err != nil {
				return err
			}
		case strings.IndexByte(delimiters, l[0]) >= 0:
			if err := s.pattern(); err != nil {
				return err
			}
		default:
			s.openPrefix()
			s.start(KindInvalid)
			if err := s.align(l); err != nil {
				return err
			}
			if err := s.dataLines(); err != nil {
				return err
			}
		}
	}
	// Remaining output (e.g. results of the last line, or text appended by
	// the test driver) belongs to the last open sink or case.
	for ; s.op < len(s.out); s.op++ {
		if s.cur == nil && len(s.cases) > 0 {
			last := &s.cases[len(s.cases)-1]
			last.Expected += string(s.out[s.op])
			continue
		}
		if s.cur == nil {
			s.openPrefix()
		}
		s.curOut.Write(s.out[s.op])
	}
	if s.cur != nil {
		s.closeCase()
	}
	for i := range s.cases {
		s.cases[i].ID = fmt.Sprintf("%s:%04d", s.file, i+1)
	}
	return nil
}

// dataLines consumes lines up to and including the next blank line.
func (s *splitter) dataLines() error {
	for s.ip < len(s.in) {
		l := s.in[s.ip]
		if err := s.align(l); err != nil {
			return err
		}
		if blank(l) {
			break
		}
	}
	s.closeCase()
	return nil
}

func (s *splitter) command(l []byte) error {
	name := string(l[1:])
	if i := strings.IndexFunc(name, func(r rune) bool { return r < 128 && isSpace(byte(r)) }); i >= 0 {
		name = name[:i]
	}
	args := strings.TrimSpace(strings.TrimPrefix(string(l[1:]), name))
	s.openPrefix()
	switch name {
	case "pop", "popcopy":
		s.start(KindPop)
		if err := s.align(l); err != nil {
			return err
		}
		return s.dataLines()
	case "pattern":
		for _, t := range modTokens(args) {
			switch t.name {
			case "push": // pushcopy and pushtablescopy keep the pattern for data
				s.defPush = !t.off
			}
		}
	}
	s.start(KindCommand)
	if err := s.align(l); err != nil {
		return err
	}
	s.closeCase()
	return nil
}

// pattern consumes a pattern (maybe over several lines) and its data.
func (s *splitter) pattern() error {
	s.openPrefix()
	s.start(KindPattern)
	first := s.in[s.ip]
	delim := first[0]
	text := append([]byte(nil), first...)
	if err := s.align(first); err != nil {
		return err
	}
	i := 1
	for {
		found := false
		for i < len(text) {
			if text[i] == '\\' && i+1 < len(text) {
				i += 2
				continue
			}
			if text[i] == delim {
				found = true
				break
			}
			i++
		}
		if found {
			break
		}
		if s.ip >= len(s.in) {
			// "Unexpected EOF": pcre2test abandons the run.
			s.closeCase()
			return nil
		}
		l := s.in[s.ip]
		text = append(text, l...)
		if err := s.align(l); err != nil {
			return err
		}
	}
	rest := text[i+1:]
	if len(rest) > 0 && rest[0] == '\\' {
		rest = rest[1:]
	}
	push := s.defPush
	for _, t := range modTokens(string(rest)) {
		switch t.name {
		case "push":
			push = !t.off
		}
	}
	if !push {
		return s.dataLines()
	}
	// A stacked pattern takes no data, unless compilation failed (or the
	// modifiers were rejected), in which case pcre2test skips to a blank
	// line. The output tells which: look at the lines up to the next input
	// echo.
	failed := false
	var next []byte
	if s.ip < len(s.in) {
		next = s.in[s.ip]
	}
	for j := s.op; j < len(s.out); j++ {
		if next != nil && bytes.Equal(s.out[j], next) {
			break
		}
		if bytes.HasPrefix(s.out[j], []byte("Failed:")) || bytes.HasPrefix(s.out[j], []byte("** ")) &&
			!bytes.HasPrefix(s.out[j], []byte("** Ignored when")) && !bytes.HasPrefix(s.out[j], []byte("** Applies only")) {
			failed = true
			break
		}
	}
	if failed {
		return s.dataLines()
	}
	// Results of the pattern line (info output) are everything up to the
	// next echoed input line, which align() will attribute on the next call.
	s.closeCase()
	return nil
}

type modToken struct {
	name string
	off  bool
}

// modTokens extracts modifier names (without values) from a modifier list.
// Single-letter abbreviations are returned as is (they never matter for the
// callers: only long names are looked at).
func modTokens(s string) []modToken {
	var toks []modToken
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' }) {
		t := modToken{}
		if strings.HasPrefix(f, "-") {
			t.off = true
			f = f[1:]
		}
		if i := strings.IndexByte(f, '='); i >= 0 {
			f = f[:i]
		}
		t.name = f
		toks = append(toks, t)
	}
	return toks
}

// ModifierNames returns the long modifier names appearing in a modifier list.
func ModifierNames(s string) []string {
	var names []string
	for _, t := range modTokens(s) {
		names = append(names, t.name)
	}
	return names
}
