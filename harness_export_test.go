package pcre2

// Test-only access to the parts of a compiled pattern and of a match data
// block that pcre2test reads from the internals rather than through the public
// API. Used by conformance_test.go (package pcre2_test).

// HarnessCodeFlags reports the internal flags pcre2test looks at when it shows
// pattern information.
func HarnessCodeFlags(c *Code) (firstCaseless, lastCaseless, nlSet, bsrSet, hasBkPorX bool) {
	f := c.flags
	return f&PCRE2_FIRSTCASELESS != 0, f&PCRE2_LASTCASELESS != 0, f&PCRE2_NL_SET != 0,
		f&PCRE2_BSR_SET != 0, f&PCRE2_HASBKPORX != 0
}

// HarnessUsedChars returns the leftmost and rightmost characters consulted by
// the last match (the "allusedtext" modifier).
func HarnessUsedChars(md *MatchData) (left, right uint64) { return md.leftchar, md.rightchar }
