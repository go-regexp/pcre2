// Port of pcre2_error.c: error message texts and pcre2_get_error_message().
package pcre2

import "strconv"

// compile_error_texts (pcre2_error.c:65-193): compile-time error messages,
// numbered from COMPILE_ERROR_BASE; each ends with NUL, the whole ends with
// two NULs.
var compile_error_texts = "no error\x00" +
	"\\ at end of pattern\x00" +
	"\\c at end of pattern\x00" +
	"unrecognized character follows \\\x00" +
	"numbers out of order in {} quantifier\x00" +
	/* 5 */
	"number too big in {} quantifier\x00" +
	"missing terminating ] for character class\x00" +
	"escape sequence is invalid in character class\x00" +
	"range out of order in character class\x00" +
	"quantifier does not follow a repeatable item\x00" +
	/* 10 */
	"internal error: unexpected repeat\x00" +
	"unrecognized character after (? or (?-\x00" +
	"POSIX named classes are supported only within a class\x00" +
	"POSIX collating elements are not supported\x00" +
	"missing closing parenthesis\x00" +
	/* 15 */
	"reference to non-existent subpattern\x00" +
	"pattern passed as NULL with non-zero length\x00" +
	"unrecognised compile-time option bit(s)\x00" +
	"missing ) after (?# comment\x00" +
	"parentheses are too deeply nested\x00" +
	/* 20 */
	"regular expression is too large\x00" +
	"failed to allocate heap memory\x00" +
	"unmatched closing parenthesis\x00" +
	"internal error: code overflow\x00" +
	"missing closing parenthesis for condition\x00" +
	/* 25 */
	"length of lookbehind assertion is not limited\x00" +
	"a relative value of zero is not allowed\x00" +
	"conditional subpattern contains more than two branches\x00" +
	"assertion expected after (?( or (?(?C)\x00" +
	"digit expected after (?+ or (?-\x00" +
	/* 30 */
	"unknown POSIX class name\x00" +
	"internal error in pcre2_study(): should not occur\x00" +
	"this version of PCRE2 does not have Unicode support\x00" +
	"parentheses are too deeply nested (stack check)\x00" +
	"character code point value in \\x{} or \\o{} is too large\x00" +
	/* 35 */
	"lookbehind is too complicated\x00" +
	"\\C is not allowed in a lookbehind assertion in UTF-8 mode\x00" +
	"PCRE2 does not support \\F, \\L, \\l, \\N{name}, \\U, or \\u\x00" +
	"number after (?C is greater than 255\x00" +
	"closing parenthesis for (?C expected\x00" +
	/* 40 */
	"invalid escape sequence in (*VERB) name\x00" +
	"unrecognized character after (?P\x00" +
	"syntax error in subpattern name (missing terminator?)\x00" +
	"two named subpatterns have the same name (PCRE2_DUPNAMES not set)\x00" +
	"subpattern name must start with a non-digit\x00" +
	/* 45 */
	"this version of PCRE2 does not have support for \\P, \\p, or \\X\x00" +
	"malformed \\P or \\p sequence\x00" +
	"unknown property after \\P or \\p\x00" +
	"subpattern name is too long (maximum " + strconv.Itoa(MAX_NAME_SIZE) + " code units)\x00" +
	"too many named subpatterns (maximum " + strconv.Itoa(MAX_NAME_COUNT) + ")\x00" +
	/* 50 */
	"invalid range in character class\x00" +
	"octal value is greater than \\377 in 8-bit non-UTF-8 mode\x00" +
	"internal error: overran compiling workspace\x00" +
	"internal error: previously-checked referenced subpattern not found\x00" +
	"DEFINE subpattern contains more than one branch\x00" +
	/* 55 */
	"missing opening brace after \\o\x00" +
	"internal error: unknown newline setting\x00" +
	"\\g is not followed by a braced, angle-bracketed, or quoted name/number or by a plain number\x00" +
	"(?R (recursive pattern call) must be followed by a closing parenthesis\x00" +
	"obsolete error (should not occur)\x00" + // Was "an argument is not allowed for (*ACCEPT), (*FAIL), or (*COMMIT)"
	/* 60 */
	"(*VERB) not recognized or malformed\x00" +
	"subpattern number is too big\x00" +
	"subpattern name expected\x00" +
	"internal error: parsed pattern overflow\x00" +
	"non-octal character in \\o{} (closing brace missing?)\x00" +
	/* 65 */
	"different names for subpatterns of the same number are not allowed\x00" +
	"(*MARK) must have an argument\x00" +
	"non-hex character in \\x{} (closing brace missing?)\x00" +
	"\\c must be followed by a printable ASCII character\x00" +
	"\\k is not followed by a braced, angle-bracketed, or quoted name\x00" +
	/* 70 */
	"internal error: unknown meta code in check_lookbehinds()\x00" +
	"\\N is not supported in a class\x00" +
	"callout string is too long\x00" +
	"disallowed Unicode code point (>= 0xd800 && <= 0xdfff)\x00" +
	"using UTF is disabled by the application\x00" +
	/* 75 */
	"using UCP is disabled by the application\x00" +
	"name is too long in (*MARK), (*PRUNE), (*SKIP), or (*THEN)\x00" +
	"character code point value in \\u.... sequence is too large\x00" +
	"digits missing in \\x{} or \\o{} or \\N{U+}\x00" +
	"syntax error or number too big in (?(VERSION condition\x00" +
	/* 80 */
	"internal error: unknown opcode in auto_possessify()\x00" +
	"missing terminating delimiter for callout with string argument\x00" +
	"unrecognized string delimiter follows (?C\x00" +
	"using \\C is disabled by the application\x00" +
	"(?| and/or (?J: or (?x: parentheses are too deeply nested\x00" +
	/* 85 */
	"using \\C is disabled in this PCRE2 library\x00" +
	"regular expression is too complicated\x00" +
	"lookbehind assertion is too long\x00" +
	"pattern string is longer than the limit set by the application\x00" +
	"internal error: unknown code in parsed pattern\x00" +
	/* 90 */
	"internal error: bad code value in parsed_skip()\x00" +
	"PCRE2_EXTRA_ALLOW_SURROGATE_ESCAPES is not allowed in UTF-16 mode\x00" +
	"invalid option bits with PCRE2_LITERAL\x00" +
	"\\N{U+dddd} is supported only in Unicode (UTF) mode\x00" +
	"invalid hyphen in option setting\x00" +
	/* 95 */
	"(*alpha_assertion) not recognized\x00" +
	"script runs require Unicode support, which this version of PCRE2 does not have\x00" +
	"too many capturing groups (maximum 65535)\x00" +
	"atomic assertion expected after (?( or (?(?C)\x00" +
	"\\K is not allowed in lookarounds (but see PCRE2_EXTRA_ALLOW_LOOKAROUND_BSK)\x00" +
	/* 100 */
	"branch too long in variable-length lookbehind assertion\x00" +
	"compiled pattern would be longer than the limit set by the application\x00"

// match_error_texts (pcre2_error.c:197-279): match-time and UTF error texts.
var match_error_texts = "no error\x00" +
	"no match\x00" +
	"partial match\x00" +
	"UTF-8 error: 1 byte missing at end\x00" +
	"UTF-8 error: 2 bytes missing at end\x00" +
	/* 5 */
	"UTF-8 error: 3 bytes missing at end\x00" +
	"UTF-8 error: 4 bytes missing at end\x00" +
	"UTF-8 error: 5 bytes missing at end\x00" +
	"UTF-8 error: byte 2 top bits not 0x80\x00" +
	"UTF-8 error: byte 3 top bits not 0x80\x00" +
	/* 10 */
	"UTF-8 error: byte 4 top bits not 0x80\x00" +
	"UTF-8 error: byte 5 top bits not 0x80\x00" +
	"UTF-8 error: byte 6 top bits not 0x80\x00" +
	"UTF-8 error: 5-byte character is not allowed (RFC 3629)\x00" +
	"UTF-8 error: 6-byte character is not allowed (RFC 3629)\x00" +
	/* 15 */
	"UTF-8 error: code points greater than 0x10ffff are not defined\x00" +
	"UTF-8 error: code points 0xd800-0xdfff are not defined\x00" +
	"UTF-8 error: overlong 2-byte sequence\x00" +
	"UTF-8 error: overlong 3-byte sequence\x00" +
	"UTF-8 error: overlong 4-byte sequence\x00" +
	/* 20 */
	"UTF-8 error: overlong 5-byte sequence\x00" +
	"UTF-8 error: overlong 6-byte sequence\x00" +
	"UTF-8 error: isolated byte with 0x80 bit set\x00" +
	"UTF-8 error: illegal byte (0xfe or 0xff)\x00" +
	"UTF-16 error: missing low surrogate at end\x00" +
	/* 25 */
	"UTF-16 error: invalid low surrogate\x00" +
	"UTF-16 error: isolated low surrogate\x00" +
	"UTF-32 error: code points 0xd800-0xdfff are not defined\x00" +
	"UTF-32 error: code points greater than 0x10ffff are not defined\x00" +
	"bad data value\x00" +
	/* 30 */
	"patterns do not all use the same character tables\x00" +
	"magic number missing\x00" +
	"pattern compiled in wrong mode: 8/16/32-bit error\x00" +
	"bad offset value\x00" +
	"bad option value\x00" +
	/* 35 */
	"invalid replacement string\x00" +
	"bad offset into UTF string\x00" +
	"callout error code\x00" + // Never returned by PCRE2 itself
	"invalid data in workspace for DFA restart\x00" +
	"too much recursion for DFA matching\x00" +
	/* 40 */
	"backreference condition or recursion test is not supported for DFA matching\x00" +
	"function is not supported for DFA matching\x00" +
	"pattern contains an item that is not supported for DFA matching\x00" +
	"workspace size exceeded in DFA matching\x00" +
	"internal error - pattern overwritten?\x00" +
	/* 45 */
	"bad JIT option\x00" +
	"JIT stack limit reached\x00" +
	"match limit exceeded\x00" +
	"no more memory\x00" +
	"unknown substring\x00" +
	/* 50 */
	"non-unique substring name\x00" +
	"NULL argument passed with non-zero length\x00" +
	"nested recursion at the same subject position\x00" +
	"matching depth limit exceeded\x00" +
	"requested value is not available\x00" +
	/* 55 */
	"requested value is not set\x00" +
	"offset limit set without PCRE2_USE_OFFSET_LIMIT\x00" +
	"bad escape sequence in replacement string\x00" +
	"expected closing curly bracket in replacement string\x00" +
	"bad substitution in replacement string\x00" +
	/* 60 */
	"match with end before start or start moved backwards is not supported\x00" +
	"too many replacements (more than INT_MAX)\x00" +
	"bad serialized data\x00" +
	"heap limit exceeded\x00" +
	"invalid syntax\x00" +
	/* 65 */
	"internal error - duplicate substitution match\x00" +
	"PCRE2_MATCH_INVALID_UTF is not supported for DFA matching\x00" +
	"INTERNAL ERROR: invalid substring offset\x00"

// GetErrorMessageBuf is pcre2_get_error_message(): it copies the message for
// enumber into buffer (zero terminated) and returns its length, or a negative
// error: PCRE2_ERROR_NOMEMORY if the buffer is empty or too small (the message
// is then truncated and terminated), PCRE2_ERROR_BADDATA for an unknown
// number. (pcre2_error.c:301)
func GetErrorMessageBuf(enumber int, buffer []byte) int {
	size := uint64(len(buffer))
	if size == 0 {
		return PCRE2_ERROR_NOMEMORY
	}
	var message string
	var n int
	if enumber >= COMPILE_ERROR_BASE { // Compile error
		message = compile_error_texts
		n = enumber - COMPILE_ERROR_BASE
	} else if enumber < 0 { // Match or UTF error
		message = match_error_texts
		n = -enumber
	} else { // Invalid error number
		message = "\x00" // Empty message list
		n = 1
	}
	p := 0
	for ; n > 0; n-- {
		for p < len(message) && message[p] != 0 {
			p++
		}
		p++
		if p >= len(message) || message[p] == 0 {
			return PCRE2_ERROR_BADDATA
		}
	}
	var i uint64
	for ; p < len(message) && message[p] != 0; i++ {
		if i >= size-1 {
			buffer[i] = 0 // Terminate partial message
			return PCRE2_ERROR_NOMEMORY
		}
		buffer[i] = message[p]
		p++
	}
	buffer[i] = 0
	return int(i)
}

// GetErrorMessage returns the text for an error code, as pcre2_get_error_message()
// would write it into a large enough buffer. For a code with no message it
// returns the empty string (C returns PCRE2_ERROR_BADDATA and leaves the buffer
// unset); use GetErrorMessageBuf to tell the cases apart.
func GetErrorMessage(errorcode int) string {
	buf := make([]byte, 512)
	n := GetErrorMessageBuf(errorcode, buf)
	if n < 0 {
		return ""
	}
	return string(buf[:n])
}
