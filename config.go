// Port of pcre2_config.c: pcre2_config(). The reference build is 8-bit, with
// Unicode support, LINK_SIZE 2 and no JIT.
package pcre2

// Config is pcre2_config(). For a numeric item it returns (value, "", 0). For
// a string item (PCRE2_CONFIG_UNICODE_VERSION, PCRE2_CONFIG_VERSION) it
// returns (0, text, 1+len(text)), the C return value (length including the
// terminating zero). PCRE2_CONFIG_JITTARGET and unknown items give
// (0, "", PCRE2_ERROR_BADOPTION), as a build without JIT does.
// (pcre2_config.c:78)
func Config(what uint32) (value uint32, text string, rc int) {
	switch what {
	case PCRE2_CONFIG_BSR:
		return PCRE2_BSR_UNICODE, "", 0 // BSR_ANYCRLF is not set
	case PCRE2_CONFIG_COMPILED_WIDTHS:
		return 1, "", 0 // SUPPORT_PCRE2_8 only
	case PCRE2_CONFIG_DEPTHLIMIT:
		return MATCH_LIMIT_DEPTH, "", 0
	case PCRE2_CONFIG_HEAPLIMIT:
		return HEAP_LIMIT, "", 0
	case PCRE2_CONFIG_JIT:
		return 0, "", 0
	case PCRE2_CONFIG_JITTARGET:
		return 0, "", PCRE2_ERROR_BADOPTION
	case PCRE2_CONFIG_LINKSIZE:
		return LINK_SIZE, "", 0
	case PCRE2_CONFIG_MATCHLIMIT:
		return MATCH_LIMIT, "", 0
	case PCRE2_CONFIG_NEWLINE:
		return NEWLINE_DEFAULT, "", 0
	case PCRE2_CONFIG_NEVER_BACKSLASH_C:
		return 0, "", 0
	case PCRE2_CONFIG_PARENSLIMIT:
		return PARENS_NEST_LIMIT, "", 0
	case PCRE2_CONFIG_STACKRECURSE: // obsolete
		return 0, "", 0
	case PCRE2_CONFIG_TABLES_LENGTH:
		return TABLES_LENGTH, "", 0
	case PCRE2_CONFIG_UNICODE_VERSION:
		return 0, unicode_version, 1 + len(unicode_version)
	case PCRE2_CONFIG_UNICODE:
		return 1, "", 0
	case PCRE2_CONFIG_VERSION:
		return 0, PCRE2_VERSION_STRING, 1 + len(PCRE2_VERSION_STRING)
	}
	return 0, "", PCRE2_ERROR_BADOPTION
}
