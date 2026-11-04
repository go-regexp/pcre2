// Port of pcre2_context.c: general, compile, match and convert contexts. The
// memory-control (malloc/free hooks) side of C is dropped: Go allocates and
// the garbage collector frees, so the *Free functions are no-ops kept for API
// parity, and the create functions take an optional *GeneralContext that is
// ignored. Setters return 0 or PCRE2_ERROR_BADDATA like C.
package pcre2

// GeneralContextCreate is pcre2_general_context_create() (no allocator hooks).
func GeneralContextCreate() *GeneralContext { return &GeneralContext{} }

// Copy is pcre2_general_context_copy().
func (g *GeneralContext) Copy() *GeneralContext { c := *g; return &c }

// Free is pcre2_general_context_free(); a no-op.
func (g *GeneralContext) Free() {}

// defaultCompileContext returns PRIV(default_compile_context)
// (pcre2_context.c:133).
func defaultCompileContext() CompileContext {
	return CompileContext{
		tables:                   default_tables[:],
		maxPatternLength:         PCRE2_UNSET,
		maxPatternCompiledLength: PCRE2_UNSET,
		bsrConvention:            PCRE2_BSR_UNICODE, // BSR_DEFAULT
		newlineConvention:        NEWLINE_DEFAULT,
		parensNestLimit:          PARENS_NEST_LIMIT,
		extraOptions:             0,
		maxVarlookbehind:         MAX_VARLOOKBEHIND,
	}
}

// NewCompileContext is pcre2_compile_context_create(NULL).
func NewCompileContext() *CompileContext {
	c := defaultCompileContext()
	return &c
}

// CompileContextCreate is pcre2_compile_context_create(gcontext).
func CompileContextCreate(g *GeneralContext) *CompileContext { return NewCompileContext() }

// Copy is pcre2_compile_context_copy().
func (c *CompileContext) Copy() *CompileContext { n := *c; return &n }

// Free is pcre2_compile_context_free(); a no-op.
func (c *CompileContext) Free() {}

// defaultMatchContext returns PRIV(default_match_context) (pcre2_context.c:166).
func defaultMatchContext() MatchContext {
	return MatchContext{
		offsetLimit: PCRE2_UNSET,
		heapLimit:   HEAP_LIMIT,
		matchLimit:  MATCH_LIMIT,
		depthLimit:  MATCH_LIMIT_DEPTH,
	}
}

// NewMatchContext is pcre2_match_context_create(NULL).
func NewMatchContext() *MatchContext {
	m := defaultMatchContext()
	return &m
}

// MatchContextCreate is pcre2_match_context_create(gcontext).
func MatchContextCreate(g *GeneralContext) *MatchContext { return NewMatchContext() }

// Copy is pcre2_match_context_copy().
func (m *MatchContext) Copy() *MatchContext { n := *m; return &n }

// Free is pcre2_match_context_free(); a no-op.
func (m *MatchContext) Free() {}

// defaultConvertContext returns PRIV(default_convert_context) (non-Windows).
func defaultConvertContext() ConvertContext {
	return ConvertContext{globSeparator: CHAR_SLASH, globEscape: CHAR_BACKSLASH}
}

// NewConvertContext is pcre2_convert_context_create(NULL).
func NewConvertContext() *ConvertContext {
	c := defaultConvertContext()
	return &c
}

// Copy is pcre2_convert_context_copy().
func (c *ConvertContext) Copy() *ConvertContext { n := *c; return &n }

// Free is pcre2_convert_context_free(); a no-op.
func (c *ConvertContext) Free() {}

// ------------ Compile context ------------

// SetCharacterTables is pcre2_set_character_tables(). tables must be
// TABLES_LENGTH bytes (as made by Maketables) or nil for the default tables.
func (c *CompileContext) SetCharacterTables(tables []byte) int {
	if tables == nil {
		tables = default_tables[:]
	}
	c.tables = tables
	return 0
}

// SetBSR is pcre2_set_bsr().
func (c *CompileContext) SetBSR(value uint32) int {
	switch value {
	case PCRE2_BSR_ANYCRLF, PCRE2_BSR_UNICODE:
		c.bsrConvention = uint16(value)
		return 0
	}
	return PCRE2_ERROR_BADDATA
}

// SetMaxPatternLength is pcre2_set_max_pattern_length().
func (c *CompileContext) SetMaxPatternLength(length uint64) int {
	c.maxPatternLength = length
	return 0
}

// SetMaxPatternCompiledLength is pcre2_set_max_pattern_compiled_length().
func (c *CompileContext) SetMaxPatternCompiledLength(length uint64) int {
	c.maxPatternCompiledLength = length
	return 0
}

// SetNewline is pcre2_set_newline().
func (c *CompileContext) SetNewline(newline uint32) int {
	switch newline {
	case PCRE2_NEWLINE_CR, PCRE2_NEWLINE_LF, PCRE2_NEWLINE_CRLF,
		PCRE2_NEWLINE_ANY, PCRE2_NEWLINE_ANYCRLF, PCRE2_NEWLINE_NUL:
		c.newlineConvention = uint16(newline)
		return 0
	}
	return PCRE2_ERROR_BADDATA
}

// SetMaxVarlookbehind is pcre2_set_max_varlookbehind().
func (c *CompileContext) SetMaxVarlookbehind(limit uint32) int {
	c.maxVarlookbehind = limit
	return 0
}

// SetParensNestLimit is pcre2_set_parens_nest_limit().
func (c *CompileContext) SetParensNestLimit(limit uint32) int {
	c.parensNestLimit = limit
	return 0
}

// SetCompileExtraOptions is pcre2_set_compile_extra_options().
func (c *CompileContext) SetCompileExtraOptions(options uint32) int {
	c.extraOptions = options
	return 0
}

// SetCompileRecursionGuard is pcre2_set_compile_recursion_guard().
func (c *CompileContext) SetCompileRecursionGuard(guard func(depth uint32, data any) int, data any) int {
	c.stackGuard = guard
	c.stackGuardData = data
	return 0
}

// ------------ Match context ------------

// SetCallout is pcre2_set_callout().
func (m *MatchContext) SetCallout(callout func(*CalloutBlock, any) int, data any) int {
	m.callout = callout
	m.calloutData = data
	return 0
}

// SetSubstituteCallout is pcre2_set_substitute_callout().
func (m *MatchContext) SetSubstituteCallout(callout func(*SubstituteCalloutBlock, any) int, data any) int {
	m.substituteCallout = callout
	m.substituteCalloutData = data
	return 0
}

// SetHeapLimit is pcre2_set_heap_limit().
func (m *MatchContext) SetHeapLimit(limit uint32) int { m.heapLimit = limit; return 0 }

// SetMatchLimit is pcre2_set_match_limit().
func (m *MatchContext) SetMatchLimit(limit uint32) int { m.matchLimit = limit; return 0 }

// SetDepthLimit is pcre2_set_depth_limit().
func (m *MatchContext) SetDepthLimit(limit uint32) int { m.depthLimit = limit; return 0 }

// SetOffsetLimit is pcre2_set_offset_limit().
func (m *MatchContext) SetOffsetLimit(limit uint64) int { m.offsetLimit = limit; return 0 }

// SetRecursionLimit is the obsolete synonym of SetDepthLimit
// (pcre2_set_recursion_limit()).
func (m *MatchContext) SetRecursionLimit(limit uint32) int { return m.SetDepthLimit(limit) }

// ------------ Convert context ------------

// SetGlobSeparator is pcre2_set_glob_separator().
func (c *ConvertContext) SetGlobSeparator(separator uint32) int {
	if separator != CHAR_SLASH && separator != CHAR_BACKSLASH && separator != CHAR_DOT {
		return PCRE2_ERROR_BADDATA
	}
	c.globSeparator = separator
	return 0
}

// SetGlobEscape is pcre2_set_glob_escape(). ispunct() is that of the C locale.
func (c *ConvertContext) SetGlobEscape(escape uint32) int {
	if escape > 255 || (escape != 0 && !cIsPunct(int(escape))) {
		return PCRE2_ERROR_BADDATA
	}
	c.globEscape = escape
	return 0
}

// ------------ JIT stack (pcre2_jit_misc.c, no-JIT build) ------------

// JITStackCreate is pcre2_jit_stack_create(). In a build without JIT C returns
// NULL (this build has none); Go returns a descriptor that is accepted and
// ignored everywhere, which is what the Julia wrapper needs, except that C
// rejects start > max or max == 0 with NULL, kept here.
func JITStackCreate(start, max uint64) *JITStack {
	if start > max || max == 0 {
		return nil
	}
	return &JITStack{start: start, max: max}
}

// JITStackAssign is pcre2_jit_stack_assign(): the stack is recorded through
// the callback form and never used, as there is no JIT.
func (m *MatchContext) JITStackAssign(js *JITStack) {
	if m == nil {
		return
	}
	m.jitCallback = nil
	m.jitCallbackData = js
}

// JITStackFree is pcre2_jit_stack_free(); a no-op.
func JITStackFree(js *JITStack) {}

// JITFreeUnusedMemory is pcre2_jit_free_unused_memory(); a no-op.
func JITFreeUnusedMemory() {}

// JITCompile is pcre2_jit_compile(). This build has no JIT, so like C without
// SUPPORT_JIT it returns PCRE2_ERROR_JIT_BADOPTION.
func (c *Code) JITCompile(options uint32) int {
	if c == nil {
		return PCRE2_ERROR_NULL
	}
	return PCRE2_ERROR_JIT_BADOPTION
}

// JITMatch is pcre2_jit_match(); without JIT, PCRE2_ERROR_JIT_BADOPTION.
func JITMatch(code *Code, subject []byte, startoffset uint64, options uint32, md *MatchData, mc *MatchContext) int {
	return PCRE2_ERROR_JIT_BADOPTION
}
