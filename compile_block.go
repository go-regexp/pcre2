package pcre2

// named_group is named_group (pcre2_intmodedep.h:712-717): an entry of the list
// of named groups built during the first pass of compiling.
type named_group struct {
	name   []byte // the name; a slice of the pattern (C: pointer into it)
	number uint32 // group number
	length uint16 // length of the name
	isdup  uint16 // TRUE if a duplicate
}

// compile_block is struct compile_block (pcre2_intmodedep.h:722-763), the
// "static" information passed around between the compiling functions. Field
// names are lowerCamelCase of the C names. C pointers into arrays are modelled
// as slices (the array) plus an int index where the C code keeps a moving
// pointer; each such field says so.
type compile_block struct {
	cx                 *CompileContext // points to the compile context
	lcc                []byte          // points to lower casing table
	fcc                []byte          // points to case-flipping table
	cbits              []byte          // points to character type table
	ctypes             []byte          // points to table of type maps
	startWorkspace     []byte          // the start of working space (the whole workspace)
	startCode          []byte          // the start of the compiled code (offsets are relative to it)
	startPattern       []byte          // the start of the pattern
	endPattern         int             // end of the pattern: index into startPattern
	nameTable          []byte          // the name/number table
	workspaceSize      uint64          // size of workspace
	smallRefOffset     [10]uint64      // offsets for \1 to \9
	erroroffset        uint64          // offset of error in pattern
	namesFound         uint16          // number of entries so far
	nameEntrySize      uint16          // size of each entry
	parensDepth        uint16          // depth of nested parentheses
	assertDepth        uint16          // depth of nested assertions
	namedGroups        []named_group   // vector in pre-compile
	namedGroupListSize uint32          // number of entries in the list
	externalOptions    uint32          // external (initial) options
	externalFlags      uint32          // external flag bits to be set
	bracount           uint32          // count of capturing parentheses
	lastcapture        uint32          // last capture encountered
	parsedPattern      []uint32        // parsed pattern buffer
	parsedPatternEnd   int             // parsed pattern should not get here: index into parsedPattern
	groupinfo          []uint32        // group info vector
	topBackref         uint32          // maximum back reference
	backrefMap         uint32          // bitmap of low back refs
	nltype             uint32          // newline type
	nllen              uint32          // newline string length
	classRangeStart    uint32          // overall class range start
	classRangeEnd      uint32          // overall class range end
	nl                 [4]byte         // newline string when fixed length
	reqVaryopt         uint32          // "after variable item" flag for reqbyte
	maxVarlookbehind   uint32          // limit for variable lookbehinds
	maxLookbehind      int             // maximum lookbehind encountered (characters)
	hadAccept          bool            // (*ACCEPT) encountered
	hadPruneorskip     bool            // (*PRUNE) or (*SKIP) encountered
	hadRecurse         bool            // had a pattern recursion or subroutine call
	dupnames           bool            // duplicate names exist
	errorcode          int             // error code (pcre2_compile.c passes it by pointer; kept here for convenience)
}
