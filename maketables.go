// Port of pcre2_maketables.c: building character tables. The C function uses
// the ctype functions of the current locale; Go has no locale, so the tables
// are those of the "C" locale (which is also what pcre2_chartables.c.dist
// contains: the default tables).
package pcre2

// ctype predicates of the "C" locale for a byte value.
func cIsUpper(i int) bool  { return i >= 'A' && i <= 'Z' }
func cIsLower(i int) bool  { return i >= 'a' && i <= 'z' }
func cIsDigit(i int) bool  { return i >= '0' && i <= '9' }
func cIsAlpha(i int) bool  { return cIsUpper(i) || cIsLower(i) }
func cIsAlnum(i int) bool  { return cIsAlpha(i) || cIsDigit(i) }
func cIsSpace(i int) bool  { return i == ' ' || (i >= '\t' && i <= '\r') }
func cIsXDigit(i int) bool { return cIsDigit(i) || (i >= 'a' && i <= 'f') || (i >= 'A' && i <= 'F') }
func cIsGraph(i int) bool  { return i > ' ' && i < 0x7f }
func cIsPrint(i int) bool  { return i >= ' ' && i < 0x7f }
func cIsPunct(i int) bool  { return cIsGraph(i) && !cIsAlnum(i) }
func cIsCntrl(i int) bool  { return i < ' ' || i == 0x7f }
func cToLower(i int) int {
	if cIsUpper(i) {
		return i + 'a' - 'A'
	}
	return i
}
func cToUpper(i int) int {
	if cIsLower(i) {
		return i - ('a' - 'A')
	}
	return i
}

// Maketables builds a set of character tables (pcre2_maketables(), with a nil
// general context): TABLES_LENGTH bytes, the lower casing table, the case
// flipping table, the class bitmaps (cbits) and the character type table.
func Maketables() []byte {
	yield := make([]byte, xTABLES_LENGTH)
	p := 0

	// First comes the lower casing table
	for i := 0; i < 256; i++ {
		yield[p] = byte(cToLower(i))
		p++
	}

	// Next the case-flipping table
	for i := 0; i < 256; i++ {
		c := cToLower(i)
		if cIsLower(i) {
			c = cToUpper(i)
		}
		if c < 256 {
			yield[p] = byte(c)
		} else {
			yield[p] = byte(i)
		}
		p++
	}

	// Then the character class tables.
	set := func(off, i int) { yield[p+off+i/8] |= 1 << uint(i&7) }
	for i := 0; i < 256; i++ {
		if cIsDigit(i) {
			set(cbit_digit, i)
		}
		if cIsUpper(i) {
			set(cbit_upper, i)
		}
		if cIsLower(i) {
			set(cbit_lower, i)
		}
		if cIsAlnum(i) {
			set(cbit_word, i)
		}
		if i == '_' {
			set(cbit_word, i)
		}
		if cIsSpace(i) {
			set(cbit_space, i)
		}
		if cIsXDigit(i) {
			set(cbit_xdigit, i)
		}
		if cIsGraph(i) {
			set(cbit_graph, i)
		}
		if cIsPrint(i) {
			set(cbit_print, i)
		}
		if cIsPunct(i) {
			set(cbit_punct, i)
		}
		if cIsCntrl(i) {
			set(cbit_cntrl, i)
		}
	}
	p += cbit_length

	// Finally, the character type table.
	for i := 0; i < 256; i++ {
		x := 0
		if cIsSpace(i) {
			x += ctype_space
		}
		if cIsAlpha(i) {
			x += ctype_letter
		}
		if cIsLower(i) {
			x += ctype_lcletter
		}
		if cIsDigit(i) {
			x += ctype_digit
		}
		if cIsAlnum(i) || i == '_' {
			x += ctype_word
		}
		yield[p] = byte(x)
		p++
	}
	return yield
}

// MaketablesFree is pcre2_maketables_free(); the garbage collector owns the
// memory, so it does nothing.
func MaketablesFree(tables []byte) {}

// default_tables is _pcre2_default_tables (pcre2_chartables.c): the tables of
// the "C" locale, TABLES_LENGTH bytes. tables_test.go checks them byte for byte
// against pcre2_chartables.c.dist.
var default_tables = func() (t [xTABLES_LENGTH]byte) {
	copy(t[:], Maketables())
	return
}()
