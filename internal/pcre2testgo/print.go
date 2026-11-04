package pcre2testgo

import (
	"fmt"
	"io"
)

var (
	utf8Table1 = [...]uint32{0x7f, 0x7ff, 0xffff, 0x1fffff, 0x3ffffff, 0x7fffffff}
	utf8Table2 = [...]byte{0, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc}
	utf8Table3 = [...]uint32{0xff, 0x1f, 0x0f, 0x07, 0x03, 0x01}
)

// utf82ord ports utf82ord() of pcre2test.c: the original RFC 2279 UTF-8
// (up to 6 bytes, values to 0x7fffffff). It returns the number of bytes
// consumed (> 0), or <= 0 for a malformed sequence.
func utf82ord(b []byte) (uint32, int) {
	if len(b) == 0 {
		return 0, 0
	}
	c := uint32(b[0])
	d := c
	i := -1
	for i = -1; i < 6; i++ {
		if d&0x80 == 0 {
			break
		}
		d <<= 1
	}
	if i == -1 {
		return c, 1
	}
	if i == 0 || i == 6 {
		return 0, 0
	}
	s := uint(6 * i)
	d = (c & utf8Table3[i]) << s
	for j := 0; j < i; j++ {
		if 1+j >= len(b) {
			return 0, 0
		}
		c = uint32(b[1+j])
		if c&0xc0 != 0x80 {
			return 0, -(j + 1)
		}
		s -= 6
		d |= (c & 0x3f) << s
	}
	j := 0
	for ; j < len(utf8Table1); j++ {
		if d <= utf8Table1[j] {
			break
		}
	}
	if j != i {
		return 0, -(i + 1)
	}
	return d, i + 1
}

// ord2utf8 ports ord2utf8(): the original UTF-8 encoding of a value.
func ord2utf8(c uint32) []byte {
	if c > 0x7fffffff {
		return nil
	}
	i := 0
	for ; i < len(utf8Table1); i++ {
		if c <= utf8Table1[i] {
			break
		}
	}
	out := make([]byte, i+1)
	for j := i; j > 0; j-- {
		out[j] = 0x80 | byte(c&0x3f)
		c >>= 6
	}
	out[0] = utf8Table2[i] | byte(c)
	return out
}

// pchar ports pchar(): print one character literally or as a hex escape,
// returning the number of characters printed. w may be nil (count only).
func pchar(c uint32, utf bool, w io.Writer) int {
	if c >= 32 && c < 127 {
		if w != nil {
			fmt.Fprintf(w, "%c", c)
		}
		return 1
	}
	if c < 0x100 {
		if utf {
			if w != nil {
				fmt.Fprintf(w, "\\x{%02x}", c)
			}
			return 6
		}
		if w != nil {
			fmt.Fprintf(w, "\\x%02x", c)
		}
		return 4
	}
	s := fmt.Sprintf("\\x{%02x}", c)
	if w != nil {
		io.WriteString(w, s)
	}
	return len(s)
}

// pchars ports pchars8(): print a code unit string, decoding UTF-8 in UTF
// mode. A negative length means the length is in the first byte (a *MARK
// string); the caller strips that, so here length is the slice length.
func pchars(p []byte, utf bool, w io.Writer) int {
	yield := 0
	for len(p) > 0 {
		if utf {
			if c, n := utf82ord(p); n > 0 {
				p = p[n:]
				yield += pchar(c, utf, w)
				continue
			}
		}
		yield += pchar(uint32(p[0]), utf, w)
		p = p[1:]
	}
	return yield
}
