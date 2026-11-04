package pcre2

import (
	"testing"
	"unicode/utf8"
)

// xcb builds XCLASS data (flag byte, optional bitmap, items, XCL_END) the way
// the compiler lays it out after the OP_XCLASS length.
type xcb struct{ b []byte }

func newXC(flags byte, bitmapChars ...byte) *xcb {
	x := &xcb{b: []byte{flags}}
	if flags&XCL_MAP != 0 {
		m := make([]byte, 32)
		for _, c := range bitmapChars {
			m[c/8] |= 1 << (c & 7)
		}
		x.b = append(x.b, m...)
	}
	return x
}
func (x *xcb) single(c rune) *xcb {
	x.b = append(x.b, XCL_SINGLE)
	x.b = utf8.AppendRune(x.b, c)
	return x
}
func (x *xcb) rng(lo, hi rune) *xcb {
	x.b = append(x.b, XCL_RANGE)
	x.b = utf8.AppendRune(x.b, lo)
	x.b = utf8.AppendRune(x.b, hi)
	return x
}
func (x *xcb) prop(t, pt, val byte) *xcb {
	x.b = append(x.b, t, pt, val)
	return x
}
func (x *xcb) end() []byte { return append(x.b, XCL_END) }

func TestXclassSingleRange(t *testing.T) {
	d := newXC(0).single(0x100).rng(0x3000, 0x30ff).end()
	for c, want := range map[uint32]bool{'a': false, 0xff: false, 0x100: true, 0x2fff: false, 0x3000: true, 0x3042: true, 0x30ff: true, 0x3100: false, 0x10ffff: false} {
		if got := xclass(c, d, true); got != want {
			t.Errorf("U+%04X: %v, want %v", c, got, want)
		}
	}
	// Negated: everything the items do not match, including ASCII (no bitmap).
	d = newXC(XCL_NOT).single(0x100).rng(0x3000, 0x30ff).end()
	for c, want := range map[uint32]bool{'a': true, 0x100: false, 0x3042: false, 0x4e00: true} {
		if got := xclass(c, d, true); got != want {
			t.Errorf("negated U+%04X: %v, want %v", c, got, want)
		}
	}
	// Items that start below 256 are reached when there is no bitmap and prop.
	d = newXC(XCL_MAP, 'a', 'z', 0xe9).rng(0x7f, 0x2ff).end()
	if !xclass('a', d, true) || xclass('b', d, true) || !xclass(0xe9, d, true) || !xclass(0x2ff, d, true) || xclass(0x300, d, true) {
		t.Error("map plus range")
	}
}

func TestXclassMap(t *testing.T) {
	d := newXC(XCL_MAP, 'a', 'z', 0xe9).single(0x4e00).end()
	for c, want := range map[uint32]bool{'a': true, 'z': true, 'b': false, 0xe9: true, 0xe8: false, 0x4e00: true, 0x4e01: false} {
		if got := xclass(c, d, true); got != want {
			t.Errorf("U+%04X: %v, want %v", c, got, want)
		}
	}
	d = newXC(XCL_MAP|XCL_NOT, 'a').single(0x4e00).end()
	// For c < 256 without XCL_HASPROP the bitmap result is final: C returns the
	// bit as is (the compiler stores the bitmap already inverted); above 255
	// the negation applies.
	for c, want := range map[uint32]bool{'a': true, 'b': false, 0x4e00: false, 0x4e01: true} {
		if got := xclass(c, d, true); got != want {
			t.Errorf("negated map U+%04X: %v, want %v", c, got, want)
		}
	}
}

func TestXclassProperties(t *testing.T) {
	type tc struct {
		name string
		pt   byte
		val  byte
		in   []uint32
		out  []uint32
	}
	for _, c := range []tc{
		{"any", PT_ANY, 0, []uint32{'a', 0x4e00}, nil},
		{"lamp", PT_LAMP, 0, []uint32{'a', 'A', 0x1c5}, []uint32{0x4e00, '1', 0x2b0}},
		{"gc L", PT_GC, ucp_L, []uint32{'a', 0x4e00, 0x2b0}, []uint32{'1', ' '}},
		{"pc Lu", PT_PC, ucp_Lu, []uint32{'A', 0x391}, []uint32{'a'}},
		{"sc Greek", PT_SC, ucp_Greek, []uint32{0x3b1, 0x391}, []uint32{'a', 0x430}},
		{"scx Arabic", PT_SCX, ucp_Arabic, []uint32{0x627, 0x660}, []uint32{'a'}},
		{"alnum", PT_ALNUM, 0, []uint32{'a', '1', 0x4e00, 0x663}, []uint32{' ', '_', 0x301}},
		{"space", PT_SPACE, 0, []uint32{' ', '\t', '\n', 0x0b, 0xa0, 0x85, 0x2028, 0x3000, 0x2003}, []uint32{'a', 0x200b}},
		{"pxspace", PT_PXSPACE, 0, []uint32{' ', 0x0c, 0x1680, 0x205f}, []uint32{'a', '_'}},
		{"word", PT_WORD, 0, []uint32{'a', '1', '_', 0x301, 0x203f}, []uint32{' ', '-'}},
		{"ucnc", PT_UCNC, 0, []uint32{'$', '@', '`', 0xa0, 0x4e00, 0xd7ff, 0xe000}, []uint32{'a', 0xd800, 0xdfff}},
		{"bidi AN", PT_BIDICL, ucp_bidiAN, []uint32{0x660, 0x6dd}, []uint32{'a'}},
		{"bool Alphabetic", PT_BOOL, ucp_Alphabetic, []uint32{'a', 0x4e00}, []uint32{'1', ' '}},
		{"bool Emoji", PT_BOOL, ucp_Emoji, []uint32{0x1f600}, []uint32{'a'}},
		{"pxpunct", PT_PXPUNCT, 0, []uint32{'!', '$', '+', '<', '=', '>', '^', '`', '|', '~', 0x2014}, []uint32{'a', ' ', 0xa9, 0x20ac}},
		{"pxxdigit", PT_PXXDIGIT, 0, []uint32{'0', '9', 'a', 'F', 0xff10, 0xff26, 0xff46}, []uint32{'g', 'G', 0xff47, 0x660}},
	} {
		prop := newXC(XCL_HASPROP).prop(XCL_PROP, c.pt, c.val).end()
		notprop := newXC(XCL_HASPROP).prop(XCL_NOTPROP, c.pt, c.val).end()
		neg := newXC(XCL_HASPROP|XCL_NOT).prop(XCL_PROP, c.pt, c.val).end()
		for _, ch := range c.in {
			if !xclass(ch, prop, true) || xclass(ch, notprop, true) || xclass(ch, neg, true) {
				t.Errorf("%s: U+%04X should match \\p, not \\P, not negated", c.name, ch)
			}
		}
		for _, ch := range c.out {
			if xclass(ch, prop, true) || !xclass(ch, notprop, true) || !xclass(ch, neg, true) {
				t.Errorf("%s: U+%04X should not match \\p, should match \\P and negated", c.name, ch)
			}
		}
	}

	// PT_PXGRAPH and PT_PXPRINT: the Cf exceptions and the Z handling.
	g := newXC(XCL_HASPROP).prop(XCL_PROP, PT_PXGRAPH, 0).end()
	p := newXC(XCL_HASPROP).prop(XCL_PROP, PT_PXPRINT, 0).end()
	for ch, want := range map[uint32][2]bool{
		'a': {true, true}, ' ': {false, true}, '\n': {false, false}, 0xad: {true, true}, // soft hyphen is Cf
		0x61c: {false, false}, 0x180e: {false, true}, 0x2066: {false, false}, 0x2069: {false, false},
		0x2028: {false, false}, 0x2029: {false, false}, 0xa0: {false, true}, 0x3000: {false, true},
		0xe000: {false, false}, // Co
	} {
		if xclass(ch, g, true) != want[0] || xclass(ch, p, true) != want[1] {
			t.Errorf("U+%04X: graph %v print %v, want %v", ch, xclass(ch, g, true), xclass(ch, p, true), want)
		}
	}

	// An unknown property type returns false whatever the negation.
	bad := newXC(XCL_HASPROP|XCL_NOT).prop(XCL_PROP, 99, 0).end()
	if xclass('a', bad, true) {
		t.Error("unknown property type matched")
	}
}

func TestXclassMixed(t *testing.T) {
	// A bitmap, a property, a single and a range, in the order the compiler
	// emits them: property items are skipped over correctly (data += 2).
	d := newXC(XCL_MAP|XCL_HASPROP, 'x').
		prop(XCL_PROP, PT_SC, ucp_Greek).single(0x1f600).rng(0x2000, 0x2010).end()
	for c, want := range map[uint32]bool{'x': true, 'y': false, 0x3b1: true, 0x1f600: true, 0x2005: true, 0x2011: false, 0x4e00: false} {
		if got := xclass(c, d, true); got != want {
			t.Errorf("U+%04X: %v, want %v", c, got, want)
		}
	}
	// With XCL_HASPROP and a bitmap, a character below 256 missing from the
	// bitmap still reaches the property list.
	if !xclass(0xe9, newXC(XCL_MAP|XCL_HASPROP).prop(XCL_PROP, PT_GC, ucp_L).end(), true) {
		t.Error("U+00E9 should be found by the property")
	}
}
