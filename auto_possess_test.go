package pcre2

import "testing"

func testCB(opts uint32) *compile_block {
	t := default_tables[:]
	return &compile_block{
		lcc: t[lcc_offset:], fcc: t[fcc_offset:], cbits: t[cbits_offset:],
		ctypes: t[ctypes_offset:], externalOptions: opts,
	}
}

func TestAutoPossessify(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want byte // expected first opcode afterwards
	}{
		{"a*b", []byte{OP_STAR, 'a', OP_CHAR, 'b', OP_END}, OP_POSSTAR},
		{"a*a", []byte{OP_STAR, 'a', OP_CHAR, 'a', OP_END}, OP_STAR},
		{"a*end", []byte{OP_STAR, 'a', OP_END}, OP_POSSTAR},
		{"a*?end", []byte{OP_MINSTAR, 'a', OP_END}, OP_MINSTAR},
		{"\\d+a", []byte{OP_TYPEPLUS, OP_DIGIT, OP_CHAR, 'a', OP_END}, OP_TYPEPOSPLUS},
		{"\\d+1", []byte{OP_TYPEPLUS, OP_DIGIT, OP_CHAR, '1', OP_END}, OP_TYPEPLUS},
		{"a+A i", []byte{OP_PLUS, 'a', OP_CHARI, 'a', OP_END}, OP_PLUS},
	}
	for _, c := range cases {
		code := append([]byte(nil), c.in...)
		if rc := auto_possessify(code, testCB(0)); rc != 0 {
			t.Errorf("%s: rc %d", c.name, rc)
		}
		if code[0] != c.want {
			t.Errorf("%s: opcode %d want %d", c.name, code[0], c.want)
		}
	}
	if auto_possessify([]byte{200}, testCB(0)) != -1 {
		t.Error("bad opcode not reported")
	}
}
