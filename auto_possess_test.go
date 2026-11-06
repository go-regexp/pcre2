package pcre2

import "testing"

func testCB(opts uint32) *compile_block {
	t := default_tables[:]
	return &compile_block{
		lcc: t[lcc_offset:], fcc: t[fcc_offset:], cbits: t[cbits_offset:],
		ctypes: t[ctypes_offset:], externalOptions: opts,
	}
}

func xTestAutoPossessify(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want byte // expected first opcode afterwards
	}{
		{"a*b", []byte{xOP_STAR, 'a', xOP_CHAR, 'b', xOP_END}, xOP_POSSTAR},
		{"a*a", []byte{xOP_STAR, 'a', xOP_CHAR, 'a', xOP_END}, xOP_STAR},
		{"a*end", []byte{xOP_STAR, 'a', xOP_END}, xOP_POSSTAR},
		{"a*?end", []byte{xOP_MINSTAR, 'a', xOP_END}, xOP_MINSTAR},
		{"\\d+a", []byte{xOP_TYPEPLUS, xOP_DIGIT, xOP_CHAR, 'a', xOP_END}, xOP_TYPEPOSPLUS},
		{"\\d+1", []byte{xOP_TYPEPLUS, xOP_DIGIT, xOP_CHAR, '1', xOP_END}, xOP_TYPEPLUS},
		{"a+A i", []byte{xOP_PLUS, 'a', xOP_CHARI, 'a', xOP_END}, xOP_PLUS},
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
