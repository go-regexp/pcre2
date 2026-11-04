package pcre2

import "testing"

func xTestPrintIntHandBuilt(t *testing.T) {
	if len(xOP_names) != xOP_TABLE_LENGTH {
		t.Fatalf("OP_names has %d entries, want %d", len(xOP_names), xOP_TABLE_LENGTH)
	}
	// /abc/ with a leading class [a-c] and a+ : BRA CHAR a b c KET END
	code := []byte{xOP_BRA, 0, 9, xOP_CHAR, 'a', xOP_CHAR, 'b', xOP_CHAR, 'c', xOP_KET, 0, 9, xOP_END}
	re := &Code{code: code}
	got := re.PrintInt(true)
	want := "  0   9 Bra\n" +
		"  3     abc\n" +
		"  9   9 Ket\n" +
		" 12     End\n" +
		"------------------------------------------------------------------\n"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}
