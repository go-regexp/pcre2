package pcre2

import "testing"

func TestPrintIntAutoCallout(t *testing.T) {
	// /a+b/IB,auto_callout from testoutput2 of PCRE2 10.44.
	code := []byte{
		OP_BRA, 0, 0,
		OP_CALLOUT, 0, 0, 0, 2, 255,
		OP_POSPLUS, 'a',
		OP_CALLOUT, 0, 2, 0, 1, 255,
		OP_CHAR, 'b',
		OP_CALLOUT, 0, 3, 0, 0, 255,
		OP_KET, 0, 0,
		OP_END,
	}
	re := &Code{code: code}
	want := "        Bra\n" +
		"        Callout 255 0 2\n" +
		"        a++\n" +
		"        Callout 255 2 1\n" +
		"        b\n" +
		"        Callout 255 3 0\n" +
		"        Ket\n" +
		"        End\n" +
		"------------------------------------------------------------------\n"
	if got := re.PrintInt(false); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestOPNamesLength(t *testing.T) {
	if len(OP_names) != OP_TABLE_LENGTH {
		t.Fatalf("OP_names has %d entries, want %d", len(OP_names), OP_TABLE_LENGTH)
	}
}
