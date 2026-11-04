package pcre2

import "testing"

func TestStudyHandBuilt(t *testing.T) {
	// abc: BRA CHAR a CHAR b CHAR c KET END
	abc := []byte{OP_BRA, 0, 9, OP_CHAR, 'a', OP_CHAR, 'b', OP_CHAR, 'c', OP_KET, 0, 9, OP_END}
	re := &Code{code: abc}
	if rc := study(re); rc != 0 {
		t.Fatalf("rc %d", rc)
	}
	if re.minlength != 3 {
		t.Errorf("minlength %d", re.minlength)
	}
	if re.flags&PCRE2_FIRSTMAPSET != 0 && re.flags&PCRE2_FIRSTSET == 0 {
		t.Errorf("flags %x", re.flags)
	}
	if re.flags&PCRE2_FIRSTSET == 0 || re.firstCodeunit != 'a' {
		t.Errorf("first %x flags %x", re.firstCodeunit, re.flags)
	}

	// (a|B): BRA CHAR a ALT CHAR B KET END -> bitmap {a,B}, minlength 1
	alt := []byte{OP_BRA, 0, 9, OP_CHAR, 'a', OP_ALT, 0, 3, OP_CHAR, 'B', OP_KET, 0, 9, OP_END}
	alt[2] = 5   // BRA -> ALT
	alt[7] = 5   // ALT -> KET
	alt[12] = 10 // KET back to BRA
	re = &Code{code: alt}
	if rc := study(re); rc != 0 {
		t.Fatalf("alt rc %d", rc)
	}
	if re.minlength != 1 || re.flags&PCRE2_FIRSTMAPSET == 0 {
		t.Errorf("alt minlength %d flags %x", re.minlength, re.flags)
	}
	if re.startBitmap['a'/8]&(1<<('a'&7)) == 0 || re.startBitmap['B'/8]&(1<<('B'&7)) == 0 {
		t.Errorf("bitmap %v", re.startBitmap)
	}

	// Unknown opcode in minlength: OP_lengths exists but opcode 255 does not.
	bad := &Code{code: []byte{OP_BRA, 0, 4, 255, OP_KET, 0, 4, OP_END}, flags: PCRE2_FIRSTSET}
	if rc := study(bad); rc != 3 {
		t.Errorf("bad rc %d", rc)
	}
}
