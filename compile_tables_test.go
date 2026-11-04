package pcre2

import "testing"

func xTestCompileTablesShape(t *testing.T) {
	if len(opcode_possessify) != xOP_CALLOUT+1 {
		t.Fatalf("opcode_possessify has %d entries, want %d", len(opcode_possessify), xOP_CALLOUT+1)
	}
	if opcode_possessify[xOP_STAR] != xOP_POSSTAR || opcode_possessify[xOP_CRRANGE] != xOP_CRPOSRANGE {
		t.Fatal("opcode_possessify misaligned")
	}
	if len(meta_extra_lengths) != int(xMETA_MINMAX_QUERY>>16&0x7fff)+1 {
		t.Fatalf("meta_extra_lengths has %d entries", len(meta_extra_lengths))
	}
	if len(escapes) != 'z'-'0'+1 {
		t.Fatalf("escapes has %d entries", len(escapes))
	}
	if len(posix_class_maps) != 3*(len(posix_name_lengths)-1) {
		t.Fatal("posix_class_maps size")
	}
	n := 0
	for i := 0; i < len(alasnames); i++ {
		if alasnames[i] == 0 {
			n++
		}
	}
	if n+1 != alascount {
		t.Fatalf("alasnames has %d names, alasmeta %d", n+1, alascount)
	}
}

func xTestReadRepeatCounts(t *testing.T) {
	pat := []byte("{2, 5}x")
	p, ec := 1, 0
	var mn, mx uint32
	if !read_repeat_counts(pat, &p, len(pat), &mn, &mx, &ec) || mn != 2 || mx != 5 || p != 7-1 || ec != 0 {
		t.Fatalf("got %d %d %d %d", mn, mx, p, ec)
	}
}
