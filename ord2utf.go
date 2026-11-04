// Port of pcre2_ord2utf.c (8-bit): convert a code point into UTF-8.
package pcre2

// ord2utf converts the code point cvalue to UTF-8, writes it at buffer[0:] and
// returns the number of code units placed in the buffer. (PRIV(ord2utf),
// pcre2_ord2utf.c:81)
func ord2utf(cvalue uint32, buffer []byte) uint {
	var i, j int
	for i = 0; i < utf8_table1_size; i++ {
		if int(cvalue) <= utf8_table1[i] {
			break
		}
	}
	b := i
	for j = i; j > 0; j-- {
		buffer[b] = 0x80 | byte(cvalue&0x3f)
		b--
		cvalue >>= 6
	}
	buffer[b] = byte(utf8_table2[i]) | byte(cvalue)
	return uint(i + 1)
}
