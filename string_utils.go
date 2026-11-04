// Port of pcre2_string_utils.c: string functions on code units. A "zero
// terminated" Go slice ends at the first NUL or at its end, whichever comes
// first. memmove is the built-in copy in Go and is not ported.
package pcre2

// cuAt returns s[i], or 0 beyond the end (the implicit terminator).
func cuAt(s []byte, i int) byte {
	if i < len(s) {
		return s[i]
	}
	return 0
}

func cmpUnits(c1, c2 byte) int {
	if c1 > c2 {
		return 1
	}
	return -1
}

// strcmp compares two zero-terminated strings; returns 0, 1 or -1.
// (PRIV(strcmp), pcre2_string_utils.c:102)
func strcmp(str1, str2 []byte) int {
	for i := 0; cuAt(str1, i) != 0 || cuAt(str2, i) != 0; i++ {
		if c1, c2 := cuAt(str1, i), cuAt(str2, i); c1 != c2 {
			return cmpUnits(c1, c2)
		}
	}
	return 0
}

// strcmp_c8 compares a zero-terminated string with a Go string. (PRIV(strcmp_c8), :130)
func strcmp_c8(str1 []byte, str2 string) int {
	for i := 0; cuAt(str1, i) != 0 || i < len(str2); i++ {
		var c2 byte
		if i < len(str2) {
			c2 = str2[i]
		}
		if c1 := cuAt(str1, i); c1 != c2 {
			return cmpUnits(c1, c2)
		}
	}
	return 0
}

// strncmp compares len units of two strings. (PRIV(strncmp), :157)
func strncmp(str1, str2 []byte, length uint64) int {
	for i := 0; uint64(i) < length; i++ {
		if c1, c2 := cuAt(str1, i), cuAt(str2, i); c1 != c2 {
			return cmpUnits(c1, c2)
		}
	}
	return 0
}

// strncmp_c8 compares len units of a string with a Go string. (PRIV(strncmp_c8), :186)
func strncmp_c8(str1 []byte, str2 string, length uint64) int {
	for i := 0; uint64(i) < length; i++ {
		var c2 byte
		if i < len(str2) {
			c2 = str2[i]
		}
		if c1 := cuAt(str1, i); c1 != c2 {
			return cmpUnits(c1, c2)
		}
	}
	return 0
}

// strlen returns the length of a zero-terminated string. (PRIV(strlen), :209)
func strlen(str []byte) uint64 {
	var c uint64
	for cuAt(str, int(c)) != 0 {
		c++
	}
	return c
}

// strcpy_c8 copies a Go string into str1 followed by a zero and returns the
// number of units copied, excluding the zero. (PRIV(strcpy_c8), :229)
func strcpy_c8(str1 []byte, str2 string) uint64 {
	n := copy(str1, str2)
	str1[n] = 0
	return uint64(n)
}
