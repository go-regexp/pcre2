// Port of pcre2_chkdint.c: checked integer operations.
package pcre2

// ckd_smul stores a*b in *r and reports whether the multiplication overflowed
// a PCRE2_SIZE (the HAVE_BUILTIN_MUL_OVERFLOW variant: a negative product, or
// one that does not fit, is an overflow; int is 32 bits in C so the 64-bit
// product of two ints cannot wrap). (PRIV(ckd_smul), pcre2_chkdint.c:309)
func ckd_smul(r *uint64, a, b int32) bool {
	m := int64(a) * int64(b)
	if m < 0 {
		return true
	}
	*r = uint64(m)
	return false
}
