# pcre2
Pure-Go port of PCRE2 10.44 (compile, match, pattern info), byte-for-byte against libpcre2

## Conformance

The PCRE2 10.44 test files that apply to an 8-bit, non-JIT, UTF/UCP build are
split into cases (7155 of them) with the output of the reference `pcre2test`
(`testdata/golden/`, built by `tools/goldengen`, which also checks every file
against an oracle `pcre2test` run). `internal/pcre2testgo` is a Go
reimplementation of the part of `pcre2test` that runs those files, and
`cmd/pcre2test-go` is its command line (`pcre2test-go [options] [input [output]]`).

```sh
go test -run TestConformance -v .                         # every case, share per file
go test -run 'TestConformance/testinput1/1:0042' -v .     # one case
PCRE2_CONFORMANCE_JSON=conformance.json go test -run TestConformance .
```

`testdata/golden/KNOWN_FAIL.txt` lists the cases that do not pass yet; a listed
case that fails is skipped, an unlisted case that fails is a regression.
`go run ./tools/bench` compares compile and match times with `pcre2test -t`.
