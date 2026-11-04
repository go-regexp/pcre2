# pcre2

Pure-Go (no cgo, no dependency) statement-by-statement port of
[PCRE2](https://github.com/PCRE2Project/pcre2) 10.44: the 8-bit library, UTF and
Unicode property support, `LINK_SIZE` 2, no JIT. Its consumer is Julia's
`base/pcre.jl`; the aim is byte-for-byte identical compiled patterns, match
results and error messages to libpcre2 10.44, which is the test oracle.

**This is a port of PCRE2.** PCRE2 is Copyright (c) 1997-2024 University of
Cambridge (Philip Hazel), released under the BSD licence of the PCRE2 project;
its notice is kept verbatim in
[LICENSE-PCRE2](LICENSE-PCRE2). The Go code is under the BSD 3-clause licence in
[LICENSE](LICENSE). Every Go file names the C file it ports.

## Status

v0.1.0. `Compile` is the port of `pcre2_compile.c` (with `auto_possess.go`,
`study.go`, `printint.go`) and produces the same bytecode, error codes and
offsets as libpcre2 10.44; `Match` is the port of `pcre2_match.c` (heap-frame
matcher, start optimisations, partial matching, limits). The public surface is
the `pcre2_*` C API: `Compile`, `Match`, the contexts, `MatchData`,
`PatternInfo`/`NameTable`, the `Substring*` family, `GetErrorMessage`, `Config`,
`Maketables`, `ValidUTF`, and the `PCRE2_*` constants. The macros and tables are
unexported.

- **No JIT.** Like a libpcre2 built without JIT, `JITCompile` returns
  `PCRE2_ERROR_JIT_BADOPTION`; the JIT stack functions are no-ops.
- **Unicode 15.0.0** (the version of PCRE2 10.44).
- **Not ported yet:** the DFA matcher (`pcre2_dfa_match.c`), `pcre2_substitute.c`,
  `pcre2_convert.c`, serialization and the POSIX wrapper.
- **Conformance:** 5429 of the 7155 cases of PCRE2's own testinput files that
  apply to this build pass (75.9%); 2 fail; 1724 need a feature listed above
  (the DFA files testinput6, 7, 14, substitute, convert). Every non-DFA case that
  needs only compile and match passes except those two.
- **Speed** against `pcre2test -t` (non-JIT, one core) is not measured yet
  (the machine load was too high); `tools/bench` is ready for it.

## Layout and conventions

- C names are kept (`PCRE2_CASELESS`, `Compile`; internal macros and opcodes
  are unexported with an `x` prefix by `tools/apisurface`, so `GET` is `xGET`);
  C functions are Go-cased; sizes and offsets are `uint64`; an offset into a
  subject or pattern is an `int` index into a `[]byte`.
- The compiled pattern (`Code`) keeps PCRE2's byte layout: name table then
  opcodes, 2-byte big-endian links.
- Constants are generated from the C headers (`go generate ./...` with
  `PCRE2_SRC` and `PCRE2_BUILD` set, see `gen.go`): `tools/cdefs` for the
  `#define`/`enum` text and `tools/ucdgen` for the Unicode tables. After
regenerating, run `go run ./tools/apisurface -w .` to unexport the internals again.

## Tests

`go test ./...` runs everything; set `PCRE2_SRC` to the `src` directory of the
pcre2-10.44 tree to also compare the error texts, the default character tables
and the generated Unicode tables with the C sources. `FuzzValidUTF` has a
committed seed corpus under `testdata/fuzz`, as does `FuzzCompile` (it must
never panic or hang).

The compiler is checked against the oracle in two ways. `TestCompileGolden`
runs the golden cases that need no match (bytecode `/B`, info `/I`, errors).
`TestCompileOracle` runs every pattern of the corpus, plus random mutations of
them (`PCRE2_ORACLE_MUTATIONS=n`), through this library and through the real
`pcre2test` (`PCRE2TEST=/path/to/pcre2test`) and compares the outputs byte for
byte.

### Conformance

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
