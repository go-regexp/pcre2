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

The foundation is in place: public constants (`consts_gen.go`), internal
constants, opcodes and tables (`internal*.go`, `tables.go`), the Unicode
database (`ucd_tables.go`, `ucptables.go`, `ucd.go`), `xclass`, `extuni`,
`script_run`, error messages, contexts, match data, `PatternInfo`,
`Config`, the `Substring*` family, UTF-8 validation. `Compile` and `Match`
delegate to `compileImpl` / `matchImpl`, which the ports of `pcre2_compile.c`
and `pcre2_match.c` supply (until then `stub_compile.go` and `stub_match.go`
return `PCRE2_ERROR_INTERNAL`).

## Layout and conventions

- C names are kept (`PCRE2_CASELESS`, `OP_CBRA`, `GET`, `PUT`, `UCD_SCRIPT`);
  C functions are Go-cased; sizes and offsets are `uint64`; an offset into a
  subject or pattern is an `int` index into a `[]byte`.
- The compiled pattern (`Code`) keeps PCRE2's byte layout: name table then
  opcodes, 2-byte big-endian links.
- Constants are generated from the C headers (`go generate ./...` with
  `PCRE2_SRC` and `PCRE2_BUILD` set, see `gen.go`): `tools/cdefs` for the
  `#define`/`enum` text and `tools/ucdgen` for the Unicode tables.

## Tests

`go test ./...` runs everything; set `PCRE2_SRC` to the `src` directory of the
pcre2-10.44 tree to also compare the error texts, the default character tables
and the generated Unicode tables with the C sources. `FuzzValidUTF` has a
committed seed corpus under `testdata/fuzz`.

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
