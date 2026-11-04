# goldengen

Builds the golden corpus of the conformance harness (`testdata/golden/`) from
the PCRE2 10.44 distribution and an exact oracle `pcre2test`.

## What it does

For every `testinputN` that RunTest runs on an 8-bit, no-JIT, UTF/UCP,
link-size-2 build (the selection, with the reason for every skipped file, is
`corpus.Plan` and ends up in `testdata/golden/MANIFEST.json`):

1. splits the file into cases. A case is a pattern (possibly over several
   lines) with its data lines and the blank terminator, or a `#command`. This
   follows `main()` of `pcre2test.c`: every input line is echoed to the
   output, results follow the echo of the line that produced them, so a case
   is a run of input lines plus the run of output lines that covers them.
2. aligns each case with the shipped `testoutputN` (for tests 8, 14 and 22 the
   `-8` variants; for test 2 the `pcre2test -error ...` tail that RunTest
   appends becomes a separate case `2:error`);
3. runs the oracle on the whole file (`pcre2test -q testinputN`, working
   directory holding `testbtables`) and checks that its output is the shipped
   testoutput. Cases where it is not are marked `excluded` with the reason
   and listed on standard output; they are left out of conformance totals.
   With PCRE2 10.44 and the reference build, none differ;
4. writes `testinputN.json` (`{id, kind, line, input, expected, excluded}`
   per case; ids are `N:0001`) and `MANIFEST.json`.

## Usage

```sh
go run ./tools/goldengen \
  -testdata <pcre2-10.44>/testdata \
  -oracle   <pcre2-10.44 build>/pcre2test
```

The same values can come from `PCRE2_TESTDATA` and `PCRE2TEST_ORACLE`.

| flag | meaning |
|------|---------|
| `-out DIR` | output directory (default `testdata/golden`) |
| `-workdir DIR` | scratch directory for the oracle runs (default: user cache dir) |
| `-check` | write nothing; exit 1 if a committed file is out of date |
| `-only N` | only testinput N (never rewrites MANIFEST.json) |
| `-verify` | also replay every case on its own through the oracle, after the state-setting `#commands` before it. This validates the case splitter independently of the shipped outputs. Expected result: only file 20 (needs `#pop`/`#load` state) and nothing else differs |
| `-freq` | print how often each pattern and data modifier is used by the committed corpus (used to prioritise the modifiers implemented by `internal/pcre2testgo`) |

The oracle is the exact PCRE2 10.44 non-JIT build; the process is
deterministic, so `-check` is suitable for CI where the distribution and the
oracle are available. `go test ./internal/pcre2testgo/corpus` runs
`TestGoldensMatchDistribution` (the same check) when `PCRE2_TESTDATA` and
`PCRE2TEST_ORACLE` are set, and skips otherwise.
