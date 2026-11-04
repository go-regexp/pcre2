# bench

Timing driver: the Go library against the oracle `pcre2test -t` (PCRE2 10.44,
non-JIT), on a handful of representative patterns. Designed now, to be run
once the matcher exists.

```sh
go run ./tools/bench -oracle <pcre2 build>/pcre2test            # table
go run ./tools/bench -oracle ... -json bench.json -rounds 11    # + JSON
go run ./tools/bench -list                                      # what is measured
```

## Method

* One benchmark is a pattern, its modifiers and a subject
  `Prefix + Unit*Count + Suffix`. The oracle input file uses pcre2test's
  replication syntax (`\[unit]{count}`), so even a 100 kB subject is a short
  line; non-alphanumeric bytes are written `\xhh`.
* Oracle: `pcre2test -q -t N file`, reading the `Compile time` and
  `Match time` lines (microseconds per operation, as pcre2test computes them
  with `clock()`; N is chosen per benchmark so that one run takes well above
  the clock resolution).
* Go: the same N compilations then N matches through the library (the same
  `internal/pcre2testgo` `Lib` adapter the conformance tests use), wall clock,
  `GOMAXPROCS(1)`, match data allocated once.
* Rounds are interleaved: for every benchmark and every round, oracle then Go.
  The report is the median over the rounds (`-rounds`, default 7).
* A ratio above 1 means the Go library is slower than the C reference; the row
  is flagged. Per the project rules that is an open defect.
* The 1-minute load average is read first (`/proc/loadavg` or
  `sysctl vm.loadavg`); above `-maxload` (default 8) the program measures
  nothing and exits 1 saying so. Allocation counts are not part of this tool
  (use `testing.AllocsPerRun`, which is exact under load).
* A benchmark also checks that the subject matches (or not) as declared, so a
  fast wrong answer does not show up as a win.
