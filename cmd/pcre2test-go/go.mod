module github.com/go-regexp/pcre2/cmd/pcre2test-go

go 1.25

require (
	github.com/go-regexp/pcre2 v0.0.0
	github.com/spf13/cobra v1.10.2
)

replace github.com/go-regexp/pcre2 => ../..
