package main

import (
	"github.com/go-regexp/pcre2/internal/pcre2testgo"
	"github.com/go-regexp/pcre2/internal/pcre2testgo/libpcre2"
)

func defaultLib() pcre2testgo.Lib { return libpcre2.New() }
