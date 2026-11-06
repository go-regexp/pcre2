// Command apisurface lists, and optionally unexports, the exported top-level
// identifiers of the root package that are not part of the pcre2_* C API.
//
// Usage: apisurface [-w] [dir]
//
// Without -w it prints the identifiers that would be renamed. With -w it
// rewrites every .go file of package pcre2 in dir (build tags ignored),
// prefixing each such identifier with "x" (GET becomes xGET).
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// public is the set of exported names that stay (the C API shape).
var public = map[string]bool{}

func init() {
	for _, n := range strings.Fields(`Compile Match Code MatchData CompileContext MatchContext
		GeneralContext ConvertContext JITStack CalloutBlock CalloutEnumerateBlock
		SubstituteCalloutBlock GeneralContextCreate NewCompileContext CompileContextCreate
		NewMatchContext MatchContextCreate NewConvertContext JITStackCreate JITStackFree
		JITFreeUnusedMemory JITMatch GetErrorMessage GetErrorMessageBuf Config Maketables
		MaketablesFree NewMatchDataSize NewMatchData PatternInfoSize
		SubstringCopyByName SubstringCopyByNumber SubstringGetByName SubstringGetByNumber
		SubstringFree SubstringLengthByName SubstringLengthByNumber SubstringListGet
		SubstringListFree SubstringNametableScan SubstringNumberFromName ValidUTF`) {
		public[n] = true
	}
}

func keep(name string) bool {
	return public[name] || strings.HasPrefix(name, "PCRE2_") || strings.HasPrefix(name, "Rig") || strings.HasPrefix(name, "Harness")
}

// exported returns the exported top-level names of package pcre2 in dir and
// the set of all identifiers (to detect collisions).
func exported(dir string) (names []string, all map[string]bool, files []string, err error) {
	all = map[string]bool{}
	fset := token.NewFileSet()
	matches, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, nil, nil, err
	}
	seen := map[string]bool{}
	for _, f := range matches {
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			return nil, nil, nil, err
		}
		if af.Name.Name != "pcre2" {
			continue
		}
		files = append(files, f)
		ast.Inspect(af, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				all[id.Name] = true
			}
			return true
		})
		for _, d := range af.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil && d.Name.IsExported() && !keep(d.Name.Name) && !seen[d.Name.Name] {
					seen[d.Name.Name] = true
					names = append(names, d.Name.Name)
				}
			case *ast.GenDecl:
				for _, s := range d.Specs {
					switch s := s.(type) {
					case *ast.TypeSpec:
						add(&names, seen, s.Name)
					case *ast.ValueSpec:
						for _, n := range s.Names {
							add(&names, seen, n)
						}
					}
				}
			}
		}
	}
	sort.Strings(names)
	return names, all, files, nil
}

func add(names *[]string, seen map[string]bool, id *ast.Ident) {
	if id.IsExported() && !keep(id.Name) && !seen[id.Name] {
		seen[id.Name] = true
		*names = append(*names, id.Name)
	}
}

// rename rewrites src, replacing identifier tokens (not after a '.') found in m.
func rename(src []byte, m map[string]string) []byte {
	fset := token.NewFileSet()
	file := fset.AddFile("", fset.Base(), len(src))
	var s scanner.Scanner
	s.Init(file, src, nil, scanner.ScanComments)
	var out []byte
	last := 0
	prev := token.ILLEGAL
	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		if tok == token.IDENT && prev != token.PERIOD {
			if nn, ok := m[lit]; ok {
				off := file.Offset(pos)
				out = append(out, src[last:off]...)
				out = append(out, nn...)
				last = off + len(lit)
			}
		}
		prev = tok
	}
	return append(out, src[last:]...)
}

func run(dir string, write bool, w *os.File) error {
	names, all, files, err := exported(dir)
	if err != nil {
		return err
	}
	m := map[string]string{}
	for _, n := range names {
		nn := "x" + n
		if all[nn] {
			return fmt.Errorf("collision: %s", nn)
		}
		m[n] = nn
	}
	if !write {
		for _, n := range names {
			fmt.Fprintln(w, n)
		}
		return nil
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		if err := os.WriteFile(f, rename(b, m), 0o644); err != nil {
			return err
		}
	}
	fmt.Fprintf(w, "renamed %d identifiers in %d files\n", len(names), len(files))
	return nil
}

func main() {
	write := false
	dir := "."
	for _, a := range os.Args[1:] {
		if a == "-w" {
			write = true
		} else {
			dir = a
		}
	}
	if err := run(dir, write, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
