package engine

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// networkCalls are the standard-library entry points that open a
// connection or resolve a name on their own. Any of them in new code is a
// way to reach the network without passing the scope check.
var networkCalls = map[string][]string{
	"net":        {"Dial", "DialTimeout", "DialTCP", "DialUDP", "DialIP", "DialUnix", "Dialer", "LookupHost", "LookupIP", "LookupAddr", "LookupCNAME", "Resolver", "DefaultResolver"},
	"crypto/tls": {"Dial", "DialWithDialer", "Dialer"},
	"net/http":   {"Client", "DefaultClient", "Transport", "DefaultTransport", "Get", "Head", "Post", "PostForm"},
}

// allowedNetworkCalls is every non-test file allowed to use networkCalls,
// with how many uses it may have. A new use anywhere, even in an allowed
// file, fails the test until someone decides whether it is passive or
// must go through Scope.Dial.
var allowedNetworkCalls = map[string]int{
	// The gate itself.
	"internal/engine/scope.go": 1, // net.Dialer in NewScope
	// Passive proxying: the browser chose the target, Sluice only forwards
	// (SPEC.md: passive proxying is not scope-limited).
	"internal/engine/forward.go": 1, // net.Dialer: plain HTTP upstream
	"internal/engine/mitm.go":    1, // net.Dialer: CONNECT tunnel upstream
	// Dev load generator: sends through the local proxy to testorigin only.
	"internal/loadgen/loadgen.go": 3, // http.Transport, http.Client (built, and a parameter type)
}

// TestOnlyScopeDialsActively keeps Scope.Dial "the one way active senders
// reach the network". Go cannot stop a package from calling net.Dial, so
// this scans the module's source instead: every dial, resolve or HTTP
// client outside the allow-list fails here, at review time, rather than as
// an out-of-scope send in someone's bug-bounty report.
func TestOnlyScopeDialsActively(t *testing.T) {
	root := moduleRoot(t)
	got := map[string]int{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "frontend", "node_modules", "build", "vendor", "testdata", ".git":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		for _, use := range networkUses(t, path) {
			got[rel]++
			if _, ok := allowedNetworkCalls[rel]; !ok {
				t.Errorf("%s: %s opens a connection or resolves a name outside Scope.Dial; active sends must use Scope.Dial", rel, use)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for file, want := range allowedNetworkCalls {
		if got[file] != want {
			t.Errorf("%s: %d network calls, allow-list says %d; a new one must be reviewed (passive, or through Scope.Dial?) and the count updated", file, got[file], want)
		}
	}
}

// networkUses returns "pkg.Name @ line" for every selector in path that
// names one of networkCalls, using the file's own import names.
func networkUses(t *testing.T, path string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	local := map[string]string{} // local name -> import path
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		if _, watched := networkCalls[p]; !watched {
			continue
		}
		name := p[strings.LastIndex(p, "/")+1:]
		if imp.Name != nil {
			name = imp.Name.Name
		}
		local[name] = p
	}
	var uses []string
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		p, ok := local[id.Name]
		if !ok {
			return true
		}
		for _, name := range networkCalls[p] {
			if sel.Sel.Name == name {
				uses = append(uses, id.Name+"."+name+" @ line "+strconv.Itoa(fset.Position(sel.Pos()).Line))
			}
		}
		return true
	})
	return uses
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

// The scanner itself must see a dial, including through a renamed import;
// otherwise the guard above passes by seeing nothing.
func TestNetworkUsesFindsDials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.go")
	src := `package x

import (
	"crypto/tls"
	stdnet "net"
)

func f() {
	_, _ = stdnet.Dial("tcp", "evil.example:80")
	_, _ = tls.Dial("tcp", "evil.example:443", nil)
	var d stdnet.Dialer
	_ = d
}
`
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := networkUses(t, path); len(got) != 3 {
		t.Fatalf("found %q, want 3 uses", got)
	}
}
