// Command tracegen generates traced wrapper types for Go interfaces.
//
// Usage:
//
//	Same package:
//	  //go:generate go run github.com/0xsequence/nitrocontrol/cmd/tracegen -interface=Target
//
//	Cross-package:
//	  //go:generate go run github.com/0xsequence/nitrocontrol/cmd/tracegen -pkg=example.com/myapp/data -interface=Target
//
// For each method with a context.Context first parameter and an error last return,
// tracegen generates tracing instrumentation using the tracing.Trace function.
// Methods without context.Context are delegated directly to the embedded interface.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/format"
	"go/types"
	"log"
	"os"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

func main() {
	ifaceName := flag.String("interface", "", "interface name to wrap (required)")
	srcPkg := flag.String("pkg", "", "import path of the package containing the interface (default: current directory)")
	output := flag.String("output", "", "output file path (default: <interface>_traced.go)")
	typeName := flag.String("type", "", "generated type name (default: Traced<Interface>)")
	label := flag.String("label", "", "trace span label prefix (default: same as -type); spans become \"<label>.MethodName\"")
	tracingPkg := flag.String("tracing-pkg", "github.com/0xsequence/nitrocontrol/tracing", "import path for the tracing package")
	flag.Parse()

	if *ifaceName == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Determine which packages to load.
	// We always need "." for the output package name.
	// If -pkg is set, we also need the source package.
	toLoad := []string{"."}
	crossPkg := *srcPkg != ""
	if crossPkg {
		toLoad = append(toLoad, *srcPkg)
	}

	cfg := &packages.Config{
		Mode: packages.NeedTypes | packages.NeedName,
	}
	pkgs, err := packages.Load(cfg, toLoad...)
	if err != nil {
		log.Fatalf("loading packages: %v", err)
	}

	// Identify packages from the loaded results.
	var localPkg, ifacePkg *packages.Package
	for _, p := range pkgs {
		if len(p.Errors) > 0 {
			for _, e := range p.Errors {
				log.Println(e)
			}
			os.Exit(1)
		}
		if crossPkg && p.PkgPath == *srcPkg {
			ifacePkg = p
		} else {
			// The package that isn't the explicitly requested source is our local output package.
			localPkg = p
		}
	}
	if !crossPkg {
		ifacePkg = localPkg
	}
	if localPkg == nil {
		log.Fatal("could not determine output package")
	}
	if ifacePkg == nil {
		log.Fatalf("could not load source package %q", *srcPkg)
	}

	// Find the interface in the source package.
	obj := ifacePkg.Types.Scope().Lookup(*ifaceName)
	if obj == nil {
		log.Fatalf("interface %q not found in package %s", *ifaceName, ifacePkg.PkgPath)
	}
	iface, ok := obj.Type().Underlying().(*types.Interface)
	if !ok {
		log.Fatalf("%q is not an interface", *ifaceName)
	}

	genTypeName := *typeName
	if genTypeName == "" {
		genTypeName = "Traced" + *ifaceName
	}

	outputFile := *output
	if outputFile == "" {
		outputFile = strings.ToLower(*ifaceName) + "_traced.go"
	}

	// Track required imports with collision-safe aliases.
	// imports: path -> alias used in generated code.
	// aliasUsed: alias -> path that claimed it (to detect collisions).
	imports := map[string]string{}
	aliasUsed := map[string]string{}

	// addImport registers a package and returns the alias to use in code.
	addImport := func(path, name string) string {
		// Already registered — return its alias.
		if alias, ok := imports[path]; ok {
			return alias
		}
		// Try the plain package name first.
		alias := name
		if existing, taken := aliasUsed[alias]; taken && existing != path {
			// Collision — derive a unique alias from the path.
			// e.g., "github.com/foo/bar/request" → "barrequest"
			parts := strings.Split(path, "/")
			if len(parts) >= 2 {
				alias = parts[len(parts)-2] + name
			}
			// If still colliding, append a number.
			base := alias
			for i := 2; aliasUsed[alias] != "" && aliasUsed[alias] != path; i++ {
				alias = fmt.Sprintf("%s%d", base, i)
			}
		}
		imports[path] = alias
		aliasUsed[alias] = path
		return alias
	}

	// Need the tracing package unless we're generating into it.
	tracingPrefix := "tracing."
	if localPkg.PkgPath == *tracingPkg {
		tracingPrefix = ""
	} else {
		addImport(*tracingPkg, "tracing")
	}

	// qualifier renders types relative to the output package.
	qualifier := func(p *types.Package) string {
		if p == localPkg.Types {
			return ""
		}
		return addImport(p.Path(), p.Name())
	}

	// Determine how to reference the interface in the generated code.
	embeddedName := *ifaceName
	if crossPkg {
		prefix := qualifier(ifacePkg.Types)
		embeddedName = prefix + "." + *ifaceName
	}

	// Determine the label prefix for trace spans.
	spanLabel := *ifaceName
	if *label != "" {
		spanLabel = *label
	}

	// Generate each method.
	var methods []string
	needsContext := false

	for i := 0; i < iface.NumMethods(); i++ {
		m := iface.Method(i)
		sig := m.Type().(*types.Signature)
		// Only generate wrappers for methods that take context.
		// Others are delegated automatically via the embedded interface.
		if sig.Params().Len() == 0 || !isContextType(sig.Params().At(0).Type()) {
			continue
		}
		code := genMethod(genTypeName, *ifaceName, spanLabel, m.Name(), sig, qualifier, tracingPrefix)
		methods = append(methods, code)
		needsContext = true
	}

	if needsContext {
		imports["context"] = "context"
	}

	// Build the source file.
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "// Code generated by tracegen. DO NOT EDIT.\n\n")
	fmt.Fprintf(&buf, "package %s\n\n", localPkg.Name)

	// Separate std library imports from third-party.
	var stdImports, extImports []string
	for p := range imports {
		if !strings.Contains(p, ".") {
			stdImports = append(stdImports, p)
		} else {
			extImports = append(extImports, p)
		}
	}
	sort.Strings(stdImports)
	sort.Strings(extImports)

	// writeImport emits an import line, adding an alias when it differs from the package name.
	writeImport := func(path string) string {
		alias := imports[path]
		// The default package name is the last element of the import path.
		parts := strings.Split(path, "/")
		defaultName := parts[len(parts)-1]
		if alias != defaultName {
			return fmt.Sprintf("\t%s %q\n", alias, path)
		}
		return fmt.Sprintf("\t%q\n", path)
	}

	fmt.Fprintf(&buf, "import (\n")
	for _, p := range stdImports {
		fmt.Fprintf(&buf, "%s", writeImport(p))
	}
	if len(stdImports) > 0 && len(extImports) > 0 {
		fmt.Fprintf(&buf, "\n")
	}
	for _, p := range extImports {
		fmt.Fprintf(&buf, "%s", writeImport(p))
	}
	fmt.Fprintf(&buf, ")\n\n")

	// Type declaration with embedded interface.
	fmt.Fprintf(&buf, "// %s wraps %s with tracing instrumentation.\n", genTypeName, embeddedName)
	fmt.Fprintf(&buf, "type %s struct {\n\t%s\n}\n\n", genTypeName, embeddedName)

	// Constructor.
	fmt.Fprintf(&buf, "// New%s returns a new %s that wraps the given %s.\n", genTypeName, genTypeName, embeddedName)
	fmt.Fprintf(&buf, "func New%s(inner %s) *%s {\n", genTypeName, embeddedName, genTypeName)
	fmt.Fprintf(&buf, "\treturn &%s{%s: inner}\n", genTypeName, *ifaceName)
	fmt.Fprintf(&buf, "}\n\n")

	// Methods.
	for _, m := range methods {
		fmt.Fprintf(&buf, "%s\n\n", m)
	}

	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		// Print raw source for debugging.
		fmt.Fprintln(os.Stderr, buf.String())
		log.Fatalf("formatting generated code: %v", err)
	}

	if err := os.WriteFile(outputFile, formatted, 0o644); err != nil {
		log.Fatalf("writing %s: %v", outputFile, err)
	}
	fmt.Printf("tracegen: wrote %s\n", outputFile)
}

// genMethod generates the source for a single traced wrapper method.
// It assumes the method has context.Context as its first parameter.
func genMethod(typeName, ifaceName, spanLabel, methodName string, sig *types.Signature, qualifier types.Qualifier, tracingPrefix string) string {
	params := sig.Params()
	results := sig.Results()
	variadic := sig.Variadic()

	hasErr := results.Len() > 0 && isErrorType(results.At(results.Len()-1).Type())

	// Generate parameter names.
	paramNames := make([]string, params.Len())
	for i := 0; i < params.Len(); i++ {
		p := params.At(i)
		if name := p.Name(); name != "" && name != "_" {
			paramNames[i] = name
		} else if i == 0 {
			paramNames[i] = "ctx"
		} else {
			paramNames[i] = fmt.Sprintf("a%d", i)
		}
	}

	// Build signature parameter list.
	sigParams := make([]string, params.Len())
	for i := 0; i < params.Len(); i++ {
		typeStr := types.TypeString(params.At(i).Type(), qualifier)
		if variadic && i == params.Len()-1 {
			// Unwrap []T → ...T
			sl := params.At(i).Type().(*types.Slice)
			typeStr = "..." + types.TypeString(sl.Elem(), qualifier)
		}
		sigParams[i] = paramNames[i] + " " + typeStr
	}

	// Build return list.
	sigResults := make([]string, results.Len())
	for i := 0; i < results.Len(); i++ {
		typeStr := types.TypeString(results.At(i).Type(), qualifier)
		if hasErr && i == results.Len()-1 {
			sigResults[i] = "err " + typeStr
		} else if hasErr {
			sigResults[i] = "_ " + typeStr
		} else {
			sigResults[i] = typeStr
		}
	}

	// Build return type string. Named returns always need parentheses.
	var returnStr string
	hasNamedReturns := hasErr
	switch {
	case len(sigResults) == 0:
		returnStr = ""
	case len(sigResults) == 1 && !hasNamedReturns:
		returnStr = sigResults[0]
	default:
		returnStr = "(" + strings.Join(sigResults, ", ") + ")"
	}

	// Build call arguments.
	callArgs := make([]string, params.Len())
	for i := 0; i < params.Len(); i++ {
		callArgs[i] = paramNames[i]
		if variadic && i == params.Len()-1 {
			callArgs[i] += "..."
		}
	}

	var buf bytes.Buffer
	ctxName := paramNames[0]

	// Method signature.
	if returnStr != "" {
		fmt.Fprintf(&buf, "func (t *%s) %s(%s) %s {\n", typeName, methodName, strings.Join(sigParams, ", "), returnStr)
	} else {
		fmt.Fprintf(&buf, "func (t *%s) %s(%s) {\n", typeName, methodName, strings.Join(sigParams, ", "))
	}

	if hasErr {
		// Tracing with error recording.
		fmt.Fprintf(&buf, "\t%s, span := %sTrace(%s, %q)\n", ctxName, tracingPrefix, ctxName, spanLabel+"."+methodName)
		fmt.Fprintf(&buf, "\tdefer func() {\n")
		fmt.Fprintf(&buf, "\t\tspan.RecordError(err)\n")
		fmt.Fprintf(&buf, "\t\tspan.End()\n")
		fmt.Fprintf(&buf, "\t}()\n")
	} else {
		// Tracing without error recording.
		fmt.Fprintf(&buf, "\t%s, span := %sTrace(%s, %q)\n", ctxName, tracingPrefix, ctxName, spanLabel+"."+methodName)
		fmt.Fprintf(&buf, "\tdefer span.End()\n")
	}

	// Delegation call.
	call := fmt.Sprintf("t.%s.%s(%s)", ifaceName, methodName, strings.Join(callArgs, ", "))
	if results.Len() > 0 {
		fmt.Fprintf(&buf, "\treturn %s\n", call)
	} else {
		fmt.Fprintf(&buf, "\t%s\n", call)
	}

	fmt.Fprintf(&buf, "}")

	return buf.String()
}

func isContextType(t types.Type) bool {
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj.Pkg() != nil && obj.Pkg().Path() == "context" && obj.Name() == "Context"
}

func isErrorType(t types.Type) bool {
	return t.String() == "error"
}
