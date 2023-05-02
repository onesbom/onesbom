package main

import (
	"fmt"
	"os"

	"github.com/onesbom/onesbom/pkg/reader"
	"github.com/onesbom/onesbom/pkg/sbom"
)

func main() {
	reader := reader.New()
	doc, err := reader.ParseFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing SBOM: %s", err.Error())
		os.Exit(1)
	}

	fmt.Printf("This SBOM describes %d elements\n", len(doc.RootElements()))
	for _, e := range doc.RootElements() {
		if p, ok := e.(*sbom.Package); ok {
			fmt.Printf(" - %s@%s\n", p.Name, p.Version)
		} else if f, ok := e.(*sbom.File); ok {
			fmt.Printf(" - %v\n", f.Name)
		}
	}
	fmt.Printf("It contains %d total elements\n", len(doc.Nodes))
}
