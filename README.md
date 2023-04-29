# OneSBOM: The Universal SBOM Library 

OneSBOM is a go library designed to read and write Software Bill of Materials.

It parses documents in any format into a losless internal representation. OneSBOM 
handles the SBOM in memory by maintaining a relationship tree and by maintaining
the SBOM elements linked to each other for easy traversal. SBOMs can be written
to any of the supported formats using a planned degradation path when data loss
is expected.

OneSBOM handles the _SBOM_ features of the formats (software and licensing), other
features like build, pedigree, security advisories are no in scope but can be
handled by embedding OneSBOM in other projects.

The library is designed to be as "leaf" as possible. This means that it tries to
keep its dependencies as minimal as possible to archieve it's purpose: reading,
writing and parsing the formats. This design consideration incluldes the required
types, OneSBOM has its own types to ingest the SPDX and CycloneDX schemas which
can be imported cheaply.

## Usage

Here is a minimal example of a program that parses an SBOM and outputs some
information about the SBOM:

```golang

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
		if p, ok := (*e).(*sbom.Package); ok {
			fmt.Printf(" - %s@%s\n", p.Name, p.Version)
		} else if f, ok := (*e).(*sbom.File); ok {
			fmt.Printf(" - %v\n", f.Name)
		}
	}
	fmt.Printf("It contains %d total elements\n", len(doc.Nodes))
}

```

The code to this example and others is 
[available in the examples directory](examples/).

## Supported Formats

The initial OneSBOM release supports reading and writing in the following formats
and encodings:

* SPDX 2.2 (JSON | Tag-Value)
* SPDX 2.3 (JSON | Tag-Value)
* SPDX 3.0 (JSON)
* CycloneDX 1.4 (JSON)

