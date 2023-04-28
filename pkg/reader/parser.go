// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package reader

import (
	"fmt"
	"io"

	"github.com/onesbom/onesbom/pkg/reader/options"
	"github.com/onesbom/onesbom/pkg/sbom"
)

var defaultOptions = options.Options{}

type Parser struct {
	impl    parserImplementation
	Options options.Options
}

func New() *Parser {
	return &Parser{
		Options: defaultOptions,
		impl:    &defaultParserImplementation{},
	}
}

// Parser reads a file and returns an sbom.Document
func (p *Parser) ParseFile(path string) (*sbom.Document, error) {
	f, err := p.impl.OpenDocumentFile(path)
	if err != nil {
		return nil, fmt.Errorf("opening SBOM file: %w", err)
	}

	return p.ParseReader(f)
}

// Parser returns a document from a reader
func (p *Parser) ParseReader(f io.Reader) (*sbom.Document, error) {
	format, err := p.impl.DetectFormat(&p.Options, f)
	if err != nil {
		return nil, fmt.Errorf("detecting SBOM format: %w", err)
	}

	formatParser, err := p.impl.GetFormatParser(&p.Options, format)
	if err != nil {
		return nil, fmt.Errorf("getting format parser: %w", err)
	}

	doc, err := formatParser.Parse(&p.Options, f)
	if err != nil {
		return nil, fmt.Errorf("parsing %s document: %w", format, err)
	}

	return doc, err
}
