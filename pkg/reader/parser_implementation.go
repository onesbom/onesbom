// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package reader

import (
	"fmt"
	"io"
	"os"

	"github.com/onesbom/onesbom/pkg/formats"
	cdx14 "github.com/onesbom/onesbom/pkg/reader/cyclonedx/v14"
	"github.com/onesbom/onesbom/pkg/reader/options"
	spdx22 "github.com/onesbom/onesbom/pkg/reader/spdx/v22"
	spdx23 "github.com/onesbom/onesbom/pkg/reader/spdx/v23"
)

type parserImplementation interface {
	OpenDocumentFile(string) (*os.File, error)
	DetectFormat(*options.Options, io.ReadSeeker) (formats.Format, error)
	GetFormatParser(*options.Options, formats.Format) (FormatParser, error)
}

type defaultParserImplementation struct{}

func (dpi *defaultParserImplementation) OpenDocumentFile(path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening document file %w", err)
	}
	return f, nil
}

func (dpi *defaultParserImplementation) DetectFormat(_ *options.Options, f io.ReadSeeker) (formats.Format, error) {
	sniffer := FormatSniffer{}
	format, err := sniffer.SniffReader(f)
	if err != nil {
		return "", fmt.Errorf("detecting format: %w", err)
	}
	return format, nil
}

func (dpi *defaultParserImplementation) GetFormatParser(_ *options.Options, format formats.Format) (FormatParser, error) {
	switch string(format) {
	case "text/spdx+json;version=2.3":
		return &spdx23.Parser{}, nil
	case "text/spdx+json;version=2.2":
		return &spdx22.Parser{}, nil
	case "text/spdx+json;version=1.4":
		return &cdx14.Parser{}, nil
	}

	return nil, fmt.Errorf("no parser registered for %s", format)
}
