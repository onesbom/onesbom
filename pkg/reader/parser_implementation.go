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
	spdx23 "github.com/onesbom/onesbom/pkg/reader/spdx/v23"
)

type parserImplementation interface {
	OpenDocumentFile(string) (io.Reader, error)
	DetectFormat(*options.Options, io.Reader) (formats.Format, error)
	GetFormatParser(*options.Options, formats.Format) (FormatParser, error)
}

type defaultParserImplementation struct{}

func (dpi *defaultParserImplementation) OpenDocumentFile(path string) (io.Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening document file %w", err)
	}
	return f, nil
}

func (dpi *defaultParserImplementation) DetectFormat(_ *options.Options, f io.Reader) (formats.Format, error) {
	sniffer := FormatSniffer{}
	format, err := sniffer.SniffReader(f)
	if err != nil {
		return "", fmt.Errorf("detecting format: %w", err)
	}
	return format, nil
}

func (dpi *defaultParserImplementation) GetFormatParser(_ *options.Options, format formats.Format) (FormatParser, error) {
	switch string(format) {
	case "2.3;text/spdx+json":
		return &spdx23.Parser{}, nil
	case "1.4;text/spdx+json":
		return &cdx14.Parser{}, nil
	}

	return nil, fmt.Errorf("no parser registered for %s", format)
}
