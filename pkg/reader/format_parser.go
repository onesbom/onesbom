// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package reader

import (
	"io"

	"github.com/onesbom/onesbom/pkg/reader/options"
	"github.com/onesbom/onesbom/pkg/sbom"
)

type FormatParser interface {
	Parse(*options.Options, io.Reader) (*sbom.Document, error)
}

func GetFormatParser(formatString string) (FormatParser, error) {
	return nil, nil
}
