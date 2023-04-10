// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package reader

import (
	"io"

	"github.com/onesbom/onesbom/pkg/sbom"
)

type FormatParser interface {
	Parse(*Options, io.Reader) (*sbom.Document, error)
}

func GetFormatParser(formatString string) (FormatParser, error) {
	return nil, nil
}

type SPDX23 struct{}

func (spdx23 *SPDX23) Parse(*Options, io.Reader) (*sbom.Document, error) {
	return nil, nil
}