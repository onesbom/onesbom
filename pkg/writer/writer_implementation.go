// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package writer

import (
	"fmt"
	"io"
	"os"

	"github.com/onesbom/onesbom/pkg/formats"
	"github.com/onesbom/onesbom/pkg/sbom"
	v23 "github.com/onesbom/onesbom/pkg/writer/spdx/v23"
)

type writerImplementation interface {
	GetFormatSerializer(string) (Serializer, error)
	SerializeSBOM(Serializer, *sbom.Document) (formats.Document, error)
	OpenFile(string) (io.WriteCloser, error)
	WriteSBOM(Serializer, interface{}, io.Writer) error
}

type defaultWriterImplementation struct{}

func (di *defaultWriterImplementation) GetFormatSerializer(format formats.Format) (Serializer, error) {
	switch format {
	case formats.SPDX23JSON:
		return &v23.Serializer{}, nil
	default:
		return nil, fmt.Errorf("no serializer defined for %s", format)
	}
}

func (di *defaultWriterImplementation) SerializeSBOM(s Serializer, bom *sbom.Document) (formats.Document, error) {
	return s.SerializeToNeutral(bom)
}

func (di *defaultWriterImplementation) OpenFile(path string) (io.WriteCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening sbom file to write: %w", err)
	}
	return f, nil
}
