// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package writer

import (
	"fmt"
	"io"

	"github.com/onesbom/onesbom/pkg/formats"
	"github.com/onesbom/onesbom/pkg/sbom"
	"github.com/onesbom/onesbom/pkg/writer/options"
)

type Serializer interface {
	Render(formats.Document, io.Writer) error
	SerializeToNeutral(*sbom.Document) (formats.Document, error)
}

type Option func(*Writer)

func New() *Writer {
	return &Writer{
		Options: options.Default,
	}
}

type Writer struct {
	impl    writerImplementation
	Options options.Options
}

func (w *Writer) Write(bom *sbom.Document, path string) error {
	s, err := w.impl.GetFormatSerializer(w.Options.Format)
	if err != nil {
		return fmt.Errorf("getting serializer: %w", err)
	}

	rawDoc, err := w.impl.SerializeSBOM(s, bom)
	if err != nil {
		return fmt.Errorf("serializing sbom: %w", err)
	}

	f, err := w.impl.OpenFile(path)
	if err != nil {
		return err
	}

	defer f.Close()

	if err := w.impl.WriteSBOM(s, rawDoc, f); err != nil {
		return fmt.Errorf("writing sbom: %w", err)
	}

	return nil
}
