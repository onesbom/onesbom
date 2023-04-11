// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package sbom

import (
	"fmt"

	"github.com/onesbom/onesbom/pkg/license"
)

type Package struct {
	Element
	SourceInfo  string
	License     license.Expression
	Identifiers []Identifier
}

func (p *Package) SetID(newID string) {
	p.id = newID
}

// linkDocument is an internal function to relate an element to its containing
// document.
func (p *Package) linkDocument(doc *Document) error {
	p.document = doc
	if doc == nil {
		return fmt.Errorf("linking document")
	}
	return nil
}

type Identifier struct {
	Type  string
	Value string
}
