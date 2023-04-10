// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package sbom

import "fmt"

type Package struct {
	Element
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
