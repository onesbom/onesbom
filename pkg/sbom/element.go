// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package sbom

import "fmt"

// Element is a common ancestor of Package and File that houses
// the common functions among them
type Element struct {
	document *Document
	id       string
}

func (e *Element) ID() string {
	return e.id
}

func (e *Package) linkDocument(doc *Document) error {
	e.document = doc
	if doc == nil {
		return fmt.Errorf("formatting document")
	}
	return nil
}
