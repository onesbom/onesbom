// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package sbom

import "fmt"

type File struct {
	Element
}

func (f *File) SetID(newID string) {
	f.id = newID
}

// linkDocument is an internal function to relate an element to its containing
// document.
func (f *File) linkDocument(doc *Document) error {
	f.document = doc
	if doc == nil {
		return fmt.Errorf("linking document")
	}
	return nil
}
