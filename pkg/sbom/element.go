// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package sbom

// Element is a common ancestor of Package and File that houses
// the common functions among them
type Element struct {
	document *Document
	id       string
	Name     string
}

// ID returns the ID of the element
func (e Element) ID() string {
	return e.id
}
