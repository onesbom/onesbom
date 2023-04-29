// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package sbom

import (
	"fmt"
	"time"

	"github.com/onesbom/onesbom/pkg/license"
)

type Package struct {
	Element
	SourceInfo       string    // any relevant background information or additional comments about the origin
	PrimaryPurpose   string    // APPLICATION | FRAMEWORK | LIBRARY | CONTAINER | OPERATING-SYSTEM | DEVICE | FIRMWARE | SOURCE | ARCHIVE | FILE | INSTALL | OTHER |
	Version          string    // Version string
	FileName         string    // Package filename when there is one
	Summary          string    // Short package description
	Description      string    // Package description (full)
	Attribution      *[]string // One or more attribution texts
	DownloadLocation string    // Location to download the package
	URL              string    // URL to get more info about the package
	Copyright        string    // Copyright text blob
	Comment          string    // Any comment
	Supplier         *Person
	Originator       *Person
	ReleaseDate      *time.Time
	BuiltDate        *time.Time
	ValidUntilDate   *time.Time
	License          license.Expression
	Identifiers      []Identifier
}

// Sets the ID of the package
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
