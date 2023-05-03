// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package sbom

import "fmt"

type Person struct {
	Name        string
	Email       string
	URL         string
	IsOrg       bool
	Phone       string             // CDX
	Contacts    []Person           // CDX
	Identifiers []PersonIdentifier // SPDX
}

type PersonIdentifier struct {
	ID      string
	Type    string
	Comment string
}

// ToSPDX returns a rendering of the Person object as a SPDX 2.x string
func (p *Person) ToSPDX2() string {
	if p.Email == "" && p.Name == "" {
		return ""
	}
	s := "Person"
	if p.IsOrg {
		s = "Organization"
	}
	s = fmt.Sprintf("%s: %s", s, p.Name)

	if p.Email != "" {
		s = fmt.Sprintf("%s (%s)", s, p.Email)
	}
	return s
}
