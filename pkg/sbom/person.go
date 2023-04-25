// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package sbom

type Person struct {
	Name        string
	Email       string
	URL         string
	Phone       string             // CDX
	Contacts    []Person           // CDX
	Identifiers []PersonIdentifier // SPDX
}

type PersonIdentifier struct {
	ID      string
	Type    string
	Comment string
}
