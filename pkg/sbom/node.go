// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package sbom

type Node interface {
	ID() string
	linkDocument(*Document) error
	Relationships() []Relationship
}
