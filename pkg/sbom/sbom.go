// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package sbom

type Document struct {
	Metadata interface{}
	Nodes    []Node
}

type Node interface{}

type Package struct{}

type File struct{}

type RelationshipType string

type Relationship struct {
	Source *Node
	Target *Node
	Type   RelationshipType
}
