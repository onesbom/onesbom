// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package sbom

import (
	"fmt"
)

type Document struct {
	Metadata      interface{}
	Nodes         []Node
	Relationships []Relationship
}

// AddNode adds a node the the document
func (doc *Document) AddNode(n Node) error {
	for _, testNode := range doc.Nodes {
		if testNode.ID() == n.ID() {
			return fmt.Errorf("node %s is already in the document", n.ID())
		}
	}

	if err := n.linkDocument(doc); err != nil {
		return fmt.Errorf("linking node to document")
	}

	doc.Nodes = append(doc.Nodes, n)
	return nil
}
