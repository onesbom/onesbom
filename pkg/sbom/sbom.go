// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package sbom

import (
	"errors"
	"fmt"
)

type Document struct {
	Metadata      interface{}
	Nodes         []Node
	Relationships []Relationship
	rootElements  NodeList
}

// AddNode adds a node the the document
func (doc *Document) AddNode(n Node) error {
	if n.ID() == "" {
		return errors.New("node has empty ID string")
	}
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

// AddRelationshipFromIDs adds a new relationship to the document by getting two
// element IDs and a relationship type. The elements named must exist in the node
// list or the call wil return an error
func (doc *Document) AddRelationshipFromIDs(sourceID, relType, destID string) error {
	if sourceID == "" {
		return fmt.Errorf("source ID cannot be an empty string")
	}
	if destID == "" {
		return fmt.Errorf("destination ID cannot be an empty string")
	}
	var sourceElement, destElement *Node
	for i := range doc.Nodes {
		if doc.Nodes[i].ID() == sourceID {
			sourceElement = &doc.Nodes[i]
		}
		if doc.Nodes[i].ID() == destID {
			destElement = &doc.Nodes[i]
		}
	}

	if sourceElement == nil {
		return fmt.Errorf("unable to find source element with ID %s", sourceID)
	}

	if sourceElement == nil {
		return fmt.Errorf("unable to find destination element with ID %s", sourceID)
	}

	return doc.AddRelationship(sourceElement, relType, destElement)
}

// CreateRelationship adds a new relationship to the document
func (doc *Document) AddRelationship(sourceElement *Node, relType string, destElement *Node) error {
	if sourceElement == nil {
		return errors.New("source element is nil")
	}
	if destElement == nil {
		return errors.New("destination element is nil")
	}

	var foundSource, foundDest bool
	for _, n := range doc.Nodes {
		if *sourceElement == n {
			foundSource = true
		}
		if *destElement == n {
			foundDest = true
		}

		if foundDest && foundSource {
			break
		}
	}

	if !foundDest {
		return errors.New("unable to find destination element")
	}

	if !foundSource {
		return errors.New("unable to find source element")
	}

	doc.Relationships = append(doc.Relationships, Relationship{
		Source: sourceElement,
		Target: destElement,
		Type:   RelationshipType(relType),
	})
	return nil
}

// AddRootElementFromID adds an element to the top level by
// specifying its ID
func (doc *Document) AddRootElementFromID(id string) error {
	node := doc.GetElementByID(id)
	if node == nil {
		return fmt.Errorf("element %s not found", id)
	}
	return doc.AddRootElement(node)
}

// AddRootElement adds an element to the top level list of elements
func (doc *Document) AddRootElement(node *Node) error {
	if node == nil {
		return fmt.Errorf("new root node is empty")
	}

	for i := range doc.rootElements {
		if *doc.rootElements[i] == *node {
			// Warn("node is already a root level node")
			return nil
		}
	}

	doc.rootElements = append(doc.rootElements, node)
	return nil
}

// RootElements returns the list of pointers to the top level elements of the
// document.
func (doc *Document) RootElements() NodeList {
	return doc.rootElements
}

// GetElementByID gets an ID and returns a pointer to the element
func (doc *Document) GetElementByID(id string) *Node {
	for i := range doc.Nodes {
		if doc.Nodes[i].ID() == id {
			return &doc.Nodes[i]
		}
	}
	return nil
}
