// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package sbom

type NodeList []Node

// Files returns all nodes in the nodelist which are Files.
func (nl *NodeList) Files() []*File {
	fileList := []*File{}
	for _, n := range *nl {
		if f, ok := n.(*File); ok {
			fileList = append(fileList, f)
		}
	}
	return fileList
}

// Pacakges returns all nodes in the nodelist which are Packages.
func (nl *NodeList) Packages() []*Package {
	packageList := []*Package{}
	for _, n := range *nl {
		if p, ok := n.(*Package); ok {
			packageList = append(packageList, p)
		}
	}
	return packageList
}
