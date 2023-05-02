// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package sbom

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func buildTestNodeList() NodeList {
	nl := NodeList{}
	for i := 0; i < 4; i++ {
		nl = append(nl, &Package{})
	}

	for i := 0; i < 5; i++ {
		nl = append(nl, &File{})
	}

	return nl
}

func TestNodeListPackages(t *testing.T) {
	nl := buildTestNodeList()
	require.Len(t, nl.Packages(), 4)
}

func TestNodeListFiles(t *testing.T) {
	nl := buildTestNodeList()
	require.Len(t, nl.Files(), 5)
}
