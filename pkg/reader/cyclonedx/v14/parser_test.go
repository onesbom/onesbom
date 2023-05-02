// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package v14

import (
	"fmt"
	"os"
	"testing"

	"github.com/onesbom/onesbom/pkg/reader/options"
	"github.com/onesbom/onesbom/pkg/sbom"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	sbomFile, err := os.Open("../../testdata/juice-shop-11.1.2.cdx.json")
	require.NoError(t, err)
	defer sbomFile.Close()

	parser := Parser{}
	doc, err := parser.Parse(&options.Options{}, sbomFile)
	require.NoError(t, err)
	require.Len(t, doc.RootElements(), 1)

	p, ok := doc.RootElements()[0].(*sbom.Package)
	require.True(t, ok)

	// The identifiers include the purl, but also all the external
	// identifiers of the root node (issue tracker, website, vcs)
	require.Len(t, p.Identifiers, 4)
	require.Equal(t, "pkg:npm/juice-shop@11.1.2", p.ID())
	require.Len(t, doc.Nodes, 841, fmt.Errorf("number of nodes: %d", len(doc.Nodes)))

	require.Len(t, p.Relationships(), 840)
}
