// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package reader

import (
	"fmt"
	"os"
	"testing"

	"github.com/onesbom/onesbom/pkg/license"
	"github.com/onesbom/onesbom/pkg/sbom"
	"github.com/stretchr/testify/require"
)

func TestSPDX23Parse(t *testing.T) {
	sbomFile, err := os.Open("testdata/nginx.spdx.json")
	require.NoError(t, err)
	defer sbomFile.Close()

	parser := SPDX23{}
	doc, err := parser.Parse(&Options{}, sbomFile)
	require.NoError(t, err)
	require.Len(t, doc.Nodes, 1185, "unexpected node length (%d)", len(doc.Nodes))

	require.Len(t, doc.RootElements(), 1)
	require.Len(t, (*doc.RootElements()[0]).Relationships(), 8)
	p, ok := (*doc.RootElements()[0]).(*sbom.Package)
	require.True(t, ok)
	require.Len(t, p.Identifiers, 1)
	require.Equal(t, "pkg:oci/nginx@sha256:2ab30d6ac53580a6db8b657abf0f68d75360ff5cc1670a85acb5bd85ba1b19c0?mediaType=application%2Fvnd.docker.distribution.manifest.list.v2+json\u0026repository_url=index.docker.io%2Flibrary", p.Identifiers[0].Value)

	// Test licenses
	require.Equal(t, license.Expression("Apache-2.0"), p.LicenseConcluded)
	require.Equal(t, license.Expression("Apache-2.0"), p.License)
}

func TestCycloneDX14Parse(t *testing.T) {
	sbomFile, err := os.Open("testdata/juice-shop-11.1.2.cdx.json")
	require.NoError(t, err)
	defer sbomFile.Close()

	parser := CDX14{}
	doc, err := parser.Parse(&Options{}, sbomFile)
	require.NoError(t, err)
	require.Len(t, doc.RootElements(), 1)

	p, ok := (*doc.RootElements()[0]).(*sbom.Package)
	require.True(t, ok)

	// The identifiers include the purl, but also all the external
	// identifiers of the root node (issue tracker, website, vcs)
	require.Len(t, p.Identifiers, 4)
	require.Equal(t, "pkg:npm/juice-shop@11.1.2", p.ID())
	require.Len(t, doc.Nodes, 841, fmt.Errorf("number of nodes: %d", len(doc.Nodes)))

	require.Len(t, p.Relationships(), 840)
}
