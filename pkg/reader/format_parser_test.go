// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package reader

import (
	"os"
	"testing"

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
}
