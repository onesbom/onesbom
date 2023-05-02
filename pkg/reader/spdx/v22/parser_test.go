// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package v22

import (
	"os"
	"testing"

	"github.com/onesbom/onesbom/pkg/license"
	"github.com/onesbom/onesbom/pkg/reader/options"
	"github.com/onesbom/onesbom/pkg/sbom"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	sbomFile, err := os.Open("../../testdata/linux-x64-manifest.spdx.json")
	require.NoError(t, err)
	defer sbomFile.Close()

	parser := Parser{}
	doc, err := parser.Parse(&options.Options{}, sbomFile)
	require.NoError(t, err)
	require.Len(t, doc.Nodes, 89, "unexpected node length (%d)", len(doc.Nodes))

	require.Len(t, doc.RootElements(), 1)
	require.Len(t, doc.RootElements()[0].Relationships(), 87)
	p, ok := doc.RootElements()[0].(*sbom.Package)
	require.True(t, ok)
	require.Equal(t, p.Version, "19452207")
	require.Equal(t, p.Name, "SBOMTool")

	// Test licenses
	require.Equal(t, license.Expression("NOASSERTION"), p.LicenseConcluded)
	require.Equal(t, license.Expression("NOASSERTION"), p.License)
}
