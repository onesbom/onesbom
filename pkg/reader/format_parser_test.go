// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package reader

import (
	"os"
	"testing"

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
}
