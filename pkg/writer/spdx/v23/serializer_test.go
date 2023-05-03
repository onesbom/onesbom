// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package v23

import (
	"testing"

	"github.com/onesbom/onesbom/pkg/reader"
	"github.com/stretchr/testify/require"
)

func TestSerialize(t *testing.T) {
	s := Serializer{}
	r := reader.New()
	doc, err := r.ParseFile("../../../reader/testdata/juice-shop-11.1.2.cdx.json")
	require.NoError(t, err)
	require.NotNil(t, doc)

	spdxDoc, err := s.Serialize(doc)
	require.NoError(t, err)
	require.NotNil(t, spdxDoc)
	require.Equal(t, len(doc.Nodes.Packages()), len(spdxDoc.Packages))
	require.Equal(t, len(doc.Nodes.Files()), len(spdxDoc.Files))
}
