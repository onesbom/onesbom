// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package sbom

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRelationshipSPDX3(t *testing.T) {
	for _, tc := range []struct {
		sut      RelationshipType
		expected string
	}{
		{RUNTIME_DEPENDENCY_OF, "runtimeDependency"},
		{VARIANT_OF, "variant"},
		{OTHER, "other"},
	} {
		require.Equal(t, tc.expected, tc.sut.SPDX3())
	}
}
