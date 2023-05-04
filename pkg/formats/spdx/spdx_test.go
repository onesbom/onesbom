// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package spdx

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseActorString(t *testing.T) {
	for _, tc := range []struct {
		sut        string
		actorName  string
		actorType  string
		actorEmail string
	}{
		{"Organization: Peanuts", "Peanuts", "org", ""},
		{"Person: Charlie Brown", "Charlie Brown", "person", ""},
		{"Person: Woodstock Bird (woodstock@peanuts.com)", "Woodstock Bird", "person", "woodstock@peanuts.com"},
		{"Organization: Peanuts Corporation (corp@peanuts.com)", "Peanuts Corporation", "org", "corp@peanuts.com"},
	} {
		y, n, e := ParseActorString(tc.sut)
		require.Equal(t, tc.actorType, y)
		require.Equal(t, tc.actorName, n)
		require.Equal(t, tc.actorEmail, e)
	}

}
