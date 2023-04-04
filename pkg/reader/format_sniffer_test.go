// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package reader

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSniffReader(t *testing.T) {
	fs := FormatSniffer{}
	for _, tc := range []struct {
		filename   string
		mustError  bool
		version    string
		formatType string
		encoding   string
	}{
		{
			filename:   "testdata/linux-x64-manifest.spdx.json",
			mustError:  false,
			version:    "2.2",
			formatType: "spdx",
			encoding:   "json",
		},
		{
			filename:   "testdata/nginx.spdx",
			mustError:  false,
			version:    "2.2",
			formatType: "spdx",
			encoding:   "text",
		},
		{
			filename:   "testdata/nginx.spdx.json",
			mustError:  false,
			version:    "2.3",
			formatType: "spdx",
			encoding:   "json",
		},
		{
			filename:   "testdata/pause.spdx",
			mustError:  false,
			version:    "2.3",
			formatType: "spdx",
			encoding:   "text",
		},
		{
			filename:  "testdata/syft.json",
			mustError: true,
		},
	} {
		f, err := os.Open(tc.filename)
		require.NoError(t, err, tc.filename)

		sbomFormat, err := fs.SniffReader(f)
		if tc.mustError {
			require.Error(t, err)
			continue
		}

		require.NoError(t, err, tc.filename)
		require.NotEmpty(t, sbomFormat)
		require.Equal(t, tc.encoding, sbomFormat.Encoding())
		require.Equal(t, tc.formatType, sbomFormat.Type())
		require.Equal(t, tc.version, sbomFormat.Version())
	}
}

func TestSniffFile(t *testing.T) {
	fs := FormatSniffer{}
	for _, tc := range []struct {
		filename  string
		mustError bool
	}{
		{
			filename:  "testdata/linux-x64-manifest.spdx.json",
			mustError: false,
		},
		{
			filename:  "testdata/blardiboy",
			mustError: true,
		},
	} {
		_, err := fs.SniffFile(tc.filename)
		if tc.mustError {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
	}
}
