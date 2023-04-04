// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package formats

import "strings"

type Format string

const (
	SPDX23TV   = Format("2.3;text/spdx+text")
	SPDX23JSON = Format("2.3;text/spdx+json")
	SPDX22TV   = Format("2.2;text/spdx+text")
	SPDX22JSON = Format("2.2;text/spdx+json")
)

var List = []Format{SPDX23TV, SPDX23JSON, SPDX22TV, SPDX22JSON}

// Returns the version
func (f *Format) Version() string {
	parts := strings.Split(string(*f), ";")
	if len(parts) > 1 {
		return parts[0]
	}
	return ""
}

// Encoding returns the encoding used by the SBOM format
func (f *Format) Encoding() string {
	parts := strings.Split(string(*f), "+")
	if len(parts) > 1 {
		return parts[1]
	}
	return ""
}

// Type returns the encoding used by the SBOM format
func (f *Format) Type() string {
	if strings.Contains(string(*f), "spdx") {
		return "spdx"
	} else if strings.Contains(string(*f), "cyclonedx") {
		return "cyclonedx"
	}
	return ""
}
