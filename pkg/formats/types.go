// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package formats

import "strings"

type Format string

const (
	JSON       = "json"
	TEXT       = "text"
	SPDX23TV   = Format("text/spdx+text;version=2.3")
	SPDX23JSON = Format("text/spdx+json;version=2.3")
	SPDX22TV   = Format("text/spdx+text;version=2.2")
	SPDX22JSON = Format("text/spdx+json;version=2.2")
	CDX14JSON  = Format("application/vnd.cyclonedx+json;version=1.4")
	CDX15JSON  = Format("application/vnd.cyclonedx+json;version=1.5")
)

type Document interface{}

var List = []Format{SPDX23TV, SPDX23JSON, SPDX22TV, SPDX22JSON, CDX14JSON, CDX15JSON}

// Version returns the version of the format
func (f *Format) Version() string {
	parts := strings.Split(string(*f), ";version=")
	if len(parts) > 1 {
		return parts[1]
	}
	return ""
}

// Encoding returns the encoding used by the SBOM format
func (f Format) Encoding() string {
	// Trim the version first
	switch {
	case strings.Contains(string(f), JSON):
		return JSON
	case strings.Contains(string(f), TEXT):
		return TEXT
	default:
		return ""
	}
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
