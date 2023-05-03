// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package options

type Options struct {
	Lossless bool // Fail if writing an SBOM results in a lossy conversion
	Format   string
}

var Default = Options{
	Lossless: false,
	Format:   "text/spdx+json;version=2.3",
}
