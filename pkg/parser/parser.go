// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package parser

type Options struct {
}

var defaultOptions = Options{}

type Parser struct {
	impl    parserImplementation
	Options Options
}

func New() *Parser {
	return &Parser{
		Options: defaultOptions,
		impl:    &defaultParserImplementation{},
	}
}
