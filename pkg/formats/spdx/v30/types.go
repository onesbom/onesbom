// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package v30

import "time"

type Identifier string

type Class struct {
	Type string     `json:"@type"`
	ID   Identifier `json:"@id"`
}

type Document struct {
	Class
	RootElements []string
	Elements     []interface{}
}

type CreationInfo struct {
	SpecVersion string     `json:"specVersion"`
	DataLicense string     `json:"dataLicense"`
	Created     *time.Time `json:"created"`
	Profile     []string   `json:"profile"`
	CreatedBy   []Identifier
}

type ExternalIdentifier struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
	Comment    string `json:"comment"`
}

type Package struct {
	Class
	PacakgeURL          string                `json:"packageURL,omitempty"`
	DownloadLocation    string                `json:"downlaodLocation,omitempty"`
	Version             string                `json:"packageVersion"`
	HomePage            string                `json:"homePage"`
	SourceInfo          string                `json:"sourceInfo"`
	ContentIdentifier   string                `json:"contentIdentifier"` // xsd:anyURI
	OriginatedBy        *[]Identifier         `json:"originatedBy"`
	ExternalIdentifiers *[]ExternalIdentifier `json:"externalIdentifiers,omitempty"`
	VerifiedUsing       *[]interface{}
}

type File struct {
	ContentIdentifier string `json:"contentIdentifier"` // xsd:anyURI
	Purpose           string `json:"filePurpose"`
	ContentType       string `json:"contentType"`
}

type Hash struct {
	Type      string `json:"@type"`
	Algorithm string `json:"algorithm"`
	HashValue string `json:"hashValue"`
}

type Person struct {
	Class
	Name                string                `json:"name"`
	ExternalIdentifiers *[]ExternalIdentifier `json:"externalIdentifiers,omitempty"`
}
