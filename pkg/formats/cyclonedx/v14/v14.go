// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package v14

import "time"

type Document struct {
	Version      int      `json:"version"`
	Format       string   `json:"bomFormat"`
	SpecVersion  string   `json:"specVersion"`
	SerialNumber string   `json:"serialNumber"`
	Metadata     Metadata `json:"metadata"`
	// TODO: Pedigree
	Components   []Component  `json:"components"`
	Dependencies []Dependency `json:"dependencies"`
}

type Metadata struct {
	Timestamp time.Time `json:"timestamp"`
	Tools     []Tool    `json:"tools"`
	Component Component `json:"component"`
}

type Tool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

type Component struct {
	Ref                string              `json:"bom-ref"`
	Type               string              `json:"type"`
	Name               string              `json:"name"`
	Version            string              `json:"version"`
	Purl               string              `json:"purl,omitempty"`
	Description        string              `json:"description"`
	Hashes             []Hash              `json:"hashes"`
	Components         []Component         `json:"components"`
	Licenses           []License           `json:"licenses,omitempty"`
	ExternalReferences []ExternalReference `json:"externalReferences"`
}

type ExternalReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type License struct {
	License struct {
		ID string `json:"id"`
	} `json:"license"`
}

type Hash struct {
	Algorithm string `json:"alg"`
	Content   string `json:"content"`
}
