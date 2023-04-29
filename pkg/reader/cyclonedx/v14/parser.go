// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package v14

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/onesbom/onesbom/pkg/formats/cyclonedx"
	cdx14 "github.com/onesbom/onesbom/pkg/formats/cyclonedx/v14"
	"github.com/onesbom/onesbom/pkg/license"
	"github.com/onesbom/onesbom/pkg/reader/options"
	"github.com/onesbom/onesbom/pkg/sbom"
)

type Parser struct{}

func (cdx *Parser) Parse(opts *options.Options, f io.Reader) (*sbom.Document, error) {
	cdxDoc := &cdx14.Document{}

	dc := json.NewDecoder(f)
	if err := dc.Decode(cdxDoc); err != nil {
		return nil, fmt.Errorf("decoding document: %w", err)
	}

	bom := &sbom.Document{}
	root, err := componentToPackage(&cdxDoc.Metadata.Component)
	if err != nil {
		return nil, fmt.Errorf("converting root component to package: %w", err)
	}
	if err := bom.AddNode(&root); err != nil {
		return nil, fmt.Errorf("adding root node from cyclone doc: %w", err)
	}
	if err := bom.AddRootElementFromID(root.ID()); err != nil {
		return nil, fmt.Errorf("adding root element: %w", err)
	}

	// Add all the components
	for i := range cdxDoc.Components {
		if cdxDoc.Components[i].Type == cyclonedx.ComponentTypeFile {
			// File
		} else {
			p, err := componentToPackage(&cdxDoc.Components[i])
			if err != nil {
				return nil, fmt.Errorf("converting component to package: %w", err)
			}
			if err := bom.AddNode(&p); err != nil {
				return nil, fmt.Errorf("adding node from cdx component: %w", err)
			}
		}
	}

	// Add the relationships. Keep track to add those located because
	// if not, we add them as direct (first level) deps
	tracked := map[string]struct{}{}
	for _, dep := range cdxDoc.Dependencies {
		if dep.DependsOn == nil || len(dep.DependsOn) == 0 {
			continue
		}
		for _, target := range dep.DependsOn {
			// Consider soft error here from options
			if err := bom.AddRelationshipFromIDs(dep.Ref, "DEPENDS_ON", target); err != nil {
				return nil, fmt.Errorf("adding relationship: %w", err)
			}
			tracked[target] = struct{}{}
		}
	}

	// CycloneDX components are related by default, so we add all that are not
	// properly located to the first leve:
	if err := addComponents(bom, cdxDoc.Components, root.ID(), tracked); err != nil {
		return nil, fmt.Errorf("adding components: %w", err)
	}

	return bom, nil
}

func addComponents(bom *sbom.Document, comps []cdx14.Component, parentID string, tracked map[string]struct{}) error {
	for i := range comps {
		if _, ok := tracked[comps[i].Ref]; ok {
			continue
		}
		if err := bom.AddRelationshipFromIDs(parentID, "CONTAINS", comps[i].Ref); err != nil {
			return fmt.Errorf("adding default relationship to component: %w", err)
		}

		if comps[i].Components != nil {
			if err := addComponents(bom, comps[i].Components, comps[i].Ref, tracked); err != nil {
				return err
			}
		}
	}
	return nil
}

// componentToPackage converts a CycloneDX component to a file
func componentToPackage(component *cdx14.Component) (sbom.Package, error) {
	p := sbom.Package{}

	if component.Type == cyclonedx.ComponentTypeFile {
		return p, errors.New("component is a file, it should be convertyed to a file")
	}

	p.SetID(component.Ref)
	p.Name = component.Name
	p.Version = component.Version
	p.Identifiers = append(p.Identifiers, sbom.Identifier{
		Type:  "purl",
		Value: component.Purl,
	})
	p.Description = component.Description
	p.Hashes = map[string]string{}
	for _, h := range component.Hashes {
		algo, err := cdxAlgorithmToString(h.Algorithm)
		if err != nil {
			return p, fmt.Errorf("adding hash %s: %w", h, err)
		}
		p.Hashes[algo] = h.Content
	}
	licString := ""
	for _, l := range component.Licenses {
		if licString != "" {
			licString += " AND "
		}
		licString += l.License.ID
	}
	p.License = license.Expression(licString)
	for _, extid := range component.ExternalReferences {
		p.Identifiers = append(p.Identifiers, sbom.Identifier{
			Type:  extid.Type,
			Value: extid.URL,
		})
	}
	return p, nil
}

func cdxAlgorithmToString(algo string) (string, error) {
	switch {
	case strings.Contains(algo, "SHA-"):
		return "SHA" + strings.TrimPrefix(algo, "SHA-"), nil
	case strings.Contains(algo, "SHA3-"):
		return "SHA3" + strings.TrimPrefix(algo, "SHA3-"), nil
	default:
		if _, ok := map[string]bool{
			"MD5": true, "BLAKE2b-256": true, "BLAKE2b-384": true, "BLAKE2b-512": true, "BLAKE3": true,
		}[algo]; ok {
			return algo, nil
		}
		return "", errors.New("unknown algorithm")
	}
}
