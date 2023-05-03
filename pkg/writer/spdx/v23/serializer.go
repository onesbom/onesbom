// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package v23

import (
	//nolint:gosec // sha1 is required by the SPDX 2 spec
	sha1 "crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/onesbom/onesbom/pkg/formats"
	spdx23 "github.com/onesbom/onesbom/pkg/formats/spdx/v23"
	"github.com/onesbom/onesbom/pkg/sbom"
)

type Serializer struct{}

func (s *Serializer) SerializeToNeutral(bom *sbom.Document) (formats.Document, error) {
	return s.Serialize(bom)
}

func (s *Serializer) RenderNeutral(neutralDoc formats.Document, w io.Writer) error {
	doc, ok := neutralDoc.(*spdx23.Document)
	if !ok {
		return fmt.Errorf("document is not an SPDX 2.3 document")
	}

	if err := json.NewEncoder(w).Encode(doc); err != nil {
		return fmt.Errorf("encoding document: %w", err)
	}

	return nil
}

func (s *Serializer) Serialize(bom *sbom.Document) (*spdx23.Document, error) {
	doc := spdx23.Document{}
	doc.CreationInfo = spdx23.CreationInfo{}

	doc.Files = []spdx23.File{}
	doc.Packages = []spdx23.Package{}

	for _, f := range bom.Nodes.Files() {
		newFile := spdx23.File{
			ID:            f.ID(), // TODO Ensure ID uniqueness?
			Name:          f.Name,
			CopyrightText: f.Copyright,
			// NoticeText:        f., ??
			LicenseConcluded: string(f.LicenseConcluded),
			// Description:      f.Description, // DLW: CycloneDX has descriptions, SPDX has not
			FileTypes: f.Types,
			// LicenseInfoInFile: []string{},
		}

		if len(f.Hashes) > 0 {
			newFile.Checksums = []spdx23.Checksum{}
			for algo, val := range f.Hashes {
				newFile.Checksums = append(newFile.Checksums, spdx23.Checksum{
					Algorithm: algo,
					Value:     val,
				})
			}
		}

		doc.Files = append(doc.Files, newFile)
	}

	for _, p := range bom.Nodes.Packages() {
		newPackage := spdx23.Package{
			FilesAnalyzed:        false,
			ID:                   p.ID(),
			Name:                 p.Name,
			Version:              p.Version,
			LicenseDeclared:      string(p.License),
			LicenseConcluded:     string(p.LicenseConcluded),
			Description:          p.Description,
			DownloadLocation:     p.DownloadLocation,
			SourceInfo:           p.SourceInfo,
			CopyrightText:        p.Copyright,
			PrimaryPurpose:       p.PrimaryPurpose,
			Filename:             p.FileName,
			HomePage:             p.URL,
			Summary:              p.Summary,
			Comment:              p.Comment,
			Attribution:          &[]string{},
			LicenseInfoFromFiles: []string{},
			// ExternalRefs:     []spdx23.ExternalRef{},
			// VerificationCode: &spdx23.PackageVerificationCode{},
		}

		if p.Originator != nil {
			newPackage.Originator = p.Originator.ToSPDX2()
			if newPackage.Originator == "" {
				// DLW: No email or name
			}
			// DLW: More other fields in person will result in data loss
		}

		if p.Supplier != nil {
			newPackage.Supplier = p.Supplier.ToSPDX2()
			if newPackage.Supplier == "" {
				// DLW: No email or name
			}
			// DLW: More other fields in person will result in data loss
		}

		if len(p.Hashes) > 0 {
			newPackage.Checksums = []spdx23.Checksum{}
			for algo, val := range p.Hashes {
				newPackage.Checksums = append(newPackage.Checksums, spdx23.Checksum{
					Algorithm: algo,
					Value:     val,
				})
			}
		}

		// Handle the package's files
		sha1s := []string{}
		allSha1s := true
		for _, r := range p.Relationships() {
			for _, f := range r.Target.Files() {
				if newPackage.HasFiles == nil {
					newPackage.HasFiles = []string{}
				}
				newPackage.HasFiles = append(newPackage.HasFiles, f.ID())

				// Record the SHA1s
				if _, ok := f.Hashes["SHA1"]; ok {
					sha1s = append(sha1s, f.Hashes["SHA1"])
				} else {
					allSha1s = false
				}
			}
		}

		// Compute packaegg verification code
		if allSha1s {
			sort.Strings(sha1s)
			//nolint:gosec // sha1 is required by the SPDX 2 spec
			h := sha1.New()
			if _, err := io.WriteString(h, strings.Join(sha1s, "")); err != nil {
				return nil, fmt.Errorf("computing hash of package verification code: %w", err)
			}
			newPackage.VerificationCode = &spdx23.PackageVerificationCode{
				Value:         fmt.Sprintf("%x", h.Sum(nil)),
				ExcludedFiles: []string{},
			}
			newPackage.FilesAnalyzed = true
		}

		doc.Packages = append(doc.Packages, newPackage)
	}

	// Finally all relationships
	for _, r := range bom.Relationships {
		for _, el := range *r.Target {
			newRel := spdx23.Relationship{
				Element: r.Source.ID(),
				Type:    string(r.Type),
				Related: el.ID(),
			}
			doc.Relationships = append(doc.Relationships, newRel)
		}
	}
	return &doc, nil
}

// Render writes the bom SBOM as a JSON strean to the w Writer
func (s *Serializer) Render(rawDoc formats.Document, w io.Writer) error {
	var doc *spdx23.Document
	switch rawDoc.(type) {
	case *sbom.Document:
		var err error
		bom := rawDoc.(*sbom.Document)
		doc, err = s.Serialize(bom)
		if err != nil {
			return fmt.Errorf("serializing document to SPDX 2.3: %w", err)
		}
	case *spdx23.Document:
		doc = rawDoc.(*spdx23.Document)
	default:
		return errors.New("unable to render document, typeis unknown")
	}

	if err := json.NewEncoder(w).Encode(doc); err != nil {
		return fmt.Errorf("encoding document: %w", err)
	}

	return nil
}
