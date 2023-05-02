// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package sbom

import "strings"

type RelationshipType string

const (
	AMENDS                      RelationshipType = "AMENDS"                      //	Is to be used when (current) SPDXRef-DOCUMENT amends the SPDX information in SPDXRef-B.
	ANCESTOR_OF                 RelationshipType = "ANCESTOR_OF"                 //	Is to be used when SPDXRef-A is an ancestor (same lineage but pre-dates) SPDXRef-B.
	BUILD_DEPENDENCY_OF         RelationshipType = "BUILD_DEPENDENCY_OF"         //	Is to be used when SPDXRef-A is a build dependency of SPDXRef-B.
	BUILD_TOOL_OF               RelationshipType = "BUILD_TOOL_OF"               //	Is to be used when SPDXRef-A is used to build SPDXRef-B.
	CONTAINED_BY                RelationshipType = "CONTAINED_BY"                //	Is to be used when SPDXRef-A is contained by SPDXRef-B.
	CONTAINS                    RelationshipType = "CONTAINS"                    //	Is to be used when SPDXRef-A contains SPDXRef-B.
	COPY_OF                     RelationshipType = "COPY_OF"                     //	Is to be used when SPDXRef-A is an exact copy of SPDXRef-B.
	DATA_FILE_OF                RelationshipType = "DATA_FILE_OF"                //	Is to be used when SPDXRef-A is a data file used in SPDXRef-B.
	DEPENDENCY_MANIFEST_OF      RelationshipType = "DEPENDENCY_MANIFEST_OF"      //	Is to be used when SPDXRef-A is a manifest file that lists a set of dependencies for SPDXRef-B.
	DEPENDENCY_OF               RelationshipType = "DEPENDENCY_OF"               //	Is to be used when SPDXRef-A is dependency of SPDXRef-B.
	DEPENDS_ON                  RelationshipType = "DEPENDS_ON"                  //	Is to be used when SPDXRef-A depends on SPDXRef-B.
	DESCENDANT_OF               RelationshipType = "DESCENDANT_OF"               //	Is to be used when SPDXRef-A is a descendant of (same lineage but postdates) SPDXRef-B.
	DESCRIBED_BY                RelationshipType = "DESCRIBED_BY"                //	Is to be used when SPDXRef-A is described by SPDXREF-Document.
	DESCRIBES                   RelationshipType = "DESCRIBES"                   //	Is to be used when SPDXRef-DOCUMENT describes SPDXRef-A.
	DEV_DEPENDENCY_OF           RelationshipType = "DEV_DEPENDENCY_OF"           //	Is to be used when SPDXRef-A is a development dependency of SPDXRef-B.
	DEV_TOOL_OF                 RelationshipType = "DEV_TOOL_OF"                 //	Is to be used when SPDXRef-A is used as a development tool for SPDXRef-B.
	DISTRIBUTION_ARTIFACT       RelationshipType = "DISTRIBUTION_ARTIFACT"       //	Is to be used when distributing SPDXRef-A requires that SPDXRef-B also be distributed.
	DOCUMENTATION_OF            RelationshipType = "DOCUMENTATION_OF"            //	Is to be used when SPDXRef-A provides documentation of SPDXRef-B.
	DYNAMIC_LINK                RelationshipType = "DYNAMIC_LINK"                //	Is to be used when SPDXRef-A dynamically links to SPDXRef-B.
	EXAMPLE_OF                  RelationshipType = "EXAMPLE_OF"                  //	Is to be used when SPDXRef-A is an example of SPDXRef-B.
	EXPANDED_FROM_ARCHIVE       RelationshipType = "EXPANDED_FROM_ARCHIVE"       //	Is to be used when SPDXRef-A is expanded from the archive SPDXRef-B.
	FILE_ADDED                  RelationshipType = "FILE_ADDED"                  //	Is to be used when SPDXRef-A is a file that was added to SPDXRef-B.
	FILE_DELETED                RelationshipType = "FILE_DELETED"                //	Is to be used when SPDXRef-A is a file that was deleted from SPDXRef-B.
	FILE_MODIFIED               RelationshipType = "FILE_MODIFIED"               //	Is to be used when SPDXRef-A is a file that was modified from SPDXRef-B.
	GENERATED_FROM              RelationshipType = "GENERATED_FROM"              //	Is to be used when SPDXRef-A was generated from SPDXRef-B.
	GENERATES                   RelationshipType = "GENERATES"                   //	Is to be used when SPDXRef-A generates SPDXRef-B.
	HAS_PREREQUISITE            RelationshipType = "HAS_PREREQUISITE"            //	Is to be used when SPDXRef-A has as a prerequisite SPDXRef-B
	METAFILE_OF                 RelationshipType = "METAFILE_OF"                 //	Is to be used when SPDXRef-A is a metafile of SPDXRef-B.
	OPTIONAL_COMPONENT_OF       RelationshipType = "OPTIONAL_COMPONENT_OF"       //	Is to be used when SPDXRef-A is an optional component of SPDXRef-B.
	OPTIONAL_DEPENDENCY_OF      RelationshipType = "OPTIONAL_DEPENDENCY_OF"      //	Is to be used when SPDXRef-A is an optional dependency of SPDXRef-B.
	OTHER                       RelationshipType = "OTHER"                       //	Is to be used for a relationship which has not been defined in the formal SPDX specification.
	PACKAGE_OF                  RelationshipType = "PACKAGE_OF"                  //	Is to be used when SPDXRef-A is used as a package as part of SPDXRef-B.
	PATCH_APPLIED               RelationshipType = "PATCH_APPLIED"               //	Is to be used when SPDXRef-A is a patch file that has been applied to SPDXRef-B.
	PATCH_FOR                   RelationshipType = "PATCH_FOR"                   //	Is to be used when SPDXRef-A is a patch file for (to be applied to) SPDXRef-B.
	PREREQUISITE_FOR            RelationshipType = "PREREQUISITE_FOR"            //	Is to be used when SPDXRef-A is a prerequisite for SPDXRef-B.
	PROVIDED_DEPENDENCY_OF      RelationshipType = "PROVIDED_DEPENDENCY_OF"      //	Is to be used when SPDXRef-A is a to be provided dependency of SPDXRef-B.
	REQUIREMENT_DESCRIPTION_FOR RelationshipType = "REQUIREMENT_DESCRIPTION_FOR" //	Is to be used when SPDXRef-A describes, illustrates, or specifies a requirement statement for SPDXRef-B.
	RUNTIME_DEPENDENCY_OF       RelationshipType = "RUNTIME_DEPENDENCY_OF"       //	Is to be used when SPDXRef-A is a dependency required for the execution of SPDXRef-B.
	SPECIFICATION_FOR           RelationshipType = "SPECIFICATION_FOR"           //	Is to be used when SPDXRef-A describes, illustrates, or defines a design specification for SPDXRef-B
	STATIC_LINK                 RelationshipType = "STATIC_LINK"                 //	Is to be used when SPDXRef-A statically links to SPDXRef-B.
	TEST_CASE_OF                RelationshipType = "TEST_CASE_OF"                //	Is to be used when SPDXRef-A is a test case used in testing SPDXRef-B.
	TEST_DEPENDENCY_OF          RelationshipType = "TEST_DEPENDENCY_OF"          //	Is to be used when SPDXRef-A is a test dependency of SPDXRef-B.
	TEST_OF                     RelationshipType = "TEST_OF"                     //	Is to be used when SPDXRef-A is used for testing SPDXRef-B.
	TEST_TOOL_OF                RelationshipType = "TEST_TOOL_OF"                //	Is to be used when SPDXRef-A is used as a test tool for SPDXRef-B.
	VARIANT_OF                  RelationshipType = "VARIANT_OF"                  //	Is to be used when SPDXRef-A is a variant of (same lineage but not clear which came first) SPDXRef-B.
)

func (rt *RelationshipType) SPDX3() string {
	rel := strings.TrimSuffix(string(*rt), "_OF")
	parts := strings.Split(rel, "_")
	r := ""
	for i, s := range parts {
		if i == 0 {
			r += strings.ToLower(s)
		} else {
			r += strings.ToUpper(string(s[0])) + strings.ToLower(s[1:])
		}
	}
	return r
}

type Relationship struct {
	Source Node
	Target Node
	Type   RelationshipType
}

func (r *Relationship) NodeList() NodeList {
	return NodeList{r.Source, r.Target}
}
