// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package cyclonedx

const (
	ComponentTypeApplication = "application"
	ComponentTypeFrameWork   = "framework"
	ComponentTypeLibrary     = "library"
	ComponentTypeContainer   = "container"
	ComponentTypeOS          = "operating-system"
	ComponentTypeDevice      = "device"
	ComponentTypeFirmware    = "firmware"
	ComponentTypeFile        = "file"
)

// ComponentTypes lists the valid component types
var ComponentTypes = []string{
	ComponentTypeApplication, ComponentTypeFrameWork, ComponentTypeLibrary,
	ComponentTypeContainer, ComponentTypeOS, ComponentTypeDevice,
	ComponentTypeFirmware, ComponentTypeFile,
}
