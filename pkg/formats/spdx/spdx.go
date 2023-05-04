// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package spdx

import "strings"

const (
	NOASSERTION = "NOASSERTION"
)

func ParseActorString(s string) (actorType, actorName, actorEmail string) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "Person:") {
		actorType = "person"
		s = strings.TrimPrefix(s, "Person:")
	} else if strings.HasPrefix(s, "Organization:") {
		actorType = "org"
		s = strings.TrimPrefix(s, "Organization:")
	}
	s = strings.TrimSpace(s)
	actorName = s
	if strings.HasSuffix(s, ")") && strings.Contains(s, "(") {
		actorName = strings.TrimSpace(s[0:strings.LastIndex(s, "(")])
		actorEmail = strings.TrimSpace(s[strings.LastIndex(s, "(")+1:])
		actorEmail = strings.TrimSuffix(actorEmail, ")")
	}

	return actorType, actorName, actorEmail
}
