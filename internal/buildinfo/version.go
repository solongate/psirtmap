// SPDX-License-Identifier: Apache-2.0
// Copyright (c) PSIRTMap contributors

// Package buildinfo defines release metadata shared by the CLI and network
// clients.
package buildinfo

const (
	// Version is the semantic version reported by the PSIRTMap binary.
	Version = "0.1.0"

	// UserAgent identifies this PSIRTMap release to vulnerability data sources.
	UserAgent = "psirtmap/" + Version
)
