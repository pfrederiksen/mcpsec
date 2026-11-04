// Package bundled exposes the default YAML rules compiled into the mcpsec binary.
package bundled

import "embed"

//go:embed *.yaml
var Files embed.FS
