package security

import (
	"github.com/containerd/containerd/oci"
)

// WithInsecureSpec sets spec with All capability.
func WithInsecureSpec() oci.SpecOpts {
	return nil
}