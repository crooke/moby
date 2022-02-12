package system

import "os"

// EnsureRemoveAll is an alias to os.RemoveAll on Darwin
var EnsureRemoveAll = os.RemoveAll
