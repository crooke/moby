package idtools // import "github.com/docker/docker/pkg/idtools"

import (
	"os"

	"github.com/docker/docker/pkg/system"
	"github.com/opencontainers/runc/libcontainer/user"
)

// This is currently a wrapper around MkdirAll, however, since currently
// permissions aren't set through this path, the identity isn't utilized.
// Ownership is handled elsewhere, but in the future could be support here
// too.
func mkdirAs(path string, mode os.FileMode, owner Identity, mkAll, chownExisting bool) error {
	if err := system.MkdirAll(path, mode); err != nil {
		return err
	}
	return nil
}

// CanAccess takes a valid (existing) directory and a uid, gid pair and determines
// if that uid, gid pair has access (execute bit) to the directory
// Windows does not require/support this function, so always return true
func CanAccess(path string, identity Identity) bool {
	return true
}

// LookupGroup uses traditional local system files lookup (from libcontainer/user) on a group name,
// followed by a call to `getent` for supporting host configured non-files passwd and group dbs
func LookupGroup(name string) (user.Group, error) {
	// first try a local system files lookup using existing capabilities
	group, err := user.LookupGroup(name)
	if err != nil {
		return user.Group{}, err
	}
	return group, nil
}
