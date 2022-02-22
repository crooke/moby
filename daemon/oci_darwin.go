package daemon // import "github.com/docker/docker/daemon"

import (
	"github.com/docker/docker/container"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
)

const (
	credentialSpecRegistryLocation = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\Containers\CredentialSpecs`
	credentialSpecFileLocation     = "CredentialSpecs"
)

func (daemon *Daemon) createSpec(c *container.Container) (*specs.Spec, error) {
	return nil, errors.New("TODO: implement createSpec for darwin")
}
