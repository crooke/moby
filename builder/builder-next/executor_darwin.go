package buildkit

import (
	"context"
	"errors"

	"github.com/docker/docker/daemon/config"
	"github.com/docker/docker/pkg/idtools"
	"github.com/docker/libnetwork"
	"github.com/moby/buildkit/executor"
	"github.com/moby/buildkit/executor/oci"
)

func newExecutor(_, _ string, _ libnetwork.NetworkController, _ *oci.DNSConfig, _ bool, _ *idtools.IdentityMapping, _ string) (executor.Executor, error) {
	return &dwinExecutor{}, nil
}

type dwinExecutor struct {
}

func (w *dwinExecutor) Run(ctx context.Context, id string, root executor.Mount, mounts []executor.Mount, process executor.ProcessInfo, started chan<- struct{}) (err error) {
	return errors.New("buildkit executor not implemented for darwin")
}

func (w *dwinExecutor) Exec(ctx context.Context, id string, process executor.ProcessInfo) error {
	return errors.New("buildkit executor not implemented for darwin")
}

func getDNSConfig(config.DNSConfig) *oci.DNSConfig {
	return nil
}
