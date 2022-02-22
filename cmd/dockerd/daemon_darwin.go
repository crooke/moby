package main

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/docker/docker/daemon/config"
	"github.com/docker/docker/libcontainerd/supervisor"
	"golang.org/x/sys/unix"
)

func getDefaultDaemonConfigFile() (string, error) {
	return "", nil
}

// setDefaultUmask doesn't do anything on windows
func setDefaultUmask() error {
	return nil
}

func getDaemonConfDir(root string) (string, error) {
	return filepath.Join(root, `\config`), nil
}

// preNotifyReady sends a message to the host when the API is active, but before the daemon is
func preNotifyReady() {
}

// notifyReady sends a message to the host when the server is ready to be used
func notifyReady() {
}

// notifyStopping sends a message to the host when the server is shutting down
func notifyStopping() {
}

// notifyShutdown is called after the daemon shuts down but before the process exits.
func notifyShutdown(err error) {
}

func (cli *DaemonCli) getPlatformContainerdDaemonOpts() ([]supervisor.DaemonOpt, error) {
	return nil, nil
}

// setupConfigReloadTrap configures the SIGHUP signal to reload the configuration.
func (cli *DaemonCli) setupConfigReloadTrap() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, unix.SIGHUP)
	go func() {
		for range c {
			cli.reloadConfig()
		}
	}()
}

// getSwarmRunRoot gets the root directory for swarm to store runtime state
// For example, the control socket
func (cli *DaemonCli) getSwarmRunRoot() string {
	return ""
}

func allocateDaemonPort(addr string) error {
	return nil
}

func newCgroupParent(config *config.Config) string {
	return ""
}

func (cli *DaemonCli) initContainerD(_ context.Context) (func(time.Duration) error, error) {
	return nil, nil
}
