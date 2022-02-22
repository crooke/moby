package daemon // import "github.com/docker/docker/daemon"

import (
	"context"
	"fmt"
	"math"
	"net"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/docker/docker/api/types"
	containertypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/container"
	"github.com/docker/docker/daemon/config"
	"github.com/docker/docker/pkg/containerfs"
	"github.com/docker/docker/pkg/idtools"
	"github.com/docker/docker/pkg/sysinfo"
	"github.com/docker/docker/runconfig"
	"github.com/docker/libnetwork"
	nwconfig "github.com/docker/libnetwork/config"
	winlibnetwork "github.com/docker/libnetwork/drivers/windows"
	"github.com/docker/libnetwork/netlabel"
	"github.com/docker/libnetwork/options"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	isWindows = false
	// platformSupported    = true
	darwinMinCPUShares  = 1
	darwinMaxCPUShares  = 10000
	darwinMinCPUPercent = 1
	darwinMaxCPUPercent = 100
)

// Windows containers are much larger than Linux containers and each of them
// have > 20 system processes which why we use much smaller parallelism value.
func adjustParallelLimit(n int, limit int) int {
	return int(math.Max(1, math.Floor(float64(runtime.NumCPU())*.8)))
}

// Windows has no concept of an execution state directory. So use config.Root here.
func getPluginExecRoot(root string) string {
	return filepath.Join(root, "plugins")
}

func (daemon *Daemon) parseSecurityOpt(container *container.Container, hostConfig *containertypes.HostConfig) error {
	return parseSecurityOpt(container, hostConfig)
}

func parseSecurityOpt(container *container.Container, config *containertypes.HostConfig) error {
	return nil
}

func setupInitLayer(idMapping *idtools.IdentityMapping) func(containerfs.ContainerFS) error {
	return nil
}

func checkKernel() error {
	return nil
}

func (daemon *Daemon) getCgroupDriver() string {
	return ""
}

// adaptContainerSettings is called during container creation to modify any
// settings necessary in the HostConfig structure.
func (daemon *Daemon) adaptContainerSettings(hostConfig *containertypes.HostConfig, adjustCPUShares bool) error {
	if hostConfig == nil {
		return nil
	}

	return nil
}

// verifyPlatformContainerResources performs platform-specific validation of the container's resource-configuration
func verifyPlatformContainerResources(resources *containertypes.Resources, isHyperv bool) (warnings []string, err error) {
	fixMemorySwappiness(resources)
	if !isHyperv {
		// The processor resource controls are mutually exclusive on
		// Windows Server Containers, the order of precedence is
		// CPUCount first, then CPUShares, and CPUPercent last.
		if resources.CPUCount > 0 {
			if resources.CPUShares > 0 {
				warnings = append(warnings, "Conflicting options: CPU count takes priority over CPU shares on Windows Server Containers. CPU shares discarded")
				resources.CPUShares = 0
			}
			if resources.CPUPercent > 0 {
				warnings = append(warnings, "Conflicting options: CPU count takes priority over CPU percent on Windows Server Containers. CPU percent discarded")
				resources.CPUPercent = 0
			}
		} else if resources.CPUShares > 0 {
			if resources.CPUPercent > 0 {
				warnings = append(warnings, "Conflicting options: CPU shares takes priority over CPU percent on Windows Server Containers. CPU percent discarded")
				resources.CPUPercent = 0
			}
		}
	}

	if resources.CPUShares < 0 || resources.CPUShares > darwinMaxCPUShares {
		return warnings, fmt.Errorf("range of CPUShares is from %d to %d", darwinMinCPUShares, darwinMaxCPUShares)
	}
	if resources.CPUPercent < 0 || resources.CPUPercent > darwinMaxCPUPercent {
		return warnings, fmt.Errorf("range of CPUPercent is from %d to %d", darwinMinCPUPercent, darwinMaxCPUPercent)
	}
	if resources.CPUCount < 0 {
		return warnings, fmt.Errorf("invalid CPUCount: CPUCount cannot be negative")
	}

	if resources.NanoCPUs > 0 && resources.CPUPercent > 0 {
		return warnings, fmt.Errorf("conflicting options: Nano CPUs and CPU Percent cannot both be set")
	}
	if resources.NanoCPUs > 0 && resources.CPUShares > 0 {
		return warnings, fmt.Errorf("conflicting options: Nano CPUs and CPU Shares cannot both be set")
	}
	// The precision we could get is 0.01, because on Windows we have to convert to CPUPercent.
	// We don't set the lower limit here and it is up to the underlying platform (e.g., Windows) to return an error.
	if resources.NanoCPUs < 0 || resources.NanoCPUs > int64(sysinfo.NumCPU())*1e9 {
		return warnings, fmt.Errorf("range of CPUs is from 0.01 to %d.00, as there are only %d CPUs available", sysinfo.NumCPU(), sysinfo.NumCPU())
	}

	if len(resources.BlkioDeviceReadBps) > 0 {
		return warnings, fmt.Errorf("invalid option: Windows does not support BlkioDeviceReadBps")
	}
	if len(resources.BlkioDeviceReadIOps) > 0 {
		return warnings, fmt.Errorf("invalid option: Windows does not support BlkioDeviceReadIOps")
	}
	if len(resources.BlkioDeviceWriteBps) > 0 {
		return warnings, fmt.Errorf("invalid option: Windows does not support BlkioDeviceWriteBps")
	}
	if len(resources.BlkioDeviceWriteIOps) > 0 {
		return warnings, fmt.Errorf("invalid option: Windows does not support BlkioDeviceWriteIOps")
	}
	if resources.BlkioWeight > 0 {
		return warnings, fmt.Errorf("invalid option: Windows does not support BlkioWeight")
	}
	if len(resources.BlkioWeightDevice) > 0 {
		return warnings, fmt.Errorf("invalid option: Windows does not support BlkioWeightDevice")
	}
	if resources.CgroupParent != "" {
		return warnings, fmt.Errorf("invalid option: Windows does not support CgroupParent")
	}
	if resources.CPUPeriod != 0 {
		return warnings, fmt.Errorf("invalid option: Windows does not support CPUPeriod")
	}
	if resources.CpusetCpus != "" {
		return warnings, fmt.Errorf("invalid option: Windows does not support CpusetCpus")
	}
	if resources.CpusetMems != "" {
		return warnings, fmt.Errorf("invalid option: Windows does not support CpusetMems")
	}
	if resources.KernelMemory != 0 {
		return warnings, fmt.Errorf("invalid option: Windows does not support KernelMemory")
	}
	if resources.MemoryReservation != 0 {
		return warnings, fmt.Errorf("invalid option: Windows does not support MemoryReservation")
	}
	if resources.MemorySwap != 0 {
		return warnings, fmt.Errorf("invalid option: Windows does not support MemorySwap")
	}
	if resources.MemorySwappiness != nil {
		return warnings, fmt.Errorf("invalid option: Windows does not support MemorySwappiness")
	}
	if resources.OomKillDisable != nil && *resources.OomKillDisable {
		return warnings, fmt.Errorf("invalid option: Windows does not support OomKillDisable")
	}
	if resources.PidsLimit != nil && *resources.PidsLimit != 0 {
		return warnings, fmt.Errorf("invalid option: Windows does not support PidsLimit")
	}
	if len(resources.Ulimits) != 0 {
		return warnings, fmt.Errorf("invalid option: Windows does not support Ulimits")
	}
	return warnings, nil
}

// verifyPlatformContainerSettings performs platform-specific validation of the
// hostconfig and config structures.
func verifyPlatformContainerSettings(daemon *Daemon, hostConfig *containertypes.HostConfig, update bool) (warnings []string, err error) {
	if hostConfig == nil {
		return nil, nil
	}
	return warnings, fmt.Errorf("Darwin verifyPlatformContainerSettings not implemented")
}

// verifyDaemonSettings performs validation of daemon config struct
func verifyDaemonSettings(config *config.Config) error {
	return nil
}

// checkSystem validates platform-specific requirements
func checkSystem() error {
	return nil
}

func ensureServicesInstalled(services []string) error {
	return nil
}

// configureKernelSecuritySupport configures and validate security support for the kernel
func configureKernelSecuritySupport(config *config.Config, driverName string) error {
	return nil
}

// configureMaxThreads sets the Go runtime max threads threshold
func configureMaxThreads(config *config.Config) error {
	return nil
}

func (daemon *Daemon) initNetworkController(config *config.Config, activeSandboxes map[string]interface{}) (libnetwork.NetworkController, error) {
	netOptions, err := daemon.networkOptions(config, daemon.PluginStore, activeSandboxes)
	if err != nil {
		return nil, err
	}

	controller, err := libnetwork.New(netOptions...)
	if err != nil {
		return nil, fmt.Errorf("error obtaining controller instance: %v", err)
	}

	if len(activeSandboxes) > 0 {
		logrus.Info("There are old running containers, the network config will not take affect")
		return controller, nil
	}

	// Initialize default network on "null"
	if n, _ := controller.NetworkByName("none"); n == nil {
		if _, err := controller.NewNetwork("null", "none", "", libnetwork.NetworkOptionPersist(true)); err != nil {
			return nil, fmt.Errorf("Error creating default \"null\" network: %v", err)
		}
	}

	// Initialize default network on "host"
	if n, _ := controller.NetworkByName("host"); n == nil {
		if _, err := controller.NewNetwork("host", "host", "", libnetwork.NetworkOptionPersist(true)); err != nil {
			return nil, fmt.Errorf("Error creating default \"host\" network: %v", err)
		}
	}

	// Clear stale bridge network
	if n, err := controller.NetworkByName("bridge"); err == nil {
		if err = n.Delete(); err != nil {
			return nil, fmt.Errorf("could not delete the default bridge network: %v", err)
		}
		if len(config.NetworkConfig.DefaultAddressPools.Value()) > 0 && !daemon.configStore.LiveRestoreEnabled {
			removeDefaultBridgeInterface()
		}
	}

	if !config.DisableBridge {
		// Initialize default driver "bridge"
		if err := initBridgeDriver(controller, config); err != nil {
			return nil, err
		}
	} else {
		removeDefaultBridgeInterface()
	}

	// Set HostGatewayIP to the default bridge's IP  if it is empty
	if daemon.configStore.HostGatewayIP == nil && controller != nil {
		if n, err := controller.NetworkByName("bridge"); err == nil {
			v4Info, v6Info := n.Info().IpamInfo()
			var gateway net.IP
			if len(v4Info) > 0 {
				gateway = v4Info[0].Gateway.IP
			} else if len(v6Info) > 0 {
				gateway = v6Info[0].Gateway.IP
			}
			daemon.configStore.HostGatewayIP = gateway
		}
	}
	return controller, nil

}

func initBridgeDriver(controller libnetwork.NetworkController, config *config.Config) error {
	if _, err := controller.NetworkByName(runconfig.DefaultDaemonNetworkMode().NetworkName()); err == nil {
		return nil
	}

	netOption := map[string]string{
		winlibnetwork.NetworkName: runconfig.DefaultDaemonNetworkMode().NetworkName(),
	}

	var ipamOption libnetwork.NetworkOption
	var subnetPrefix string

	if config.BridgeConfig.FixedCIDR != "" {
		subnetPrefix = config.BridgeConfig.FixedCIDR
	}

	if subnetPrefix != "" {
		ipamV4Conf := libnetwork.IpamConf{PreferredPool: subnetPrefix}
		v4Conf := []*libnetwork.IpamConf{&ipamV4Conf}
		v6Conf := []*libnetwork.IpamConf{}
		ipamOption = libnetwork.NetworkOptionIpam("default", "", v4Conf, v6Conf, nil)
	}

	_, err := controller.NewNetwork(string(runconfig.DefaultDaemonNetworkMode()), runconfig.DefaultDaemonNetworkMode().NetworkName(), "",
		libnetwork.NetworkOptionGeneric(options.Generic{
			netlabel.GenericData: netOption,
		}),
		ipamOption,
	)

	if err != nil {
		return fmt.Errorf("Error creating default network: %v", err)
	}

	return nil
}

// registerLinks sets up links between containers and writes the
// configuration out for persistence. As of Windows TP4, links are not supported.
func (daemon *Daemon) registerLinks(container *container.Container, hostConfig *containertypes.HostConfig) error {
	return nil
}

func (daemon *Daemon) cleanupMountsByID(in string) error {
	return nil
}

func (daemon *Daemon) cleanupMounts() error {
	return nil
}

func recursiveUnmount(_ string) error {
	return nil
}

func setupRemappedRoot(config *config.Config) (*idtools.IdentityMapping, error) {
	return &idtools.IdentityMapping{}, nil
}

func setupDaemonRoot(config *config.Config, rootDir string, rootIdentity idtools.Identity) error {
	config.Root = rootDir
	// Create the root directory if it doesn't exists
	if err := idtools.MkdirAllAndChown(config.Root, 0710, idtools.CurrentIdentity()); err != nil {
		return errors.Wrapf(err, "could not create or set daemon root permissions: %s", config.Root)
	}
	return nil
}

// conditionalMountOnStart is a platform specific helper function during the
// container start to call mount.
func (daemon *Daemon) conditionalMountOnStart(container *container.Container) error {
	return nil
}

// conditionalUnmountOnCleanup is a platform specific helper function called
// during the cleanup of a container to unmount.
func (daemon *Daemon) conditionalUnmountOnCleanup(container *container.Container) error {
	return nil
}

func driverOptions(config *config.Config) []nwconfig.Option {
	return []nwconfig.Option{}
}

func (daemon *Daemon) stats(c *container.Container) (*types.StatsJSON, error) {
	if !c.IsRunning() {
		return nil, errNotRunning(c.ID)
	}

	// Obtain the stats from HCS via libcontainerd
	stats, err := daemon.containerd.Stats(context.Background(), c.ID)
	if err != nil {
		if strings.Contains(err.Error(), "container not found") {
			return nil, containerNotFound(c.ID)
		}
		return nil, err
	}

	// Start with an empty structure
	s := &types.StatsJSON{}
	s.Stats.Read = stats.Read

	return s, nil
}

// setDefaultIsolation determine the default isolation mode for the
// daemon to run in. This is only applicable on Windows
func (daemon *Daemon) setDefaultIsolation() error {
	return nil
}

func setupDaemonProcess(config *config.Config) error {
	return nil
}

func (daemon *Daemon) setupSeccompProfile() error {
	return nil
}

func (daemon *Daemon) loadRuntimes() error {
	return nil
}

func (daemon *Daemon) initRuntimes(_ map[string]types.Runtime) error {
	return nil
}

func setupResolvConf(config *config.Config) {
}

// RawSysInfo returns *sysinfo.SysInfo .
func (daemon *Daemon) RawSysInfo(quiet bool) *sysinfo.SysInfo {
	return sysinfo.New(quiet)
}
