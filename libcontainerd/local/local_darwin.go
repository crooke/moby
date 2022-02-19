package local // import "github.com/docker/docker/libcontainerd/local"

// This package contains the legacy in-proc calls in HCS using the v1 schema
// for Darwin runtime purposes.

import (
	"context"
	"fmt"
	"sync"
	"syscall"
	"time"

	"github.com/containerd/containerd"

	"github.com/docker/docker/errdefs"
	"github.com/docker/docker/libcontainerd/queue"
	libcontainerdtypes "github.com/docker/docker/libcontainerd/types"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type process struct {
	id  string
	pid int
	// hcsProcess hcsshim.Process
}

type container struct {
	sync.Mutex

	// The ociSpec is required, as client.Create() needs a spec, but can
	// be called from the RestartManager context which does not otherwise
	// have access to the Spec
	ociSpec *specs.Spec

	isDarwin bool
	// hcsContainer hcsshim.Container

	id               string
	status           containerd.ProcessStatus
	exitedAt         time.Time
	exitCode         uint32
	waitCh           chan struct{}
	init             *process
	execs            map[string]*process
	terminateInvoked bool
}

// Win32 error codes that are used for various workarounds
// These really should be ALL_CAPS to match golangs syscall library and standard
// Win32 error conventions, but golint insists on CamelCase.
const (
	CoEClassstring     = syscall.Errno(0x800401F3) // Invalid class string
	ErrorNoNetwork     = syscall.Errno(1222)       // The network is not present or not started
	ErrorBadPathname   = syscall.Errno(161)        // The specified path is invalid
	ErrorInvalidObject = syscall.Errno(0x800710D8) // The object identifier does not represent a valid object
)

// defaultOwner is a tag passed to HCS to allow it to differentiate between
// container creator management stacks. We hard code "docker" in the case
// of docker.
const defaultOwner = "docker"

type client struct {
	sync.Mutex

	stateDir   string
	backend    libcontainerdtypes.Backend
	logger     *logrus.Entry
	eventQ     queue.Queue
	containers map[string]*container
}

// NewClient creates a new local executor for darwin
func NewClient(ctx context.Context, cli *containerd.Client, stateDir, ns string, b libcontainerdtypes.Backend) (libcontainerdtypes.Client, error) {
	c := &client{
		stateDir:   stateDir,
		backend:    b,
		logger:     logrus.WithField("module", "libcontainerd").WithField("module", "libcontainerd").WithField("namespace", ns),
		containers: make(map[string]*container),
	}

	return c, nil
}

func (c *client) Version(ctx context.Context) (containerd.Version, error) {
	return containerd.Version{}, errors.New("not implemented on Darwin")
}

// Create is the entrypoint to create a container from a spec.
func (c *client) Create(_ context.Context, id string, spec *specs.Spec, shim string, runtimeOptions interface{}, opts ...containerd.NewContainerOpts) error {
	if ctr := c.getContainer(id); ctr != nil {
		return errors.WithStack(errdefs.Conflict(errors.New("id already in use")))
	}

	var err error
	if spec.Linux == nil {
		err = c.createDarwin(id, spec, runtimeOptions)
	} else {
		err = c.createLinux(id, spec, runtimeOptions)
	}

	if err == nil {
		c.eventQ.Append(id, func() {
			ei := libcontainerdtypes.EventInfo{
				ContainerID: id,
			}
			c.logger.WithFields(logrus.Fields{
				"container": id,
				"event":     libcontainerdtypes.EventCreate,
			}).Info("sending event")
			err := c.backend.ProcessEvent(id, libcontainerdtypes.EventCreate, ei)
			if err != nil {
				c.logger.WithError(err).WithFields(logrus.Fields{
					"container": id,
					"event":     libcontainerdtypes.EventCreate,
				}).Error("failed to process event")
			}
		})
	}
	return err
}

func (c *client) createDarwin(id string, spec *specs.Spec, runtimeOptions interface{}) error {
	return fmt.Errorf("TODO: implement createDarwin")
}

func (c *client) createLinux(id string, spec *specs.Spec, runtimeOptions interface{}) error {
	return fmt.Errorf("linux containers not supported on darwin")
}

func (c *client) Start(_ context.Context, id, _ string, withStdin bool, attachStdio libcontainerdtypes.StdioCallback) (int, error) {
	return -1, fmt.Errorf("TODO: implement Start")
}

// Exec adds a process in an running container
func (c *client) Exec(ctx context.Context, containerID, processID string, spec *specs.Process, withStdin bool, attachStdio libcontainerdtypes.StdioCallback) (int, error) {
	return -1, fmt.Errorf("TODO: implement createDarwin")
}

// Signal handles `docker stop` on Darwin. While Linux has support for
// the full range of signals, signals aren't really implemented on Darwin.
// We fake supporting regular stop and -9 to force kill.
func (c *client) SignalProcess(_ context.Context, containerID, processID string, signal int) error {
	return fmt.Errorf("TODO: implement SignalProcess")

}

// Resize handles a CLI event to resize an interactive docker run or docker
// exec window.
func (c *client) ResizeTerminal(_ context.Context, containerID, processID string, width, height int) error {
	return fmt.Errorf("TODO: implement ResizeTerminal")
}

func (c *client) CloseStdin(_ context.Context, containerID, processID string) error {
	return fmt.Errorf("TODO: implement CloseStdin")
}

// Pause handles pause requests for containers
func (c *client) Pause(_ context.Context, containerID string) error {
	return fmt.Errorf("TODO: implement Pause")
}

// Resume handles resume requests for containers
func (c *client) Resume(_ context.Context, containerID string) error {
	return fmt.Errorf("TODO: implement Resume")
}

// Stats handles stats requests for containers
func (c *client) Stats(_ context.Context, containerID string) (*libcontainerdtypes.Stats, error) {
	return nil, fmt.Errorf("TODO: implement Stats")
}

// Restore is the handler for restoring a container
func (c *client) Restore(ctx context.Context, id string, attachStdio libcontainerdtypes.StdioCallback) (bool, int, libcontainerdtypes.Process, error) {
	return false, -1, nil, fmt.Errorf("TODO: implement Restore")
}

// GetPidsForContainer returns a list of process IDs running in a container.
// Not used on Darwin.
func (c *client) ListPids(_ context.Context, _ string) ([]uint32, error) {
	return nil, errors.New("not implemented on Darwin")
}

// Summary returns a summary of the processes running in a container.
// This is present in Darwin to support docker top. In linux, the
// engine shells out to ps to get process information. On Darwin, as
// the containers could be Hyper-V containers, they would not be
// visible on the container host. However, libcontainerd does have
// that information.
func (c *client) Summary(_ context.Context, containerID string) ([]libcontainerdtypes.Summary, error) {
	return nil, errors.New("not implemented on Darwin")
}

func (c *client) DeleteTask(ctx context.Context, containerID string) (uint32, time.Time, error) {
	return 0, time.Now(), errors.New("not implemented on Darwin")
}

func (c *client) Delete(_ context.Context, containerID string) error {
	return errors.New("not implemented on Darwin")
}

func (c *client) Status(ctx context.Context, containerID string) (containerd.ProcessStatus, error) {
	return containerd.Unknown, errors.New("not implemented on Darwin")
}

func (c *client) UpdateResources(ctx context.Context, containerID string, resources *libcontainerdtypes.Resources) error {
	// Updating resource isn't supported on Darwin
	// but we should return nil for enabling updating container
	return nil
}

func (c *client) CreateCheckpoint(ctx context.Context, containerID, checkpointDir string, exit bool) error {
	return errors.New("Darwin: Containers do not support checkpoints")
}

func (c *client) getContainer(id string) *container {
	c.Lock()
	ctr := c.containers[id]
	c.Unlock()

	return ctr
}

func (c *client) getProcess(containerID, processID string) (*container, *process, error) {
	ctr := c.getContainer(containerID)
	switch {
	case ctr == nil:
		return nil, nil, errors.WithStack(errdefs.NotFound(errors.New("no such container")))
	case ctr.init == nil:
		return nil, nil, errors.WithStack(errdefs.NotFound(errors.New("container is not running")))
	case processID == libcontainerdtypes.InitProcessName:
		return ctr, ctr.init, nil
	default:
		ctr.Lock()
		defer ctr.Unlock()
		if ctr.execs == nil {
			return nil, nil, errors.WithStack(errdefs.NotFound(errors.New("no execs")))
		}
	}

	p := ctr.execs[processID]
	if p == nil {
		return nil, nil, errors.WithStack(errdefs.NotFound(errors.New("no such exec")))
	}

	return ctr, p, nil
}
