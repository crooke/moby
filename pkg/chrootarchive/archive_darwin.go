package chrootarchive // import "github.com/docker/docker/pkg/chrootarchive"

import (
	"io"

	"github.com/docker/docker/pkg/archive"
)

func invokeUnpack(decompressedArchive io.ReadCloser,
	dest string,
	options *archive.TarOptions, root string) error {
	// TODO: consider using chroot to sandbox like Linux does
	return archive.Unpack(decompressedArchive, dest, options)
}

func invokePack(srcPath string, options *archive.TarOptions, root string) (io.ReadCloser, error) {
	// TODO: consider using chroot to sandbox like Linux does
	return archive.TarWithOptions(srcPath, options)
}
