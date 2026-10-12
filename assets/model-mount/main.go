// SPDX-License-Identifier: Apache-2.0
// The guest agent supplies resolved, policy-authorized sources over stdin.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/tinfoilsh/modelwrap"
	"github.com/tinfoilsh/modelwrap/unwrap"
)

type model struct {
	ModelID   string `json:"modelid"`
	MountPath string `json:"mount_path"`
	Info      string `json:"info"`
	InputPath string `json:"input_path"`
}

// Journal only mappings and mounts owned by this helper, before creating them.
type resource struct {
	Input  string `json:"input"`
	Mapper string `json:"mapper"`
	Mount  string `json:"mount"`
}

func decode(r io.Reader, target any) error {
	d := json.NewDecoder(io.LimitReader(r, 1024*1024+1))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return fmt.Errorf("trailing JSON data")
	}
	return nil
}

func validate(models []model) error {
	if models == nil {
		return fmt.Errorf("expected an array")
	}
	for i, m := range models {
		if strings.TrimSpace(m.ModelID) != m.ModelID || !strings.Contains(m.ModelID, "@") || strings.HasSuffix(m.ModelID, "@") || strings.HasPrefix(m.ModelID, "@") {
			return fmt.Errorf("model %d: expected exact name@revision identity", i)
		}
		if !strings.HasPrefix(m.MountPath, "/models/") || filepath.Clean(m.MountPath) != m.MountPath || strings.ContainsRune(m.MountPath, 0) {
			return fmt.Errorf("model %d: invalid mount_path", i)
		}
		ref, err := modelwrap.ParseRef(m.Info)
		if err != nil {
			return fmt.Errorf("model %d: invalid info: %w", i, err)
		}
		offset, err := ref.HashOffsetBytes()
		if err != nil {
			return fmt.Errorf("model %d: %w", i, err)
		}
		if _, err := modelwrap.VerityParamsForArtifact(offset, modelwrap.VeritySalt(m.ModelID)); err != nil {
			return fmt.Errorf("model %d: %w", i, err)
		}
		if !filepath.IsAbs(m.InputPath) || filepath.Clean(m.InputPath) != m.InputPath {
			return fmt.Errorf("model %d: invalid input_path", i)
		}
		for _, prev := range models[:i] {
			if prev.MountPath == m.MountPath || strings.HasPrefix(m.MountPath, prev.MountPath+"/") || strings.HasPrefix(prev.MountPath, m.MountPath+"/") {
				return fmt.Errorf("overlapping mount paths")
			}
		}
	}
	return nil
}

func command(name string, args ...string) error {
	c := exec.Command(name, args...)
	c.Stdout, c.Stderr = os.Stderr, os.Stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func mapperActive(name string) (bool, error) {
	err := exec.Command("veritysetup", "status", name).Run()
	if err == nil {
		return true, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 4 { // Inactive mapping.
		return false, nil
	}
	return false, fmt.Errorf("veritysetup status: %w", err)
}

func mapperName(dir string, index int) string {
	hash := sha256.Sum256([]byte(dir))
	return fmt.Sprintf("modelwrap-%x-%d", hash[:], index)
}

// veritysetup takes an exclusive open of its data device. Give each consumer
// an owned, read-only linear view so concurrent verity mappings can share the
// caller's raw block input while retaining modelwrap's pinned verity opener.
func linearInput(file *os.File, name string) error {
	capacity, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	table := fmt.Sprintf("0 %d linear %s 0", capacity/512, descriptorPath(file))
	if err := command("dmsetup", "create", name, "--readonly", "--noudevsync", "--addnodeoncreate", "--table", table); err != nil {
		return err
	}
	// The agent does not depend on a udev daemon to create mapping nodes.
	return command("dmsetup", "mknodes", name)
}

func linearActive(name string) (bool, error) {
	// Query kernel names rather than relying on device nodes, which may not
	// appear before an interrupted dmsetup process is killed.
	output, err := exec.Command("dmsetup", "info", "--columns", "--noheadings", "--options", "name").Output()
	if err != nil {
		return false, fmt.Errorf("dmsetup info: %w", err)
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.TrimSpace(line) == name {
			return true, nil
		}
	}
	return false, nil
}

func save(dir string, resources []resource) error {
	data, err := json.Marshal(resources)
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, "state.tmp")
	if err = os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, "state.json"))
}

// Keep the opened device alive until veritysetup has opened both data and hash
// inputs. The child opens our descriptor through procfs, never the caller's
// replaceable path. O_NOFOLLOW rejects a symlink at the final component.
func openBlock(path string, offset uint64) (*os.File, error) {
	fd, err := openNoFollow(path)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if err := checkBlock(file, offset); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

// Walk using directory descriptors so no component can be followed through
// a symlink or replaced between checking it and opening its child.
func openNoFollow(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return -1, fmt.Errorf("invalid block input path")
	}
	parent, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, component := range components {
		flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
		if i < len(components)-1 {
			flags |= syscall.O_DIRECTORY
		}
		child, openErr := syscall.Openat(parent, component, flags, 0)
		syscall.Close(parent)
		if openErr != nil {
			return -1, openErr
		}
		parent = child
	}
	return parent, nil
}

func checkBlock(file *os.File, offset uint64) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeDevice == 0 || info.Mode()&os.ModeCharDevice != 0 {
		return fmt.Errorf("input must be a block device")
	}
	capacity, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("block capacity: %w", err)
	}
	if err := checkCapacity(capacity, offset); err != nil {
		return err
	}
	_, err = file.Seek(0, io.SeekStart)
	return err
}

func checkCapacity(capacity int64, offset uint64) error {
	// SHA-256 packs 128 hashes into each 4096-byte hash block. Include
	// every level of the tree and modelwrap's leading verity superblock.
	blocks := offset / modelwrap.VerityDataBlockSize
	hashBlocks := uint64(1)
	for blocks > 1 {
		blocks = (blocks + 127) / 128
		hashBlocks += blocks
	}
	if capacity < 0 || uint64(capacity) < offset+hashBlocks*modelwrap.VerityDataBlockSize {
		return fmt.Errorf("block device has insufficient capacity for data and hash areas")
	}
	return nil
}

func descriptorPath(file *os.File) string {
	return fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), file.Fd())
}

func cleanup(dir string) error {
	data, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var resources []resource
	if err = decode(strings.NewReader(string(data)), &resources); err != nil {
		return err
	}
	var failures []error
	for i := len(resources) - 1; i >= 0; i-- {
		r := resources[i]
		if r.Mount != filepath.Join(dir, "mounts", strconv.Itoa(i)) || r.Mapper != mapperName(dir, i) || r.Input != mapperName(dir, i)+"-input" {
			return fmt.Errorf("invalid resource record")
		}
		if err := syscall.Unmount(r.Mount, 0); err != nil && err != syscall.EINVAL && err != syscall.ENOENT {
			failures = append(failures, err)
			continue
		}
		// Query the kernel by mapping name: a killed veritysetup may have
		// created the mapping before its /dev/mapper node appeared.
		active, err := mapperActive(r.Mapper)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if active {
			if err = command("veritysetup", "close", r.Mapper); err != nil {
				failures = append(failures, err)
				continue
			}
		}
		inputActive, err := linearActive(r.Input)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if inputActive {
			if err = command("dmsetup", "remove", "--noudevsync", r.Input); err != nil {
				failures = append(failures, err)
				continue
			}
		}
		if err := os.Remove(r.Mount); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, err)
		}
	}
	if len(failures) != 0 {
		return errors.Join(failures...)
	}
	if err := os.Remove(filepath.Join(dir, "state.json")); err != nil {
		return err
	}
	// No owned resources remain; remove empty per-container state directories.
	for _, path := range []string{filepath.Join(dir, "state.tmp"), filepath.Join(dir, "mounts"), dir} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func mountAll(dir string, models []model) (err error) {
	if err = validate(models); err != nil {
		return err
	}
	if _, err = os.Stat(filepath.Join(dir, "state.json")); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("existing model mount state; refusing to overwrite")
	}
	if err = os.MkdirAll(filepath.Join(dir, "mounts"), 0700); err != nil {
		return err
	}
	if err = os.Chmod(dir, 0700); err != nil {
		return err
	}
	reservation, reserveErr := os.OpenFile(filepath.Join(dir, "state.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if reserveErr != nil {
		return fmt.Errorf("reserve state: %w", reserveErr)
	}
	_, err = reservation.WriteString("[]")
	closeErr := reservation.Close()
	if err != nil || closeErr != nil {
		return errors.Join(err, closeErr)
	}
	resources := []resource{}
	defer func() {
		if err != nil {
			if cleanupErr := cleanup(dir); cleanupErr != nil {
				err = errors.Join(err, fmt.Errorf("rollback: %w", cleanupErr))
			}
		}
	}()
	for i, m := range models {
		// validate has checked the complete reference and offset before any
		// resources are created. The OCI mount resolves the raw block device, not its UUID.
		ref, _ := modelwrap.ParseRef(m.Info)
		offset, _ := ref.HashOffsetBytes()
		device, openErr := openBlock(m.InputPath, offset)
		if openErr != nil {
			return fmt.Errorf("%s: %w", m.ModelID, openErr)
		}
		r := resource{Input: mapperName(dir, i) + "-input", Mapper: mapperName(dir, i), Mount: filepath.Join(dir, "mounts", strconv.Itoa(i))}
		resources = append(resources, r)
		if err = save(dir, resources); err != nil {
			device.Close()
			return err
		}
		err = linearInput(device, r.Input)
		if err == nil {
			// This node belongs to the mapping just created by this helper.
			// Hold its descriptor through verity opening as well as the raw FD.
			var input *os.File
			input, err = os.Open("/dev/mapper/" + r.Input)
			if err == nil {
				err = unwrap.OpenVerity(descriptorPath(input), r.Mapper, ref.RootHash, ref.HashOffset, modelwrap.VeritySalt(m.ModelID))
				input.Close()
			}
		}
		if err == nil {
			err = unwrap.Mount("/dev/mapper/"+r.Mapper, r.Mount)
		}
		if err == nil {
			err = command("mount", "--make-private", r.Mount)
		}
		device.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", m.ModelID, err)
		}
	}
	return nil
}

func run(args []string, in io.Reader) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: podvm-model-mount mount|cleanup STATE_DIR")
	}
	dir := args[1]
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || dir == "/" {
		return fmt.Errorf("invalid state directory")
	}
	switch args[0] {
	case "cleanup":
		return cleanup(dir)
	case "mount":
		var models []model
		if err := decode(in, &models); err != nil {
			return err
		}
		return mountAll(dir, models)
	default:
		return fmt.Errorf("unknown operation")
	}
}

func main() {
	if err := run(os.Args[1:], os.Stdin); err != nil {
		fmt.Fprintln(os.Stderr, "modelwrap:", err)
		os.Exit(1)
	}
}
