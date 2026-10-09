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
	"unsafe"

	"github.com/tinfoilsh/modelwrap"
	"github.com/tinfoilsh/modelwrap/unwrap"
)

const stateDir = "/run/modelwrap"

type parameters struct {
	RootHash   string `json:"root_hash"`
	HashOffset uint64 `json:"hash_offset"`
}

type model struct {
	ModelID    string     `json:"modelid"`
	MountPath  string     `json:"mount_path"`
	Parameters parameters `json:"parameters"`
	InputPath  string     `json:"input_path"`
}

// Records are written before creating each mapping/mount. Loop devices use
// AUTOCLEAR, so a killed helper cannot leak an unattached loop device.
type resource struct {
	Loop   string `json:"loop"`
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
		if len(m.Parameters.RootHash) != 64 || strings.Trim(m.Parameters.RootHash, "0123456789abcdef") != "" {
			return fmt.Errorf("model %d: invalid root_hash", i)
		}
		if _, err := modelwrap.VerityParamsForArtifact(m.Parameters.HashOffset, modelwrap.VeritySalt(m.ModelID)); err != nil {
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
	return fmt.Sprintf("modelwrap-%x-%d", hash[:8], index)
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

// Linux loop_config/loop_info64 ABI. LOOP_CONFIGURE attaches the backing file
// and sets read-only + autoclear atomically (available since Linux 5.8).
type loopInfo struct {
	Device, Inode, RDevice, Offset, SizeLimit  uint64
	Number, EncryptType, EncryptKeySize, Flags uint32
	FileName, CryptName                        [64]byte
	EncryptKey                                 [32]byte
	Init                                       [2]uint64
}
type loopConfig struct {
	FD, BlockSize uint32
	Info          loopInfo
	Reserved      [8]uint64
}

func ioctl(fd uintptr, op uintptr, arg uintptr) (uintptr, error) {
	result, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, op, arg)
	if errno != 0 {
		return 0, errno
	}
	return result, nil
}

func node(path string, mode uint32, dev int) error {
	if err := syscall.Mknod(path, mode|0600, dev); err != nil && err != syscall.EEXIST {
		return err
	}
	return nil
}

func openLoop(path string, offset uint64) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || uint64(info.Size()) < offset+4096 {
		return nil, fmt.Errorf("input must be a regular file containing data and hash areas")
	}
	if err = node("/dev/loop-control", syscall.S_IFCHR, int(10<<8|237)); err != nil {
		return nil, err
	}
	control, err := os.OpenFile("/dev/loop-control", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	defer control.Close()
	for attempt := 0; attempt < 16; attempt++ {
		n, err := ioctl(control.Fd(), 0x4c82, 0) // LOOP_CTL_GET_FREE
		if err != nil {
			return nil, err
		}
		path := "/dev/loop" + strconv.Itoa(int(n))
		// Linux makedev for major 7, with support for minors beyond 255.
		dev := int(7<<8 | (n & 255) | (n&^255)<<12)
		if err = node(path, syscall.S_IFBLK, dev); err != nil {
			return nil, err
		}
		loop, err := os.OpenFile(path, os.O_RDONLY, 0)
		if err != nil {
			return nil, err
		}
		config := loopConfig{FD: uint32(file.Fd()), BlockSize: 4096, Info: loopInfo{Flags: 1 | 4}}
		_, err = ioctl(loop.Fd(), 0x4c0a, uintptr(unsafe.Pointer(&config))) // LOOP_CONFIGURE
		if err == nil {
			return loop, nil
		}
		loop.Close()
		if err != syscall.EBUSY {
			return nil, err
		}
	}
	return nil, fmt.Errorf("no available loop device")
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
		if r.Mount != filepath.Join(dir, "mounts", strconv.Itoa(i)) || r.Mapper != mapperName(dir, i) || !strings.HasPrefix(r.Loop, "/dev/loop") {
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
		// Closing the mapping clears AUTOCLEAR loops automatically.
		if err := os.Remove(r.Mount); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, err)
		}
	}
	if len(failures) != 0 {
		return errors.Join(failures...)
	}
	return os.Remove(filepath.Join(dir, "state.json"))
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
	resources := []resource{}
	defer func() {
		if err != nil {
			if cleanupErr := cleanup(dir); cleanupErr != nil {
				err = errors.Join(err, fmt.Errorf("rollback: %w", cleanupErr))
			}
		}
	}()
	for i, m := range models {
		loop, openErr := openLoop(m.InputPath, m.Parameters.HashOffset)
		if openErr != nil {
			return fmt.Errorf("%s: %w", m.ModelID, openErr)
		}
		r := resource{Loop: loop.Name(), Mapper: mapperName(dir, i), Mount: filepath.Join(dir, "mounts", strconv.Itoa(i))}
		resources = append(resources, r)
		if err = save(dir, resources); err != nil {
			loop.Close()
			return err
		}
		err = unwrap.OpenVerity(r.Loop, r.Mapper, m.Parameters.RootHash, strconv.FormatUint(m.Parameters.HashOffset, 10), modelwrap.VeritySalt(m.ModelID))
		if err == nil {
			err = unwrap.Mount("/dev/mapper/"+r.Mapper, r.Mount)
		}
		if err == nil {
			err = command("mount", "--make-private", r.Mount)
		}
		loop.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", m.ModelID, err)
		}
	}
	return nil
}

func run(args []string, in io.Reader) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: podvm-model-mount mount|cleanup")
	}
	switch args[0] {
	case "cleanup":
		return cleanup(stateDir)
	case "mount":
		var models []model
		if err := decode(in, &models); err != nil {
			return err
		}
		return mountAll(stateDir, models)
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
