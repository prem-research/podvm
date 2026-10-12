package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tinfoilsh/modelwrap"
)

const testUUID = "01234567-89ab-cdef-0123-456789abcdef"

func validModel() model {
	return model{ModelID: "org/model@revision", MountPath: "/models/example", InputPath: "/input.mpk", Info: strings.Repeat("ab", 32) + "_4096_" + testUUID}
}

func TestDecodeAndValidation(t *testing.T) {
	m := validModel()
	if err := validate([]model{m}); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*model){
		func(m *model) { m.ModelID = "alias" },
		func(m *model) { m.MountPath = "/models/../etc" },
		func(m *model) { m.Info = strings.Replace(m.Info, strings.Repeat("ab", 32), "bad", 1) },
		func(m *model) { m.Info = strings.Replace(m.Info, "_4096_", "_4097_", 1) },
		func(m *model) { m.Info = strings.Replace(m.Info, "_4096_", "_9223372036854775808_", 1) },
		func(m *model) { m.InputPath = "relative" },
	} {
		bad := m
		change(&bad)
		if validate([]model{bad}) == nil {
			t.Fatalf("accepted %#v", bad)
		}
	}
	if validate([]model{m, m}) == nil {
		t.Fatal("accepted duplicate mounts")
	}
	child := m
	child.MountPath += "/child"
	if validate([]model{m, child}) == nil {
		t.Fatal("accepted overlapping mounts")
	}
	for _, input := range []string{"null", "{}", "[] []", `[{"unknown":true}]`} {
		var models []model
		if err := decode(strings.NewReader(input), &models); err == nil && validate(models) == nil {
			t.Fatalf("accepted %s", input)
		}
	}

}

func TestInfoContract(t *testing.T) {
	m := validModel()
	for _, info := range []string{
		"", strings.Repeat("ab", 32) + "_4096", m.Info + "_extra", m.Info + "\n", " " + m.Info,
		strings.ToUpper(m.Info),
		strings.Replace(m.Info, "_4096_", "_0_", 1),
		strings.Replace(m.Info, "_4096_", "_+4096_", 1),
		strings.Replace(m.Info, "_4096_", "_-4096_", 1),
		strings.Replace(m.Info, "_4096_", "_4096.0_", 1),
		strings.Replace(m.Info, "_4096_", "_18446744073709551616_", 1),
		strings.Replace(m.Info, testUUID, "bad", 1),
		strings.Replace(m.Info, testUUID, strings.ReplaceAll(testUUID, "-", ""), 1),
		strings.Replace(m.Info, testUUID, "g1234567-89ab-cdef-0123-456789abcdef", 1),
	} {
		bad := m
		bad.Info = info
		if err := validate([]model{bad}); err == nil {
			t.Errorf("accepted invalid info %q", info)
		}
	}
	for _, offset := range []string{"0004096", "4611686018427387904"} {
		valid := m
		valid.Info = strings.Replace(m.Info, "_4096_", "_"+offset+"_", 1)
		if err := validate([]model{valid}); err != nil {
			t.Errorf("rejected valid offset %q: %v", offset, err)
		}
	}
	data, err := json.Marshal([]model{m})
	if err != nil {
		t.Fatal(err)
	}
	var decoded []model
	if err := decode(bytes.NewReader(data), &decoded); err != nil || len(decoded) != 1 || decoded[0].Info != m.Info {
		t.Fatalf("info round trip: %s: %v", data, err)
	}
	for _, input := range []string{
		strings.Replace(string(data), `"info":"`+m.Info+`"`, `"parameters":{"root_hash":"`+strings.Repeat("ab", 32)+`","hash_offset":4096}`, 1),
		strings.Replace(string(data), `"info":"`+m.Info+`"`, `"info":null`, 1),
		strings.Replace(string(data), `"info":"`+m.Info+`"`, `"info":{}`, 1),
		strings.Replace(string(data), `"info":"`+m.Info+`",`, "", 1),
	} {
		decoded = nil
		if err := decode(strings.NewReader(input), &decoded); err == nil && validate(decoded) == nil {
			t.Errorf("accepted invalid contract %s", input)
		}
	}
}

func TestExistingStateIsNeverOverwritten(t *testing.T) {
	dir := t.TempDir()
	state := []byte("existing state")
	if err := os.WriteFile(filepath.Join(dir, "state.json"), state, 0600); err != nil {
		t.Fatal(err)
	}
	if mountAll(dir, []model{validModel()}) == nil {
		t.Fatal("overwrote existing state")
	}
	data, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if !bytes.Equal(data, state) {
		t.Fatal("state changed")
	}
}

func fixture(t *testing.T, dir, id string) model {
	t.Helper()
	root := filepath.Join(dir, "root")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "weights"), []byte(strings.Repeat("verified model bytes\n", 8192)), 0644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "model.mpk")
	if output, err := exec.Command("mkfs.erofs", "--all-root", "-T0", path, root).CombinedOutput(); err != nil {
		t.Fatalf("mkfs.erofs: %s: %v", output, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	offset := info.Size()
	salt := sha256.Sum256([]byte(id))
	output, err := exec.Command("veritysetup", "format", path, path, "--format=1", "--hash=sha256", "--data-block-size=4096", "--hash-block-size=4096", "--salt="+hex.EncodeToString(salt[:]), "--hash-offset="+strconvInt(offset)).CombinedOutput()
	if err != nil {
		t.Fatalf("veritysetup format: %s: %v", output, err)
	}
	match := regexp.MustCompile(`Root hash:\s+([a-f0-9]{64})`).FindSubmatch(output)
	if len(match) != 2 {
		t.Fatalf("missing root hash: %s", output)
	}
	uuid := regexp.MustCompile(`UUID:\s+([a-f0-9-]{36})`).FindSubmatch(output)
	if len(uuid) != 2 {
		t.Fatalf("missing verity UUID: %s", output)
	}
	return model{ModelID: id, MountPath: "/models/example", InputPath: path, Info: string(match[1]) + "_" + strconvInt(offset) + "_" + string(uuid[1])}
}

func strconvInt(n int64) string { return fmt.Sprintf("%d", n) }

// Runs inside the privileged, isolated Docker integration runner only. It
// uses per-test mapper names; never detach another build's loop devices.
func TestVerifiedMountIntegration(t *testing.T) {
	if os.Getenv("MODEL_MOUNT_INTEGRATION") != "1" {
		t.Skip("requires privileged integration runner")
	}
	dir := t.TempDir()
	m := fixture(t, filepath.Join(dir, "fixture"), "org/model@revision")
	backing := m.InputPath
	m.InputPath = attachReadOnly(t, backing)
	state := filepath.Join(dir, "state")
	defer func() {
		if err := cleanup(state); err != nil {
			t.Error(err)
		}
	}()
	if err := mountAll(state, []model{m}); err != nil {
		t.Fatal(err)
	}
	weights := filepath.Join(state, "mounts/0/weights")
	data, err := os.ReadFile(weights)
	if err != nil || !bytes.HasPrefix(data, []byte("verified model bytes")) {
		t.Fatalf("model read: %v", err)
	}
	if os.WriteFile(weights, []byte("tamper"), 0644) == nil {
		t.Fatal("model mount is writable")
	}
	// Interrupted setup may leave a kernel mapping without its device node.
	// Cleanup must query by name and release it anyway.
	if err := os.Remove("/dev/mapper/" + mapperName(state, 0)); err != nil {
		t.Fatal(err)
	}
	if err := cleanup(state); err != nil {
		t.Fatal(err)
	}
	if active, err := mapperActive(mapperName(state, 0)); active || err != nil {
		t.Fatalf("mapping remains after cleanup: active=%v err=%v", active, err)
	}
	if _, err := os.Stat(filepath.Join(state, "state.json")); !os.IsNotExist(err) {
		t.Fatal("state remains after cleanup")
	}
	// Cleanup must leave the caller's read-only device attached.
	if output, err := exec.Command("losetup", m.InputPath).CombinedOutput(); err != nil {
		t.Fatalf("caller-owned device detached: %s: %v", output, err)
	}
	// Independent consumers of the same input have distinct resources.
	other := filepath.Join(dir, "other-state")
	if err := mountAll(state, []model{m}); err != nil {
		t.Fatal(err)
	}
	if err := mountAll(other, []model{m}); err != nil {
		t.Fatal(err)
	}
	defer cleanup(other)
	if err := cleanup(state); err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(filepath.Join(other, "mounts/0/weights")); err != nil {
		t.Fatal(err)
	}
	if err := cleanup(other); err != nil {
		t.Fatal(err)
	}
	// A wrong identity/root hash must never yield a usable filesystem.
	for _, change := range []func(*model){
		func(m *model) { m.ModelID = "org/model@wrong-revision" },
		func(m *model) { m.Info = strings.Repeat("0", 64) + "_" + strings.SplitN(m.Info, "_", 2)[1] },
		func(m *model) { m.Info = strings.Replace(m.Info, "_"+strings.Split(m.Info, "_")[1]+"_", "_4096_", 1) },
	} {
		bad := m
		change(&bad)
		if err := mountAll(state, []model{bad}); err == nil {
			t.Fatal("mounted unauthenticated model")
		}
		if _, err := os.Stat(filepath.Join(state, "state.json")); !os.IsNotExist(err) {
			t.Fatal("partial state remains")
		}
	}
	// Failure on a later model must undo the earlier successful mount.
	bad := m
	bad.MountPath = "/models/other"
	bad.InputPath = filepath.Join(dir, "missing.mpk")
	if mountAll(state, []model{m, bad}) == nil {
		t.Fatal("accepted missing second model")
	}
	if _, err := os.Stat(filepath.Join(state, "state.json")); !os.IsNotExist(err) {
		t.Fatal("rollback did not remove resources")
	}
	// Metadata can mount while an unread data block is corrupt: reads still
	// fail closed. Corrupt the backing file only after opening the mapping.
	if err := mountAll(state, []model{m}); err != nil {
		t.Fatal(err)
	}
	source, err := os.OpenFile(backing, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	original := make([]byte, 4096)
	ref, err := modelwrap.ParseRef(m.Info)
	if err != nil {
		t.Fatal(err)
	}
	offset, err := ref.HashOffsetBytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = source.ReadAt(original, int64(offset)-4096); err != nil {
		t.Fatal(err)
	}
	if _, err = source.WriteAt(make([]byte, 4096), int64(offset)-4096); err != nil {
		t.Fatal(err)
	}
	if err = source.Sync(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.ReadFile(weights); err == nil {
		t.Fatal("read corrupted model weights")
	}
	if err = cleanup(state); err != nil {
		t.Fatal(err)
	}
	if _, err = source.WriteAt(original, int64(offset)-4096); err != nil {
		t.Fatal(err)
	}
	source.Close()
	// Persisted records also support cleanup by a fresh helper process.
	if err := mountAll(state, []model{m}); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(filepath.Join(state, "state.json"))
	var records []resource
	if json.Unmarshal(data, &records) != nil || len(records) != 1 {
		t.Fatal("missing cleanup journal")
	}
}

func TestExportSmokeFixtures(t *testing.T) {
	dir := os.Getenv("MODEL_MOUNT_FIXTURE_DIR")
	if dir == "" {
		t.Skip("only used to export VM smoke fixtures")
	}
	models := []model{}
	for i := 0; i < 2; i++ {
		m := fixture(t, filepath.Join(dir, fmt.Sprintf("model%d", i)), fmt.Sprintf("org/model%d@revision", i))
		m.MountPath = fmt.Sprintf("/models/example%d", i)
		models = append(models, m)
	}
	data, err := json.Marshal(models)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "models.json"), data, 0644); err != nil {
		t.Fatal(err)
	}
}

// Only the privileged test harness owns loop attachments; the guest helper
// neither allocates nor detaches them. Detach the exact device we allocated.
func attachReadOnly(t *testing.T, path string) string {
	t.Helper()
	output, err := exec.Command("losetup", "--find", "--show", "--read-only", path).CombinedOutput()
	if err != nil {
		t.Fatalf("attach fixture: %s: %v", output, err)
	}
	device := strings.TrimSpace(string(output))
	t.Cleanup(func() {
		if output, err := exec.Command("losetup", "--detach", device).CombinedOutput(); err != nil {
			t.Errorf("detach owned fixture %s: %s: %v", device, output, err)
		}
	})
	return device
}

func TestRejectNonBlockInputs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, make([]byte, 16384), 0600); err != nil {
		t.Fatal(err)
	}
	link := path + ".link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{path, link, "/dev/null", "/dev/zero"} {
		file, err := openBlock(input, 4096)
		if err == nil {
			file.Close()
			t.Fatalf("accepted %s", input)
		}
	}
}

func TestCapacity(t *testing.T) {
	for _, capacity := range []int64{-1, 0, 4096, 8191} {
		if checkCapacity(capacity, 4096) == nil {
			t.Fatalf("accepted capacity %d", capacity)
		}
	}
	if err := checkCapacity(8192, 4096); err != nil {
		t.Fatal(err)
	}
	// 129 data blocks need two leaf blocks, one root block, and superblock.
	if checkCapacity(132*4096, 129*4096) == nil {
		t.Fatal("accepted short hash tree")
	}
	if err := checkCapacity(133*4096, 129*4096); err != nil {
		t.Fatal(err)
	}
}

func TestStateDirectoryArgument(t *testing.T) {
	for _, args := range [][]string{{"cleanup"}, {"cleanup", "/"}, {"cleanup", "relative"}, {"cleanup", "/tmp/../tmp/state"}} {
		if run(args, strings.NewReader("[]")) == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	if err := run([]string{"cleanup", t.TempDir()}, strings.NewReader("")); err != nil {
		t.Fatal(err)
	}
}

func TestDescriptorSurvivesPathReplacement(t *testing.T) {
	// procfs resolves the held descriptor even after its original name changes.
	path := filepath.Join(t.TempDir(), "input")
	os.WriteFile(path, []byte("original"), 0600)
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	os.Rename(path, path+".old")
	os.WriteFile(path, []byte("replacement"), 0600)
	data, err := exec.Command("cat", descriptorPath(file)).Output()
	if err != nil || string(data) != "original" {
		t.Fatalf("descriptor reopened replaced input: %q %v", data, err)
	}
}

// Re-execute the test binary as a helper to exercise SIGKILL recovery using
// the same CLI and journal that the agent uses in a fresh helper process.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("PODVM_HELPER_PROCESS") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			if err := run(os.Args[i+1:], os.Stdin); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			os.Exit(0)
		}
	}
	os.Exit(2)
}

func TestInterruptedSetupIntegration(t *testing.T) {
	if os.Getenv("MODEL_MOUNT_INTEGRATION") != "1" {
		t.Skip("requires privileged integration runner")
	}
	dir := t.TempDir()
	m := fixture(t, filepath.Join(dir, "fixture"), "org/model@revision")
	m.InputPath = attachReadOnly(t, m.InputPath)
	state := filepath.Join(dir, "state")
	t.Cleanup(func() {
		if err := cleanup(state); err != nil {
			t.Error(err)
		}
	})
	tools := filepath.Join(dir, "tools")
	os.Mkdir(tools, 0700)
	mount, err := exec.LookPath("mount")
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "mounted")
	// All paths here come from TempDir and the trusted runner tool search.
	script := fmt.Sprintf("#!/bin/sh\n'%s' \"$@\" || exit $?\ntouch '%s'\nsleep 60\n", mount, marker)
	if err := os.WriteFile(filepath.Join(tools, "mount"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal([]model{m})
	child := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$", "--", "mount", state)
	child.Env = append(os.Environ(), "PODVM_HELPER_PROCESS=1", "PATH="+tools+":"+os.Getenv("PATH"))
	child.Stdin = bytes.NewReader(data)
	child.Stdout, child.Stderr = os.Stderr, os.Stderr
	child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	running := true
	defer func() {
		if running {
			syscall.Kill(-child.Process.Pid, syscall.SIGKILL)
			child.Wait()
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("interrupted setup never reached mount")
		}
		time.Sleep(10 * time.Millisecond)
	}
	syscall.Kill(-child.Process.Pid, syscall.SIGKILL)
	child.Wait()
	running = false
	fresh := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$", "--", "cleanup", state)
	fresh.Env = append(os.Environ(), "PODVM_HELPER_PROCESS=1")
	if output, err := fresh.CombinedOutput(); err != nil {
		t.Fatalf("fresh cleanup: %s: %v", output, err)
	}
	if active, err := mapperActive(mapperName(state, 0)); active || err != nil {
		t.Fatalf("interrupted mapping remains: %v %v", active, err)
	}
	if output, err := exec.Command("losetup", m.InputPath).CombinedOutput(); err != nil {
		t.Fatalf("caller input detached: %s: %v", output, err)
	}
}

func TestParentSymlinksAreRejected(t *testing.T) {
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "target"), 0700)
	os.WriteFile(filepath.Join(dir, "target/file"), []byte("input"), 0600)
	os.Symlink(filepath.Join(dir, "target"), filepath.Join(dir, "link"))
	if fd, err := openNoFollow(filepath.Join(dir, "link/file")); err == nil {
		syscall.Close(fd)
		t.Fatal("followed parent symlink")
	}
}
