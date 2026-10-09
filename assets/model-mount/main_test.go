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
	"testing"
	"unsafe"
)

func validModel() model {
	return model{ModelID: "org/model@revision", MountPath: "/models/example", InputPath: "/input.mpk", Parameters: parameters{RootHash: strings.Repeat("ab", 32), HashOffset: 4096}}
}

func TestDecodeAndValidation(t *testing.T) {
	m := validModel()
	if err := validate([]model{m}); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*model){
		func(m *model) { m.ModelID = "alias" },
		func(m *model) { m.MountPath = "/models/../etc" },
		func(m *model) { m.Parameters.RootHash = "bad" },
		func(m *model) { m.Parameters.HashOffset = 4097 },
		func(m *model) { m.Parameters.HashOffset = 1 << 63 },
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
	if unsafe.Sizeof(loopInfo{}) != 232 || unsafe.Sizeof(loopConfig{}) != 304 {
		t.Fatal("incorrect Linux loop ABI")
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
	return model{ModelID: id, MountPath: "/models/example", InputPath: path, Parameters: parameters{RootHash: string(match[1]), HashOffset: uint64(offset)}}
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
	// A wrong identity/root hash must never yield a usable filesystem.
	for _, change := range []func(*model){
		func(m *model) { m.ModelID = "org/model@wrong-revision" },
		func(m *model) { m.Parameters.RootHash = strings.Repeat("0", 64) },
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
	source, err := os.OpenFile(m.InputPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	original := make([]byte, 4096)
	if _, err = source.ReadAt(original, int64(m.Parameters.HashOffset)-4096); err != nil {
		t.Fatal(err)
	}
	if _, err = source.WriteAt(make([]byte, 4096), int64(m.Parameters.HashOffset)-4096); err != nil {
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
	if _, err = source.WriteAt(original, int64(m.Parameters.HashOffset)-4096); err != nil {
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
