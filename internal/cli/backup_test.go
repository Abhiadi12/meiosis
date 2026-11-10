package cli

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/mindfire-test/meiosis/internal/gitops"
	"github.com/mindfire-test/meiosis/internal/graph"
	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/mindfire-test/meiosis/pkg/storage/sqlite"
)

// servedRepo is a project with data in its store and a served bare repository
// holding one commit.
func servedRepo(t *testing.T) (root string) {
	t.Helper()
	root = gitProject(t)
	declareJSON(t, root, "Backed-up intent", "--files", "src/**")
	repo := filepath.Join(root, ".meiosis", "git", "proj.git")
	if err := gitops.InitBare(context.Background(), "", repo); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "-C", root, "push", repo, "main").CombinedOutput(); err != nil {
		t.Fatalf("seed the served repository: %v\n%s", err, out)
	}
	return root
}

func TestBackupAndRestoreRoundTrip(t *testing.T) {
	root := servedRepo(t)
	backup := filepath.Join(t.TempDir(), "bk")

	out := mustRun(t, "", "backup", backup, "--repo", root)
	for _, want := range []string{"backup written", "repositories    1", "NOT included"} {
		if !strings.Contains(out, want) {
			t.Errorf("backup output missing %q:\n%s", want, out)
		}
	}
	var manifest backupManifest
	if err := json.Unmarshal([]byte(mustRead(t, filepath.Join(backup, "MANIFEST.json"))), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Format != 1 || len(manifest.Repos) != 1 || manifest.Keys || len(manifest.DatabaseSHA) != 64 {
		t.Fatalf("manifest = %+v", manifest)
	}
	if _, err := os.Stat(filepath.Join(backup, "keys")); err == nil {
		t.Fatal("private keys were included without --include-keys")
	}

	// Restore into a place that has nothing.
	target := filepath.Join(t.TempDir(), "fresh")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if res := mustRun(t, "", "restore", backup, "--repo", target); !strings.Contains(res, "restored") {
		t.Fatalf("restore: %s", res)
	}
	if list := mustRun(t, "", "intent", "list", "--repo", target); !strings.Contains(list, "Backed-up intent") {
		t.Fatalf("the restored database lost the intent:\n%s", list)
	}
	clone := filepath.Join(t.TempDir(), "clone")
	if out, err := exec.Command("git", "clone", "-q", filepath.Join(target, ".meiosis", "git", "proj.git"), clone).CombinedOutput(); err != nil {
		t.Fatalf("clone the restored repository: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(clone, "src", "main.go")); err != nil {
		t.Fatalf("the restored repository lost its content: %v", err)
	}
	// The restored repository is configured for serving again.
	if cfg, err := exec.Command("git", "--git-dir", filepath.Join(target, ".meiosis", "git", "proj.git"), "config", "--get", "receive.denyNonFastForwards").Output(); err != nil || strings.TrimSpace(string(cfg)) != "true" {
		t.Fatalf("restored repository serving config = %q, %v", cfg, err)
	}

	// It will not clobber an existing database without being told to.
	if _, err := run("", "restore", backup, "--repo", target); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("restoring over a database = %v", err)
	}
	if _, err := run("", "restore", backup, "--repo", target, "--force"); err != nil {
		t.Fatalf("--force: %v", err)
	}
}

func TestBackupIsConsistentWhileTheDatabaseIsBeingWritten(t *testing.T) {
	root := servedRepo(t)
	backend, err := sqlite.Open(filepath.Join(root, ".meiosis", "meiosisd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = backend.Close() }()
	store := graph.NewStore(backend)
	keys, _ := crypto.GenerateKeyPair()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			_, _ = store.CreateIntent(context.Background(), graph.CreateIntentParams{
				Repo: "r", Title: "concurrent " + string(rune('a'+i%26)) + strings.Repeat("x", i%50), Goal: "g",
				Acceptance: []specv1.Criterion{{Text: "ok"}}, Scope: specv1.Scope{Allow: []string{"**"}, Mode: specv1.ScopeModeWarn}, CreatedBy: "human:w",
			}, keys.PrivateKey)
		}
	}()
	for i := range 5 {
		dest := filepath.Join(t.TempDir(), "bk")
		mustRun(t, "", "backup", dest, "--repo", root)
		snap, err := sqlite.Open(filepath.Join(dest, backupDBName))
		if err != nil {
			t.Fatal(err)
		}
		problems, err := snap.IntegrityCheck(context.Background())
		_ = snap.Close()
		if err != nil || len(problems) > 0 {
			close(stop)
			t.Fatalf("backup %d is not a sound database: %v %v", i, problems, err)
		}
	}
	close(stop)
	wg.Wait()
}

func TestBackupRefusesNonEmptyDestinationsAndRestoreRefusesDamagedBackups(t *testing.T) {
	root := servedRepo(t)
	occupied := t.TempDir()
	if err := os.WriteFile(filepath.Join(occupied, "x"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := run("", "backup", occupied, "--repo", root); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("backup into a non-empty directory = %v", err)
	}

	backup := filepath.Join(t.TempDir(), "bk")
	mustRun(t, "", "backup", backup, "--repo", root, "--include-keys")
	if info, err := os.Stat(filepath.Join(backup, "keys", "human.private.key")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("--include-keys: %v %v", info, err)
	}

	// Alter the database after the fact: the manifest's checksum catches it.
	dbFile := filepath.Join(backup, backupDBName)
	data, _ := os.ReadFile(dbFile)
	data[len(data)/2] ^= 0xff
	if err := os.WriteFile(dbFile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "t")
	_ = os.MkdirAll(target, 0o755)
	if _, err := run("", "restore", backup, "--repo", target); err == nil || !strings.Contains(err.Error(), "does not match its manifest") {
		t.Fatalf("restoring a tampered backup = %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, ".meiosis", "meiosisd.db")); err == nil {
		t.Fatal("a refused restore still wrote a database")
	}
	if _, err := run("", "restore", t.TempDir(), "--repo", target); err == nil || !strings.Contains(err.Error(), "not a meiosis backup") {
		t.Fatalf("restoring a directory that is no backup = %v", err)
	}
}
