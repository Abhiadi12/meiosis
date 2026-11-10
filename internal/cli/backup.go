package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/mindfire-test/meiosis/internal/gitops"
	"github.com/mindfire-test/meiosis/pkg/storage/sqlite"
)

// backupManifest describes what a backup holds, so a restore can check it.
type backupManifest struct {
	Format      int       `json:"format"`
	CreatedAt   time.Time `json:"created_at"`
	MeiVersion  string    `json:"mei_version"`
	DatabaseSHA string    `json:"database_sha256"`
	Repos       []string  `json:"repos"`
	Keys        bool      `json:"includes_keys"`
}

const (
	backupFormat = 1
	backupDBName = "meiosisd.db"
)

// keyFiles are the secrets a backup leaves out unless asked.
var keyFiles = []string{"human.private.key", "human.public.key", "agent.private.key", "agent.public.key"}

func newBackupCommand(settings *Settings) *cobra.Command {
	var dbPath, reposDir string
	var includeKeys bool
	cmd := &cobra.Command{
		Use:   "backup <directory>",
		Short: "Write a consistent backup of the database and the served repositories",
		Long: `Writes a backup to a new (or empty) directory, safe to take while the server is
running:

  meiosisd.db     a snapshot taken inside one transaction, not a file copy
  git/NAME.git    a mirror clone of each served repository
  config.yaml     the repository's meiosis config
  MANIFEST.json   what it holds, with the database's SHA-256

Keys are secrets and are NOT included unless --include-keys is given. Without
them a restore keeps every record verifiable (public keys travel in the
records' tokens) but cannot sign new ones, so back the keys up separately.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root, err := repoRoot(settings)
			if err != nil {
				return err
			}
			meiosis := filepath.Join(root, ".meiosis")
			if dbPath == "" {
				dbPath = filepath.Join(meiosis, "meiosisd.db")
			}
			if reposDir == "" {
				reposDir = filepath.Join(meiosis, "git")
			}
			dest, err := filepath.Abs(args[0])
			if err != nil {
				return err
			}
			if err = requireEmptyDir(dest); err != nil {
				return err
			}
			if _, statErr := os.Stat(dbPath); statErr != nil {
				return fmt.Errorf("no database at %s: nothing to back up", dbPath)
			}

			store, err := sqlite.Open(dbPath)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close() }()
			dbDest := filepath.Join(dest, backupDBName)
			if err = store.Backup(context.Background(), dbDest); err != nil {
				return err
			}
			sum, err := fileSHA(dbDest)
			if err != nil {
				return err
			}

			manifest := backupManifest{Format: backupFormat, CreatedAt: time.Now().UTC(), MeiVersion: Version, DatabaseSHA: sum, Keys: includeKeys}
			entries, _ := os.ReadDir(reposDir)
			for _, e := range entries {
				if !e.IsDir() || !strings.HasSuffix(e.Name(), ".git") {
					continue
				}
				if cloneErr := mirror(cmd.Context(), filepath.Join(reposDir, e.Name()), filepath.Join(dest, "git", e.Name())); cloneErr != nil {
					return cloneErr
				}
				manifest.Repos = append(manifest.Repos, e.Name())
			}
			if data, readErr := os.ReadFile(filepath.Join(meiosis, "config.yaml")); readErr == nil {
				if err = os.WriteFile(filepath.Join(dest, "config.yaml"), data, 0o644); err != nil { //nolint:gosec // world-readable by design: not secret
					return err
				}
			}
			if includeKeys {
				for _, k := range keyFiles {
					data, readErr := os.ReadFile(filepath.Join(meiosis, k))
					if readErr != nil {
						continue
					}
					if err = os.MkdirAll(filepath.Join(dest, "keys"), 0o700); err != nil {
						return err
					}
					if err = os.WriteFile(filepath.Join(dest, "keys", k), data, 0o600); err != nil { //nolint:gosec // k is one of the fixed key file names
						return err
					}
				}
			}
			encoded, err := json.MarshalIndent(manifest, "", "  ")
			if err != nil {
				return err
			}
			if err = os.WriteFile(filepath.Join(dest, "MANIFEST.json"), encoded, 0o644); err != nil { //nolint:gosec // world-readable by design: not secret
				return err
			}
			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "backup written to %s\n  database sha256 %s\n  repositories    %d\n", dest, sum[:16]+"…", len(manifest.Repos))
			if !includeKeys {
				_, _ = fmt.Fprintln(out, "  keys            NOT included (back up .meiosis/*.private.key separately, or use --include-keys)")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "database to back up (default: <repo>/.meiosis/meiosisd.db)")
	cmd.Flags().StringVar(&reposDir, "repos-dir", "", "served repositories (default: <repo>/.meiosis/git)")
	cmd.Flags().BoolVar(&includeKeys, "include-keys", false, "also copy the private keys (the backup then holds secrets: protect it)")
	return cmd
}

func newRestoreCommand(settings *Settings) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "restore <backup-directory>",
		Short: "Restore a backup made by `mei backup` into this repository's .meiosis directory",
		Long: `Checks the backup against its manifest (the database's SHA-256 and SQLite's
integrity check) before changing anything, then copies the database, the
repositories and, if the backup has them, the keys into <repo>/.meiosis.
It refuses to overwrite an existing database unless --force is given.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root, err := repoRoot(settings)
			if err != nil {
				return err
			}
			src, err := filepath.Abs(args[0])
			if err != nil {
				return err
			}
			var manifest backupManifest
			data, err := os.ReadFile(filepath.Join(src, "MANIFEST.json"))
			if err != nil {
				return fmt.Errorf("%s is not a meiosis backup: %w", src, err)
			}
			if err = json.Unmarshal(data, &manifest); err != nil || manifest.Format != backupFormat {
				return fmt.Errorf("unsupported backup manifest (format %d)", manifest.Format)
			}
			dbSrc := filepath.Join(src, backupDBName)
			sum, err := fileSHA(dbSrc)
			if err != nil {
				return err
			}
			if sum != manifest.DatabaseSHA {
				return fmt.Errorf("the backup's database does not match its manifest (sha256 %s, expected %s): it was altered or damaged", sum[:16], manifest.DatabaseSHA[:16])
			}
			meiosis := filepath.Join(root, ".meiosis")
			dbDest := filepath.Join(meiosis, "meiosisd.db")
			if _, statErr := os.Stat(dbDest); statErr == nil && !force {
				return fmt.Errorf("%s already exists: restoring over it would lose what it holds; move it aside or pass --force", dbDest)
			}
			if err = os.MkdirAll(meiosis, 0o700); err != nil {
				return err
			}
			// Check a copy, never the backup itself: opening a SQLite file can change it
			// (its journal mode, its schema), and a backup must stay exactly as written.
			staged := dbDest + ".restoring"
			defer func() { _ = os.Remove(staged) }()
			if err = copyFile(dbSrc, staged, 0o600); err != nil {
				return err
			}
			check, err := sqlite.Open(staged)
			if err != nil {
				return fmt.Errorf("open the backup's database: %w", err)
			}
			problems, err := check.IntegrityCheck(context.Background())
			_ = check.Close()
			if err != nil || len(problems) > 0 {
				return fmt.Errorf("the backup's database failed SQLite's integrity check: %v %w", problems, err)
			}
			for _, suffix := range []string{"", "-wal", "-shm"} {
				_ = os.Remove(dbDest + suffix)
			}
			for _, suffix := range []string{"-wal", "-shm"} {
				_ = os.Remove(staged + suffix)
			}
			if err = os.Rename(staged, dbDest); err != nil {
				return err
			}
			for _, name := range manifest.Repos {
				target := filepath.Join(meiosis, "git", name)
				if err = os.RemoveAll(target); err != nil {
					return err
				}
				if err = mirror(cmd.Context(), filepath.Join(src, "git", name), target); err != nil {
					return err
				}
				if err = gitops.InitBare(cmd.Context(), "", target); err != nil {
					return err
				}
			}
			restoredKeys := 0
			for _, k := range keyFiles {
				from := filepath.Join(src, "keys", k)
				if _, statErr := os.Stat(from); statErr == nil {
					if err = copyFile(from, filepath.Join(meiosis, k), 0o600); err != nil {
						return err
					}
					restoredKeys++
				}
			}
			if _, statErr := os.Stat(filepath.Join(meiosis, "config.yaml")); statErr != nil {
				if cfg, readErr := os.ReadFile(filepath.Join(src, "config.yaml")); readErr == nil {
					_ = os.WriteFile(filepath.Join(meiosis, "config.yaml"), cfg, 0o644) //nolint:gosec // world-readable by design: not secret
				}
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "restored %s: database, %d repositor(ies), %d key file(s)\n", src, len(manifest.Repos), restoredKeys)
			return err
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing database")
	return cmd
}

func requireEmptyDir(dir string) error {
	entries, err := os.ReadDir(dir)
	switch {
	case os.IsNotExist(err):
		return os.MkdirAll(dir, 0o700)
	case err != nil:
		return err
	case len(entries) > 0:
		return fmt.Errorf("%s is not empty: a backup goes in a new directory", dir)
	}
	return nil
}

// mirror clones src to dest as a bare mirror, which git does consistently even
// while src is being pushed to.
func mirror(ctx context.Context, src, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return err
	}
	out, err := exec.CommandContext(ctx, "git", "clone", "--mirror", "--quiet", src, dest).CombinedOutput()
	if err != nil {
		return fmt.Errorf("git clone --mirror %s: %w: %s", src, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func fileSHA(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyFile(from, to string, perm os.FileMode) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err = io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
