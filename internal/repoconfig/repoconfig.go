// Package repoconfig reads the per-repository settings that `mei init` writes to
// .meiosis/config.yaml and decides how strictly a process enforces capability
// tokens. It has no dependency on the servers that use it.
package repoconfig

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

// ResolveEnforcement decides which issuer public key a process enforces
// capability tokens against, and whether the repository is strict. It returns
// an empty path only when the caller was explicitly told to run without
// enforcement.
//
// Enforcement is the default: with no explicit key the process looks for the
// human.public.key that `mei init` leaves next to the database, and refuses to
// start if there is none, rather than quietly accepting unauthenticated calls.
// Running without tokens takes an explicit opt-out, and a repository whose
// config says strict: true (FR-1.3) does not permit even that.
func ResolveEnforcement(explicit, dbPath string, allowUnauth bool, warn io.Writer) (issuerPath string, strict bool, err error) {
	dir := filepath.Dir(dbPath)
	strict = IsStrict(dir)
	if allowUnauth && strict {
		return "", true, fmt.Errorf("--allow-unauthenticated is refused: %s sets strict: true, so every call must carry a capability token", filepath.Join(dir, "config.yaml"))
	}
	if explicit != "" {
		return explicit, strict, nil
	}
	beside := filepath.Join(dir, "human.public.key")
	if _, statErr := os.Stat(beside); statErr == nil {
		return beside, strict, nil
	}
	if allowUnauth {
		if warn != nil {
			_, _ = fmt.Fprintln(warn, "WARNING: serving without capability enforcement (--allow-unauthenticated)")
		}
		return "", false, nil
	}
	return "", strict, fmt.Errorf("capability enforcement is required but there is no issuer key: pass --issuer-pubkey, run `mei init` so %s exists, or pass --allow-unauthenticated to opt out", beside)
}

// IsStrict reports whether the config in dir turns strict mode on. A
// missing or unreadable config means it does not.
func IsStrict(dir string) bool {
	cfg := viper.New()
	cfg.SetConfigFile(filepath.Join(dir, "config.yaml"))
	if err := cfg.ReadInConfig(); err != nil {
		return false
	}
	return cfg.GetBool("strict")
}

// SecretsMode reads the credential-scanning mode from the config in dir.
// A missing key means "warn".
func SecretsMode(dir string) string {
	cfg := viper.New()
	cfg.SetConfigFile(filepath.Join(dir, "config.yaml"))
	if err := cfg.ReadInConfig(); err != nil {
		return "warn"
	}
	if mode := cfg.GetString("secrets"); mode != "" {
		return mode
	}
	return "warn"
}
