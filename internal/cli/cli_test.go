package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func execute(t *testing.T, args ...string) string {
	t.Helper()
	command := New(nil)
	var output strings.Builder
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetArgs(args)
	if err := command.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	return output.String()
}

func TestCommandsExecute(t *testing.T) {
	for _, name := range []string{"intent", "attempt", "evidence"} {
		t.Run(name, func(t *testing.T) {
			if output := execute(t, name); !strings.Contains(output, name) {
				t.Fatalf("output = %q, want command name", output)
			}
		})
	}
}

func TestVersionCommand(t *testing.T) {
	old := Version
	defer func() { Version = old }()
	Version = "v1.2.3"
	if output := execute(t, "version"); !strings.Contains(output, "mei v1.2.3") {
		t.Fatalf("output = %q, want stamped version", output)
	}
}

func TestConfigurationPrecedence(t *testing.T) {
	directory := t.TempDir()
	configDirectory := filepath.Join(directory, ".meiosis")
	if err := os.Mkdir(configDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(configDirectory, "config.yaml")
	if err := os.WriteFile(configPath, []byte("repo: from-file\nformat: json\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(directory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldDirectory) })
	t.Setenv("MEIOSIS_REPO", "from-env")

	command := New(nil)
	var output strings.Builder
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetArgs([]string{"intent", "--repo", "from-flag"})
	if err := command.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !strings.Contains(output.String(), `"repo":"from-flag"`) {
		t.Fatalf("output = %q, want CLI flag to win", output.String())
	}
}

func TestCompletionCommands(t *testing.T) {
	for _, shell := range []string{"bash", "zsh"} {
		t.Run(shell, func(t *testing.T) {
			command := New(nil)
			var output strings.Builder
			command.SetOut(&output)
			command.SetErr(&output)
			command.SetArgs([]string{"completion", shell})
			if err := command.Execute(); err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			if output.Len() == 0 {
				t.Fatal("completion output is empty")
			}
		})
	}
}
