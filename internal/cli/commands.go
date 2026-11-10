package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

func newActionCommand(name, short string, settings *Settings) *cobra.Command {
	return &cobra.Command{
		Use:   name,
		Short: short,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if settings.Format == "json" {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
					"command": name,
					"repo":    settings.Repo,
				})
			}
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", name, settings.Repo)
			return err
		},
	}
}

func newCompletionCommand() *cobra.Command {
	completion := &cobra.Command{
		Use:   "completion",
		Short: "Generate shell completion scripts",
	}
	completion.AddCommand(
		&cobra.Command{
			Use:   "bash",
			Short: "Generate Bash completion",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				return cmd.Root().GenBashCompletion(cmd.OutOrStdout())
			},
		},
		&cobra.Command{
			Use:   "zsh",
			Short: "Generate Zsh completion",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				return cmd.Root().GenZshCompletion(cmd.OutOrStdout())
			},
		},
	)
	return completion
}
