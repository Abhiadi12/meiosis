package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/mindfire-test/meiosis/internal/pushhook"
)

// newHookCommand is what the receive hooks `mei serve` installs call. It is not
// meant to be run by hand.
func newHookCommand() *cobra.Command {
	hook := &cobra.Command{
		Use:    "hook",
		Short:  "Receive hooks run by git for a served repository (not for direct use)",
		Hidden: true,
	}
	for _, name := range []string{"pre-receive", "post-receive"} {
		hook.AddCommand(&cobra.Command{
			Use:    name,
			Short:  "Run the " + name + " policy",
			Hidden: true,
			Args:   cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				env, err := pushhook.EnvFromProcess()
				if err != nil {
					return err
				}
				updates, err := pushhook.ReadUpdates(cmd.InOrStdin())
				if err != nil {
					return err
				}
				out := cmd.ErrOrStderr()
				if name == "pre-receive" {
					err = pushhook.PreReceive(cmd.Context(), env, updates, out)
				} else {
					err = pushhook.PostReceive(cmd.Context(), env, updates, out)
				}
				if err == nil {
					return nil
				}
				var rejection *pushhook.RejectionError
				if errors.As(err, &rejection) {
					return silentError{err} // PreReceive already told the pusher why
				}
				_, _ = fmt.Fprintf(out, "meiosis: %s failed: %v\n", name, err)
				return silentError{err}
			},
		})
	}
	return hook
}
