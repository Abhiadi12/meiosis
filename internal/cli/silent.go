package cli

import "errors"

// silentError is a failure whose reason has already been shown to the user, so
// the entry point should exit non-zero without printing it again. The receive
// hooks use it: a push rejection is explained on the lines git relays to the
// pusher.
type silentError struct{ error }

// IsSilent reports whether err was already reported.
func IsSilent(err error) bool {
	var s silentError
	return errors.As(err, &s)
}
