package cmd

import (
	"context"
	"errors"
	"fmt"
)

func validateNoSessionOptions(noSession, forwardAgent bool, command []string) error {
	if !noSession {
		return nil
	}
	if len(command) != 0 {
		return errors.New("-no-session cannot be combined with a remote command")
	}
	if forwardAgent {
		return errors.New("-no-session cannot be combined with -forward-agent because agent forwarding requires a session channel")
	}
	return nil
}

// waitWithoutSession keeps a forwarding-only connection alive without
// opening a session channel. A local shutdown signal is a successful,
// intentional termination; losing the SSH3 conversation is an error.
func waitWithoutSession(connectionCtx, shutdownCtx context.Context) error {
	select {
	case <-shutdownCtx.Done():
		return nil
	case <-connectionCtx.Done():
		cause := context.Cause(connectionCtx)
		if cause == nil {
			cause = connectionCtx.Err()
		}
		return fmt.Errorf("SSH3 connection closed: %w", cause)
	}
}
