package cmd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	cmxsafeUsernameEnv  = "CMXSAFE_USERNAME"
	cmxsafeSessionIDEnv = "CMXSAFE_SESSION_ID"
	cmxsafeSessionIDLen = 32
)

type sessionHookCommand func(context.Context, string, []string) error

type cmxsafeSessionHooks struct {
	startPath string
	endPath   string
	timeout   time.Duration
	random    io.Reader
	run       sessionHookCommand
}

func newCMXsafeSessionHooks(startPath, endPath string, timeout time.Duration) *cmxsafeSessionHooks {
	if startPath == "" && endPath == "" {
		return nil
	}
	return &cmxsafeSessionHooks{
		startPath: startPath,
		endPath:   endPath,
		timeout:   timeout,
		random:    rand.Reader,
		run:       runSessionHookCommand,
	}
}

func runSessionHookCommand(ctx context.Context, path string, environment []string) error {
	command := exec.CommandContext(ctx, path)
	command.Env = environment
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return command.Run()
}

func sessionHookEnvironment(username, sessionID string) []string {
	environment := os.Environ()
	filtered := environment[:0]
	for _, entry := range environment {
		if strings.HasPrefix(entry, cmxsafeUsernameEnv+"=") ||
			strings.HasPrefix(entry, cmxsafeSessionIDEnv+"=") {
			continue
		}
		filtered = append(filtered, entry)
	}
	return append(filtered,
		cmxsafeUsernameEnv+"="+username,
		cmxsafeSessionIDEnv+"="+sessionID,
	)
}

func (hooks *cmxsafeSessionHooks) newSessionID() (string, error) {
	randomBytes := make([]byte, cmxsafeSessionIDLen)
	if _, err := io.ReadFull(hooks.random, randomBytes); err != nil {
		return "", errors.New("could not create CMXsafe session identifier")
	}
	return hex.EncodeToString(randomBytes), nil
}

func (hooks *cmxsafeSessionHooks) execute(parent context.Context, path, username, sessionID string) error {
	ctx, cancel := context.WithTimeout(parent, hooks.timeout)
	defer cancel()
	err := hooks.run(ctx, path, sessionHookEnvironment(username, sessionID))
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func (hooks *cmxsafeSessionHooks) begin(ctx context.Context, username string) (func(), error) {
	if hooks == nil {
		return func() {}, nil
	}

	sessionID, err := hooks.newSessionID()
	if err != nil {
		return nil, err
	}

	// The end hook is deliberately registered before start. A failed or timed
	// out start may have made a partial external allocation, so it receives the
	// same opaque lease ID exactly once for cleanup.
	var finishOnce sync.Once
	finish := func() {
		finishOnce.Do(func() {
			if hooks.endPath == "" {
				return
			}
			endContext := context.Background()
			if err := hooks.execute(endContext, hooks.endPath, username, sessionID); err != nil {
				reason := "failed"
				if errors.Is(err, context.DeadlineExceeded) {
					reason = "timeout"
				}
				log.Error().Str("hook", "end").Str("reason", reason).
					Msg("CMXsafe session hook did not complete")
			}
		})
	}

	if hooks.startPath != "" {
		if err := hooks.execute(ctx, hooks.startPath, username, sessionID); err != nil {
			finish()
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return nil, errors.New("CMXsafe session start hook timed out")
			}
			return nil, errors.New("CMXsafe session start hook failed")
		}
	}

	return finish, nil
}

func (hooks *cmxsafeSessionHooks) runConversation(ctx context.Context, username string, conversation func() error) error {
	finish, err := hooks.begin(ctx, username)
	if err != nil {
		return err
	}
	defer finish()
	return conversation()
}

func validateCMXsafeSessionHookConfiguration(gatewayName, startPath, endPath string, timeout time.Duration) error {
	if startPath == "" && endPath == "" {
		return nil
	}
	if gatewayName == "" {
		return errors.New("CMXsafe session hooks require -cmxsafe-gateway-name")
	}
	if timeout <= 0 {
		return fmt.Errorf("CMXsafe session hook timeout must be greater than zero")
	}
	for _, hookPath := range []string{startPath, endPath} {
		if hookPath != "" && (!filepath.IsAbs(hookPath) || filepath.Clean(hookPath) != hookPath) {
			return errors.New("CMXsafe session hook paths must be clean absolute paths")
		}
	}
	return nil
}
