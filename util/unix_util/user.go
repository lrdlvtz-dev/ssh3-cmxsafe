package unix_util

import (
	"fmt"
	"io"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

type User struct {
	Username string
	Uid      uint64
	Gid      uint64
	Groups   []uint64
	Dir      string
	Shell    string
}

func GetUser(username string) (*User, error) {
	u, err := getUser(username)
	if err != nil {
		return nil, err
	}
	account, err := osuser.Lookup(username)
	if err != nil {
		return nil, fmt.Errorf("lookup supplementary groups for %s: %w", username, err)
	}
	groupIDs, err := account.GroupIds()
	if err != nil {
		return nil, fmt.Errorf("lookup supplementary groups for %s: %w", username, err)
	}
	for _, groupID := range groupIDs {
		gid, err := strconv.ParseUint(groupID, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse supplementary gid %q for %s: %w", groupID, username, err)
		}
		u.Groups = append(u.Groups, gid)
	}
	return u, nil
}

func (u *User) credential() (*syscall.Credential, error) {
	const maxUint32 = uint64(^uint32(0))
	if u.Uid > maxUint32 || u.Gid > maxUint32 {
		return nil, fmt.Errorf("uid/gid for %s exceeds operating-system credential range", u.Username)
	}
	groups := make([]uint32, 0, len(u.Groups))
	for _, group := range u.Groups {
		if group > maxUint32 {
			return nil, fmt.Errorf("supplementary gid %d for %s exceeds operating-system credential range", group, u.Username)
		}
		groups = append(groups, uint32(group))
	}
	return &syscall.Credential{Uid: uint32(u.Uid), Gid: uint32(u.Gid), Groups: groups}, nil
}

func (u *User) CreateCommand(addEnv string, stdout, stderr io.Writer, stdin io.Reader, loginShell bool, command string, args ...string) (*exec.Cmd, io.Reader, io.Reader, io.Writer, error) {
	cmd := exec.Command(command, args...)
	cmd.Env = append(cmd.Env, addEnv)
	cmd.Dir = u.Dir

	if loginShell {
		// from man bash: A  login shell is one whose first character of argument zero is a -, or
		// 				  one started with the --login option.
		// We chose to start it with a preprended "-"
		cmd.Args[0] = fmt.Sprintf("-%s", filepath.Base(cmd.Args[0]))
	}

	credential, err := u.credential()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: credential}

	var stdoutR, stderrR io.Reader
	var stdinW io.Writer

	if stdout == nil {
		stdoutR, err = cmd.StdoutPipe()
		if err != nil {
			return nil, nil, nil, nil, err
		}
	} else {
		cmd.Stdout = stdout
	}
	if stderr == nil {
		stderrR, err = cmd.StderrPipe()
		if err != nil {
			return nil, nil, nil, nil, err
		}
	} else {
		cmd.Stderr = stderr
	}
	if stdin == nil {
		stdinW, err = cmd.StdinPipe()
		if err != nil {
			return nil, nil, nil, nil, err
		}
	} else {
		cmd.Stdin = stdin
	}

	return cmd, stdoutR, stderrR, stdinW, err
}

func (u *User) CreateCommandPipeOutput(addEnv string, loginShell bool, command string, args ...string) (*exec.Cmd, io.Reader, io.Reader, io.Writer, error) {
	return u.CreateCommand(addEnv, nil, nil, nil, loginShell, command, args...)
}

/*
 *  Returns a boolean stating whether the user is correctly authenticated on this
 *  server. May return a UserNotFound error when the user does not exist.
 */
func UserPasswordAuthentication(username, password string) (bool, error) {
	return userPasswordAuthentication(username, password)
}

func PasswordAuthAvailable() bool {
	return passwordAuthAvailable()
}
