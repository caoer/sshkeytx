// Package remote runs commands on the remote host over an established
// *ssh.Client. Every operation opens a session on the SAME underlying
// connection as the transaction guard, so any transport failure surfaces
// immediately instead of silently switching to a new connection.
//
// File content travels over session stdin/stdout (cat), never SFTP, so the
// only remote requirement is a POSIX sh and coreutils-level tools.
package remote

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Quote returns s as a POSIX single-quoted word, safe to embed in sh -c.
func Quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// validUser guards every username interpolated into a remote command.
var validUser = regexp.MustCompile(`^[a-zA-Z0-9._][a-zA-Z0-9._-]*$`)

// ValidUsername reports whether name is safe to use in remote commands.
func ValidUsername(name string) bool { return validUser.MatchString(name) }

// ExitError carries a remote command's failure with its stderr.
type ExitError struct {
	Cmd    string
	Status int
	Stderr string
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("remote command failed (exit %d): %s — stderr: %s", e.Status, e.Cmd, strings.TrimSpace(e.Stderr))
}

// Run executes script under `sh -c` and returns stdout. stdin may be nil.
func Run(c *ssh.Client, script string, stdin []byte) ([]byte, error) {
	sess, err := c.NewSession()
	if err != nil {
		return nil, fmt.Errorf("open session: %w", err)
	}
	defer sess.Close()
	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr
	if stdin != nil {
		sess.Stdin = bytes.NewReader(stdin)
	}
	err = sess.Run("sh -c " + Quote(script))
	if err != nil {
		if ee, ok := err.(*ssh.ExitError); ok {
			return stdout.Bytes(), &ExitError{Cmd: script, Status: ee.ExitStatus(), Stderr: stderr.String()}
		}
		return stdout.Bytes(), fmt.Errorf("run %q: %w — stderr: %s", script, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// FileInfo captures what a swap must preserve.
type FileInfo struct {
	Exists bool
	UID    string
	GID    string
	Mode   string // octal, e.g. "600"
}

// missingSentinel: exit 9 marks "path absent" distinctly from real failures.
const statScript = `if [ -e %[1]s ]; then (stat -c '%%u %%g %%a' %[1]s 2>/dev/null || stat -f '%%u %%g %%OLp' %[1]s); else exit 9; fi`

// Stat returns ownership/mode for path, handling both GNU and BSD stat.
func Stat(c *ssh.Client, path string) (FileInfo, error) {
	out, err := Run(c, fmt.Sprintf(statScript, Quote(path)), nil)
	if err != nil {
		if ee, ok := err.(*ExitError); ok && ee.Status == 9 {
			return FileInfo{Exists: false}, nil
		}
		return FileInfo{}, err
	}
	fields := strings.Fields(string(out))
	if len(fields) != 3 {
		return FileInfo{}, fmt.Errorf("stat %s: unparseable output %q", path, string(out))
	}
	return FileInfo{Exists: true, UID: fields[0], GID: fields[1], Mode: fields[2]}, nil
}

// ReadFile returns path's content. Absent files return exists=false, no error.
func ReadFile(c *ssh.Client, path string) (content []byte, exists bool, err error) {
	out, err := Run(c, fmt.Sprintf(`if [ -e %[1]s ]; then cat %[1]s; else exit 9; fi`, Quote(path)), nil)
	if err != nil {
		if ee, ok := err.(*ExitError); ok && ee.Status == 9 {
			return nil, false, nil
		}
		return nil, false, err
	}
	return out, true, nil
}

// WriteOpts controls SwapFile's attribute handling.
type WriteOpts struct {
	UID  string // chown target (numeric); empty = leave as created
	GID  string
	Mode string // octal; empty = 600
	// MkdirFor creates the parent directory (0700, owned per UID/GID)
	// when the target file does not exist yet.
	MkdirFor bool
}

// SwapFile atomically replaces path with content: write sibling temp file,
// set owner+mode, rename over the target. The temp file lives in the target
// directory so the rename never crosses filesystems.
func SwapFile(c *ssh.Client, path string, content []byte, opts WriteOpts) error {
	if opts.Mode == "" {
		opts.Mode = "600"
	}
	q := Quote(path)
	tmp := Quote(path + ".sshkeytx.tmp")
	var b strings.Builder
	b.WriteString("umask 077; ")
	if opts.MkdirFor {
		dir := Quote(dirOf(path))
		fmt.Fprintf(&b, "mkdir -p %s && chmod 700 %s && ", dir, dir)
		if opts.UID != "" {
			fmt.Fprintf(&b, "chown %s:%s %s && ", opts.UID, opts.GID, dir)
		}
	}
	fmt.Fprintf(&b, "cat > %s && chmod %s %s && ", tmp, opts.Mode, tmp)
	if opts.UID != "" {
		fmt.Fprintf(&b, "chown %s:%s %s && ", opts.UID, opts.GID, tmp)
	}
	fmt.Fprintf(&b, "mv -f %s %s", tmp, q)
	_, err := Run(c, b.String(), content)
	return err
}

// WriteFile writes content to path (no rename dance — for backups inside the
// transaction directory, where atomicity does not matter).
func WriteFile(c *ssh.Client, path string, content []byte) error {
	_, err := Run(c, fmt.Sprintf("umask 077; cat > %s", Quote(path)), content)
	return err
}

// AppendFile appends content to path (used for the trap manifest).
func AppendFile(c *ssh.Client, path string, content []byte) error {
	_, err := Run(c, fmt.Sprintf("umask 077; cat >> %s", Quote(path)), content)
	return err
}

// Remove deletes a path.
func Remove(c *ssh.Client, path string) error {
	_, err := Run(c, "rm -f "+Quote(path), nil)
	return err
}

// LookupUser resolves a username to numeric uid/gid and home directory.
func LookupUser(c *ssh.Client, name string) (uid, gid, home string, err error) {
	if !ValidUsername(name) {
		return "", "", "", fmt.Errorf("invalid username %q", name)
	}
	script := fmt.Sprintf(`uid=$(id -u %[1]s) && gid=$(id -g %[1]s) && home=$(eval echo ~%[1]s) && printf '%%s\n%%s\n%%s\n' "$uid" "$gid" "$home"`, name)
	out, err := Run(c, script, nil)
	if err != nil {
		return "", "", "", fmt.Errorf("lookup user %s: %w", name, err)
	}
	parts := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(parts) != 3 || parts[2] == "" || !strings.HasPrefix(parts[2], "/") {
		return "", "", "", fmt.Errorf("lookup user %s: unparseable id/home output %q", name, string(out))
	}
	return parts[0], parts[1], parts[2], nil
}

// Whoami returns `id -u` for the guard connection (to decide whether chown
// is possible).
func Whoami(c *ssh.Client) (uid string, err error) {
	out, err := Run(c, "id -u", nil)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// MkTxDir creates the remote transaction directory under tmpBase.
func MkTxDir(c *ssh.Client, tmpBase, txid string) (string, error) {
	script := fmt.Sprintf("umask 077; d=%s/sshkeytx-%s; mkdir -p \"$d/backup\" && printf '%%s' \"$d\"", Quote(tmpBase), txid)
	out, err := Run(c, script, nil)
	if err != nil {
		return "", fmt.Errorf("create tx dir: %w", err)
	}
	dir := strings.TrimSpace(string(out))
	if !strings.HasPrefix(dir, "/") {
		return "", fmt.Errorf("create tx dir: unexpected output %q", dir)
	}
	return dir, nil
}

func dirOf(path string) string {
	i := strings.LastIndex(path, "/")
	if i <= 0 {
		return "/"
	}
	return path[:i]
}
