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
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// ErrSymlink is returned when a swap target, or its parent, is a symlink.
var ErrSymlink = errors.New("refusing to operate on a symlink")

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

// CommandTimeout bounds every remote command. Without it a black-holed
// connection — a closed laptop lid, a VPN flap, a NAT rebind, none of which
// produce a RST — hangs the transaction forever inside sess.Run:
// ssh.ClientConfig.Timeout covers only the dial and handshake, and nothing
// deadlines the session afterwards. A hang mid-transaction is worse than an
// error, because the abort that would put the host back never runs.
var CommandTimeout = 60 * time.Second

// Run executes script under `sh -c` and returns stdout. stdin may be nil.
// It never blocks longer than CommandTimeout.
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

	done := make(chan error, 1)
	go func() { done <- sess.Run("sh -c " + Quote(script)) }()
	select {
	case err = <-done:
	case <-time.After(CommandTimeout):
		// Closing the session unblocks the goroutine's Run.
		_ = sess.Close()
		return stdout.Bytes(), fmt.Errorf("run %q: no response within %s — treating the connection as dead", script, CommandTimeout)
	}
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
	Exists    bool
	IsSymlink bool // target is a symlink — callers must refuse to swap it
	UID       string
	GID       string
	Mode      string // octal, e.g. "600"
}

// statScript exit codes: 8 = path is a symlink, 9 = path is absent. Both are
// distinct from a real failure. `stat` is deliberately NOT given -L: a symlink
// reports its own mode (0777 on GNU, 0755 on BSD), so dereferencing here would
// silently hand that mode to the swap. Symlinks are refused instead.
const statScript = `if [ -L %[1]s ]; then exit 8; elif [ -e %[1]s ]; then (stat -c '%%u %%g %%a' %[1]s 2>/dev/null || stat -f '%%u %%g %%OLp' %[1]s); else exit 9; fi`

// Stat returns ownership/mode for path, handling both GNU and BSD stat.
// A symlinked path returns IsSymlink without an error, for the caller to reject.
func Stat(c *ssh.Client, path string) (FileInfo, error) {
	out, err := Run(c, fmt.Sprintf(statScript, Quote(path)), nil)
	if err != nil {
		if ee, ok := err.(*ExitError); ok && ee.Status == 8 {
			return FileInfo{Exists: true, IsSymlink: true}, nil
		}
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
	// RunAs drops privileges to this user for the whole write. Set it
	// whenever the guard is root and the target file belongs to someone
	// else: the write then happens with the file owner's own credentials,
	// so a symlink planted in their directory cannot reach anything they
	// could not already reach, and no chown is needed.
	RunAs string
}

var (
	validMode   = regexp.MustCompile(`^[0-7]{3,4}$`)
	validNumber = regexp.MustCompile(`^[0-9]+$`)
)

// validate rejects attribute values before they reach a remote shell. They are
// interpolated as bare words, and on the `restore` path they come from a
// meta.json the operator may not have written.
func (o WriteOpts) validate() error {
	if !validMode.MatchString(o.Mode) {
		return fmt.Errorf("refusing mode %q: want 3-4 octal digits", o.Mode)
	}
	if o.UID != "" && (!validNumber.MatchString(o.UID) || !validNumber.MatchString(o.GID)) {
		return fmt.Errorf("refusing uid/gid %q:%q: want numeric", o.UID, o.GID)
	}
	if o.RunAs != "" && !ValidUsername(o.RunAs) {
		return fmt.Errorf("refusing run-as user %q", o.RunAs)
	}
	return nil
}

// SwapFile atomically replaces path with content: write a temp file in the
// target directory, set owner+mode, rename over the target.
//
// The temp file is created by mktemp — an atomic O_EXCL create under an
// unpredictable name, so there is no pre-existing path for a planted symlink to
// redirect the write through — and both the target and its parent are refused
// if they are symlinks. The fixed, predictable temp name this used to employ
// needed no race at all to hijack.
func SwapFile(c *ssh.Client, path string, content []byte, opts WriteOpts) error {
	if opts.Mode == "" {
		opts.Mode = "600"
	}
	if err := opts.validate(); err != nil {
		return err
	}
	q := Quote(path)
	dir := Quote(dirOf(path))
	var b strings.Builder
	b.WriteString("umask 077; ")
	// Never follow a symlink at the target or its parent.
	fmt.Fprintf(&b, "if [ -L %s ]; then echo 'refusing: %s is a symlink' >&2; exit 8; fi; ", q, path)
	fmt.Fprintf(&b, "if [ -L %s ]; then echo 'refusing: parent directory is a symlink' >&2; exit 8; fi; ", dir)
	if opts.MkdirFor {
		// mkdir -p succeeds straight through a symlinked directory, so the
		// parent is created only when genuinely absent, and never chowned:
		// a shared directory (--path /etc/ssh/authorized_keys.d/%u) must not
		// change hands just because one user's file was created in it.
		fmt.Fprintf(&b, "if [ ! -d %s ]; then mkdir -p %s && chmod 700 %s || exit 1; fi; ", dir, dir, dir)
	}
	fmt.Fprintf(&b, "t=$(mktemp %s/.sshkeytx.XXXXXXXX) || exit 1; ", dir)
	b.WriteString(`cat > "$t" && chmod ` + Quote(opts.Mode) + ` "$t" && `)
	if opts.UID != "" && opts.RunAs == "" {
		fmt.Fprintf(&b, "chown %s:%s \"$t\" && ", Quote(opts.UID), Quote(opts.GID))
	}
	fmt.Fprintf(&b, "mv -f \"$t\" %s || { rm -f \"$t\"; exit 1; }", q)

	_, err := Run(c, dropPrivileges(b.String(), opts.RunAs), content)
	return err
}

// dropPrivileges wraps script so it runs as user, when one is named. runuser
// is the util-linux tool present on Linux servers; su is the POSIX-ish
// fallback. Both keep stdin attached, which is how file content travels.
func dropPrivileges(script, user string) string {
	if user == "" {
		return script
	}
	inner := Quote(script)
	return fmt.Sprintf(
		`if command -v runuser >/dev/null 2>&1; then exec runuser -u %[1]s -- /bin/sh -c %[2]s; `+
			`else exec su %[1]s -s /bin/sh -c %[2]s; fi`,
		user, inner)
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

// MkTxDir creates the remote transaction directory under tmpBase. mktemp -d is
// atomic and O_EXCL by construction, so a pre-planted name in a world-writable
// /tmp cannot capture the backups the dead-man trap restores from.
func MkTxDir(c *ssh.Client, tmpBase, txid string) (string, error) {
	script := fmt.Sprintf("umask 077; d=$(mktemp -d %s/sshkeytx-%s.XXXXXXXX) || exit 1; mkdir \"$d/backup\" && printf '%%s' \"$d\"", Quote(tmpBase), txid)
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

// DirOf is dirOf for callers outside this package, which need to stat a
// target's parent directory to decide how to write it (see DecideWriteOpts).
func DirOf(path string) string { return dirOf(path) }

// dirWritableByOthers reports whether an octal mode grants write to group or
// other. A directory anyone but root can write into is a directory root must
// not write into on someone's behalf, sticky bit or not: the sticky bit stops
// unlinking OTHER people's files, and every file this tool writes is created
// under a name it chose itself in that same directory.
func dirWritableByOthers(mode string) bool {
	if len(mode) < 3 {
		return true // unparseable — assume the unsafe answer
	}
	last := mode[len(mode)-3:]
	group, other := last[1], last[2]
	if group < '0' || group > '7' || other < '0' || other > '7' {
		return true
	}
	return (group-'0')&2 != 0 || (other-'0')&2 != 0
}

// WriteTarget is everything DecideWriteOpts needs to judge one write.
type WriteTarget struct {
	GuardIsRoot bool     // the guard connection's uid is 0
	GuardUser   string   // the user the guard authenticated as
	EntryUser   string   // the authorized_keys entry's owner-to-be
	EntryUID    string   // EntryUser's numeric uid
	EntryGID    string   // EntryUser's numeric gid
	File        FileInfo // the target file, pre-transaction
	Dir         FileInfo // the target's PARENT DIRECTORY
}

// DecideWriteOpts is the single place that decides whether a privileged write
// drops privileges. Both `apply` (tx.writeOpts) and `restore` route through it,
// because they diverged once and the recovery half was the broken one.
//
// THE PREDICATE IS THE PARENT DIRECTORY, NOT THE FILE.
//
// The drop exists for one reason (see the package doc): root must not write
// into a directory its owner controls, because that owner can arrange for the
// write to land somewhere else. That is a property of the DIRECTORY. Keying it
// on the file's owner — as 355ed68 did on the username, and as the first fix
// did on the file's uid — gets the common cases right and the interesting ones
// wrong in both directions:
//
//   - root-owned file in a user-owned home (an admin's `sudo cp`, or any
//     config-management tool that forgot to chown) took the ROOT path, which
//     is the escalation the drop was written to prevent;
//   - root-owned file in a root-owned directory (NixOS renders
//     /etc/ssh/authorized_keys.d/<user> as root:root 444) took the DROP path,
//     where mktemp cannot succeed, so neither the edit nor the revert could
//     ever land.
//
// Directory ownership answers both at once, and it answers the absent-file
// case too — which the file's own ownership cannot, there being no file to
// stat. So this function needs no special case for creation.
func DecideWriteOpts(t WriteTarget) WriteOpts {
	opts := WriteOpts{}
	if t.File.Exists {
		opts.Mode = t.File.Mode
	} else {
		opts.Mode = "600"
		opts.MkdirFor = true
	}

	// A non-root guard can neither drop nor chown; it writes as itself.
	if !t.GuardIsRoot {
		return opts
	}

	// Writing the guard's own file: nobody to drop to.
	if t.EntryUser != t.GuardUser {
		// A directory root owns and only root can write is a directory the
		// entry user could never have written to — dropping there guarantees
		// EACCES. Anywhere else, the entry user may control the directory, so
		// the write happens with their own credentials and reaches nothing
		// they could not already reach.
		rootManaged := t.Dir.Exists && t.Dir.UID == "0" && !dirWritableByOthers(t.Dir.Mode)
		if !rootManaged {
			opts.RunAs = t.EntryUser
			return opts
		}
	}

	// Root writes it. Preserve the file's ownership if it had one; a file
	// being created belongs to the entry user.
	if t.File.Exists {
		opts.UID, opts.GID = t.File.UID, t.File.GID
	} else {
		opts.UID, opts.GID = t.EntryUID, t.EntryGID
	}
	return opts
}
