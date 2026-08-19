package tx

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/caoer/sshkeytx/internal/remote"
)

// guardReadyToken is printed by the guard script once its trap is armed.
// Nothing is mutated on the remote before this token is observed.
const guardReadyToken = "SSHKEYTX_GUARD_READY"

// guardScript is the dead-man switch. It runs inside the held guard session
// for the whole transaction:
//
//   - It arms a trap BEFORE any file is touched. If the session ends without
//     $TX/commit existing — connection death, sshd shutdown, signal — the trap
//     restores every file named in $TX/manifest from its remote backup copy
//     and drops $TX/restored as evidence.
//   - Restoration is `cat backup > target`: it overwrites content in place,
//     preserving the target's inode, owner and mode.
//   - It then signals readiness and blocks on stdin. Closing stdin is the
//     graceful shutdown; after a committed transaction the trap sees
//     $TX/commit and restores nothing.
//
// Manifest format, one file per line, tab-separated:
//
//	F <tab> backup-path <tab> target-path   (restore = overwrite content)
//	A <tab> -           <tab> target-path   (target was absent; restore = delete)
func guardScript(txdir string) string {
	q := remote.Quote(txdir)
	tab := "\t"
	return strings.Join([]string{
		"TX=" + q,
		`restore_all() {`,
		`  [ -f "$TX/commit" ] && return 0`,
		`  if [ -f "$TX/manifest" ]; then`,
		`    while IFS='` + tab + `' read -r typ bak dst; do`,
		// The trap restores as root, and `>` follows symlinks. SwapFile
		// refuses a symlinked target and a symlinked parent; the trap did not,
		// so a user who controls the directory could swap the target for a
		// link mid-transaction and have root write the backup content through
		// it. The two halves of one transaction must agree about who may write
		// where. A refusal is recorded, never silent.
		`      case "$typ" in`,
		`        F) if [ -L "$dst" ] || [ -L "$(dirname "$dst")" ]; then`,
		`             printf '%s\n' "$dst" >> "$TX/restore-refused"`,
		`           elif [ -f "$bak" ]; then cat "$bak" > "$dst"; fi ;;`,
		`        A) [ -L "$dst" ] && printf '%s\n' "$dst" >> "$TX/restore-refused" || rm -f "$dst" ;;`,
		`      esac`,
		`    done < "$TX/manifest"`,
		`    : > "$TX/restored"`,
		`  fi`,
		`  return 0`,
		`}`,
		`trap restore_all EXIT`,
		`trap 'restore_all; trap - EXIT; exit 129' HUP`,
		`trap 'restore_all; trap - EXIT; exit 130' INT`,
		`trap 'restore_all; trap - EXIT; exit 143' TERM`,
		`: > "$TX/ready"`,
		`echo ` + guardReadyToken,
		`cat > /dev/null`,
	}, "\n")
}

// guard is the held session running guardScript.
type guard struct {
	sess  *ssh.Session
	stdin io.WriteCloser

	mu      sync.Mutex
	exited  bool
	exitErr error
	stderr  syncBuf
}

// syncBuf is a bytes.Buffer safe for the ssh library's stderr-copy goroutine
// to write while startGuard's failure paths read it. Those reads happen while
// the copier is still live; only closeGraceful's read is ordered after Wait.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// startGuard opens the guard session on client and blocks until the remote
// trap is armed (readiness token observed) or timeout.
func startGuard(client *ssh.Client, txdir string, timeout time.Duration) (*guard, error) {
	sess, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("guard: open session: %w", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		sess.Close()
		return nil, fmt.Errorf("guard: stdin pipe: %w", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		sess.Close()
		return nil, fmt.Errorf("guard: stdout pipe: %w", err)
	}
	g := &guard{sess: sess, stdin: stdin}
	sess.Stderr = &g.stderr

	if err := sess.Start("sh -c " + remote.Quote(guardScript(txdir))); err != nil {
		sess.Close()
		return nil, fmt.Errorf("guard: start: %w", err)
	}

	ready := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if strings.TrimSpace(scanner.Text()) == guardReadyToken {
				ready <- nil
				// Keep draining so the remote never blocks on stdout.
				for scanner.Scan() {
				}
				return
			}
		}
		ready <- fmt.Errorf("guard: stdout closed before readiness token (stderr: %s)", strings.TrimSpace(g.stderr.String()))
	}()
	go func() {
		err := sess.Wait()
		g.mu.Lock()
		g.exited, g.exitErr = true, err
		g.mu.Unlock()
	}()

	select {
	case err := <-ready:
		if err != nil {
			sess.Close()
			return nil, err
		}
	case <-time.After(timeout):
		sess.Close()
		return nil, fmt.Errorf("guard: no readiness token within %s (stderr: %s)", timeout, strings.TrimSpace(g.stderr.String()))
	}
	return g, nil
}

// alive reports whether the guard session is still running.
func (g *guard) alive() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return !g.exited
}

// closeGraceful ends the guard by closing its stdin (EOF → script exits →
// trap runs; with $TX/commit present it restores nothing) and waits for the
// session to end.
func (g *guard) closeGraceful(timeout time.Duration) error {
	_ = g.stdin.Close()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		g.mu.Lock()
		exited, exitErr := g.exited, g.exitErr
		g.mu.Unlock()
		if exited {
			if exitErr != nil {
				return fmt.Errorf("guard exited with error: %w (stderr: %s)", exitErr, strings.TrimSpace(g.stderr.String()))
			}
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	g.sess.Close()
	return fmt.Errorf("guard did not exit within %s after stdin close", timeout)
}
