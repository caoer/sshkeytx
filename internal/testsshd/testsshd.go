// Package testsshd runs an in-process SSH server for integration tests.
//
// It behaves like a minimal sshd: publickey auth is checked against a live
// per-user authorized_keys file inside a sandbox directory (re-read on every
// attempt, so edits take effect immediately — exactly what the verify phases
// depend on), and exec requests run through the real /bin/sh with stdin,
// stdout, stderr and exit codes wired.
package testsshd

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	glssh "github.com/gliderlabs/ssh"
	"golang.org/x/crypto/ssh"
)

// Server is the test sshd.
type Server struct {
	Addr    string // 127.0.0.1:port
	Sandbox string // sandbox root; per-user keys at <Sandbox>/keys/<user>/authorized_keys

	ln  net.Listener
	srv *glssh.Server
	wg  sync.WaitGroup
}

// KeysPath returns the authorized_keys path the server consults for user.
func (s *Server) KeysPath(user string) string {
	return filepath.Join(s.Sandbox, "keys", user, "authorized_keys")
}

// PathTemplate is the --path template matching KeysPath.
func (s *Server) PathTemplate() string {
	return filepath.Join(s.Sandbox, "keys", "%u", "authorized_keys")
}

// WriteKeys (re)writes a user's authorized_keys in the sandbox.
func (s *Server) WriteKeys(user string, lines ...string) error {
	p := s.KeysPath(user)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	content := ""
	for _, l := range lines {
		content += l + "\n"
	}
	return os.WriteFile(p, []byte(content), 0o600)
}

// Start launches the server on a random loopback port.
func Start(sandbox string, hostSigner ssh.Signer) (*Server, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &Server{Addr: ln.Addr().String(), Sandbox: sandbox, ln: ln}

	s.srv = &glssh.Server{
		Handler: func(sess glssh.Session) {
			raw := sess.RawCommand()
			if raw == "" {
				fmt.Fprintln(sess.Stderr(), "testsshd: interactive shells unsupported")
				_ = sess.Exit(1)
				return
			}
			cmd := exec.Command("/bin/sh", "-c", raw)
			stdin, err := cmd.StdinPipe()
			if err != nil {
				_ = sess.Exit(1)
				return
			}
			cmd.Stdout = sess
			cmd.Stderr = sess.Stderr()
			if err := cmd.Start(); err != nil {
				fmt.Fprintf(sess.Stderr(), "testsshd: %v\n", err)
				_ = sess.Exit(127)
				return
			}
			// Feed session stdin to the process; close on EOF or connection
			// death so held processes (the guard) see EOF exactly like a
			// real sshd delivering a hangup.
			go func() {
				_, _ = io.Copy(stdin, sess)
				_ = stdin.Close()
			}()
			err = cmd.Wait()
			code := 0
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else if err != nil {
				code = 1
			}
			_ = sess.Exit(code)
		},
		PublicKeyHandler: func(ctx glssh.Context, key glssh.PublicKey) bool {
			content, err := os.ReadFile(s.KeysPath(ctx.User()))
			if err != nil {
				return false
			}
			rest := content
			for len(rest) > 0 {
				var ak ssh.PublicKey
				ak, _, _, rest, err = ssh.ParseAuthorizedKey(rest)
				if err != nil {
					break
				}
				if glssh.KeysEqual(ak, key) {
					return true
				}
			}
			return false
		},
	}
	s.srv.AddHostKey(hostSigner)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		_ = s.srv.Serve(ln)
	}()
	return s, nil
}

// Close shuts the server down.
func (s *Server) Close() {
	_ = s.srv.Close()
	s.wg.Wait()
}
