// Package sshx wraps golang.org/x/crypto/ssh with the pieces sshkeytx needs:
// target parsing, auth assembly (agent + identity files), host key policy,
// and an authorized-key acceptance probe that needs no private key.
package sshx

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Target is one remote account: user@host:port.
type Target struct {
	User string
	Host string
	Port string
}

// ParseTarget parses "user@host[:port]". Port defaults to 22.
func ParseTarget(s string) (Target, error) {
	at := strings.LastIndex(s, "@")
	if at <= 0 || at == len(s)-1 {
		return Target{}, fmt.Errorf("target %q must be user@host[:port]", s)
	}
	t := Target{User: s[:at], Host: s[at+1:], Port: "22"}
	if host, port, err := net.SplitHostPort(t.Host); err == nil {
		t.Host, t.Port = host, port
	}
	return t, nil
}

func (t Target) Addr() string             { return net.JoinHostPort(t.Host, t.Port) }
func (t Target) String() string           { return fmt.Sprintf("%s@%s", t.User, t.Addr()) }
func (t Target) WithUser(u string) Target { t2 := t; t2.User = u; return t2 }

// HostKeyPolicy builds the ssh.HostKeyCallback for every connection the
// transaction opens (guard and verification dials use the same policy).
type HostKeyPolicy struct {
	KnownHostsFiles []string // consulted in order
	PinnedSHA256    string   // "SHA256:..." — accept exactly this host key
	Insecure        bool     // accept anything (explicit opt-in)
}

// Callback resolves the policy. Precedence: Insecure > PinnedSHA256 > known_hosts.
func (p HostKeyPolicy) Callback() (ssh.HostKeyCallback, error) {
	if p.Insecure {
		return ssh.InsecureIgnoreHostKey(), nil //nolint:gosec // explicit opt-in
	}
	if p.PinnedSHA256 != "" {
		want := p.PinnedSHA256
		return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			got := ssh.FingerprintSHA256(key)
			if got != want {
				return fmt.Errorf("host key mismatch for %s: got %s, pinned %s", hostname, got, want)
			}
			return nil
		}, nil
	}
	var files []string
	for _, f := range p.KnownHostsFiles {
		if _, err := os.Stat(f); err == nil {
			files = append(files, f)
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no usable known_hosts file (checked %v); use --known-hosts, --host-key-fp, or --insecure-host-key", p.KnownHostsFiles)
	}
	return knownhosts.New(files...)
}

// DefaultKnownHosts returns ~/.ssh/known_hosts if resolvable.
func DefaultKnownHosts() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return []string{home + "/.ssh/known_hosts"}
}

// AuthBundle assembles guard-connection auth: ssh-agent (if SSH_AUTH_SOCK is
// set) plus any identity files.
type AuthBundle struct {
	IdentityFiles []string
	DisableAgent  bool
}

// Methods returns the auth methods, most specific first. Encrypted identity
// files fail with a hint to load them into the agent instead.
func (a AuthBundle) Methods() ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	var signers []ssh.Signer
	for _, f := range a.IdentityFiles {
		pem, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("identity %s: %w", f, err)
		}
		s, err := ssh.ParsePrivateKey(pem)
		if err != nil {
			var pass *ssh.PassphraseMissingError
			if errors.As(err, &pass) {
				return nil, fmt.Errorf("identity %s is passphrase-protected: load it into ssh-agent (ssh-add %s) and retry", f, f)
			}
			return nil, fmt.Errorf("identity %s: %w", f, err)
		}
		signers = append(signers, s)
	}
	if len(signers) > 0 {
		methods = append(methods, ssh.PublicKeys(signers...))
	}
	if !a.DisableAgent {
		if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
			conn, err := net.Dial("unix", sock)
			if err == nil {
				methods = append(methods, ssh.PublicKeysCallback(agent.NewClient(conn).Signers))
			}
		}
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("no auth available: no --identity given and no usable ssh-agent (SSH_AUTH_SOCK)")
	}
	return methods, nil
}

// Dial opens an SSH connection with a hard TCP + handshake timeout.
func Dial(t Target, methods []ssh.AuthMethod, hostKey ssh.HostKeyCallback, timeout time.Duration) (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{
		User:            t.User,
		Auth:            methods,
		HostKeyCallback: hostKey,
		Timeout:         timeout,
	}
	client, err := ssh.Dial("tcp", t.Addr(), cfg)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", t, err)
	}
	return client, nil
}

// errProbe is returned by the sentinel signer so a probe connection aborts
// deterministically once the server has revealed its verdict.
var errProbe = errors.New("sshkeytx: probe sentinel — signature intentionally not produced")

// probeSigner satisfies ssh.Signer (and AlgorithmSigner, so RSA keys get
// rsa-sha2-* negotiation) for a public key whose private half we do not
// hold. Sign records that the server sent PK_OK — the server only asks for
// a signature after confirming the key is authorized — then fails.
type probeSigner struct {
	pub   ssh.PublicKey
	asked *bool
}

func (p probeSigner) PublicKey() ssh.PublicKey { return p.pub }

func (p probeSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	*p.asked = true
	return nil, errProbe
}

func (p probeSigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	*p.asked = true
	return nil, errProbe
}

// ProbeResult is the verdict of an acceptance probe.
type ProbeResult struct {
	Accepted bool
	// Detail describes how the verdict was reached, for logs.
	Detail string
}

// ProbeKey opens a NEW connection and asks the server, via the SSH publickey
// query phase (RFC 4252 §7), whether pub is authorized for t.User. No private
// key is needed and no session is created: the server answers PK_OK (or not)
// before any signature exists. This is how "removed key → new connection
// rejected" is verified even for keys whose private half belongs to someone
// else.
func ProbeKey(t Target, pub ssh.PublicKey, hostKey ssh.HostKeyCallback, timeout time.Duration) (ProbeResult, error) {
	asked := false
	cfg := &ssh.ClientConfig{
		User:            t.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(probeSigner{pub: pub, asked: &asked})},
		HostKeyCallback: hostKey,
		Timeout:         timeout,
	}
	client, err := ssh.Dial("tcp", t.Addr(), cfg)
	if client != nil {
		client.Close() // cannot happen with the sentinel, but be safe
	}
	if asked {
		return ProbeResult{Accepted: true, Detail: "server sent PK_OK for the key (authorized); probe aborted before authentication"}, nil
	}
	if err == nil {
		return ProbeResult{}, fmt.Errorf("probe %s: connection succeeded without the server requesting a signature — cannot interpret", t)
	}
	if isAuthFailure(err) {
		return ProbeResult{Accepted: false, Detail: "server refused the key at the publickey query phase"}, nil
	}
	return ProbeResult{}, fmt.Errorf("probe %s inconclusive (connection-level error, not an auth verdict): %w", t, err)
}

// VerifyAuth opens a NEW connection and fully authenticates with signer.
// Returns Accepted=true only on a complete successful handshake — the
// strongest possible "new connection accepted" evidence. Auth failure maps
// to Accepted=false; transport errors are returned as errors.
func VerifyAuth(t Target, signer ssh.Signer, hostKey ssh.HostKeyCallback, timeout time.Duration) (ProbeResult, error) {
	cfg := &ssh.ClientConfig{
		User:            t.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKey,
		Timeout:         timeout,
	}
	client, err := ssh.Dial("tcp", t.Addr(), cfg)
	if err == nil {
		client.Close()
		return ProbeResult{Accepted: true, Detail: "full authentication succeeded on a fresh connection"}, nil
	}
	if isAuthFailure(err) {
		return ProbeResult{Accepted: false, Detail: "full authentication refused: " + err.Error()}, nil
	}
	return ProbeResult{}, fmt.Errorf("verify %s inconclusive (connection-level error, not an auth verdict): %w", t, err)
}

// isAuthFailure distinguishes "the server evaluated and refused our auth"
// from transport/host-key trouble.
func isAuthFailure(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "unable to authenticate") ||
		strings.Contains(msg, "no supported methods remain")
}
