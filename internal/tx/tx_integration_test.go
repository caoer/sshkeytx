package tx

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/caoer/sshkeytx/internal/authkeys"
	"github.com/caoer/sshkeytx/internal/remote"
	"github.com/caoer/sshkeytx/internal/sshx"
	"github.com/caoer/sshkeytx/internal/testsshd"
)

// harness is one in-process sshd + a transaction-ready Config skeleton.
type harness struct {
	t       *testing.T
	srv     *testsshd.Server
	sandbox string
	user    string
	target  sshx.Target
}

func newKey(t *testing.T) (ssh.Signer, ssh.PublicKey, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	return signer, signer.PublicKey(), line
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	hostSigner, _, _ := newKey(t)
	sandbox := t.TempDir()
	if err := os.MkdirAll(filepath.Join(sandbox, "tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	srv, err := testsshd.Start(sandbox, hostSigner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	tgt, err := sshx.ParseTarget(u.Username + "@" + srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	return &harness{t: t, srv: srv, sandbox: sandbox, user: u.Username, target: tgt}
}

func (h *harness) config(guard ssh.Signer, ops []Op) Config {
	return Config{
		Target:       h.target,
		Ops:          ops,
		PathTemplate: h.srv.PathTemplate(),
		HostKey:      ssh.InsecureIgnoreHostKey(),
		AuthMethods:  []ssh.AuthMethod{ssh.PublicKeys(guard)},
		DialTimeout:  10 * time.Second,
		RemoteTmp:    filepath.Join(h.sandbox, "tmp"),
		BackupRoot:   filepath.Join(h.sandbox, "local-backups"),
		Log:          h.t.Logf,
	}
}

func mustReadKeys(t *testing.T, path string) *authkeys.File {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return authkeys.Parse(content)
}

// TestRotateOwnGuardKey is the core scenario: the guard connection
// authenticates with the very key being removed. The held connection must
// survive, the removed key must be refused on fresh connections, the new
// key accepted, and the transaction committed.
func TestRotateOwnGuardKey(t *testing.T) {
	h := newHarness(t)
	oldSigner, oldPub, oldLine := newKey(t)
	_, otherPub, otherLine := newKey(t)
	newSigner, newPub, _ := newKey(t)
	if err := h.srv.WriteKeys(h.user, "# managed by test", oldLine, otherLine); err != nil {
		t.Fatal(err)
	}
	orig, _ := os.ReadFile(h.srv.KeysPath(h.user))

	cfg := h.config(oldSigner, []Op{
		// Removal by fingerprint exercises key enrichment for the probe.
		{User: h.user, Action: ActionRemove, Spec: "old", Matcher: authkeys.Matcher{FingerprintSHA256: authkeys.Fingerprint(oldPub)}},
		{User: h.user, Action: ActionAdd, Spec: "new", Matcher: authkeys.Matcher{Key: newPub}, Key: newPub, Comment: "rotated@test"},
	})
	cfg.VerifySigners = []ssh.Signer{newSigner} // full-auth verification path

	res := Run(cfg)
	if res.Err != nil || res.Outcome != OutcomeCommitted {
		t.Fatalf("expected committed, got %s err=%v", res.Outcome, res.Err)
	}

	f := mustReadKeys(t, h.srv.KeysPath(h.user))
	if len(f.Find(authkeys.Matcher{Key: oldPub})) != 0 {
		t.Fatal("old key still present after commit")
	}
	if len(f.Find(authkeys.Matcher{Key: newPub})) != 1 {
		t.Fatal("new key missing after commit")
	}
	if len(f.Find(authkeys.Matcher{Key: otherPub})) != 1 {
		t.Fatal("unrelated key was disturbed")
	}
	if f.Lines[0].Raw != "# managed by test" {
		t.Fatal("comment line was disturbed")
	}

	// Local CAS copy holds the pre-transaction content.
	backup, err := os.ReadFile(filepath.Join(res.LocalDir, "files", h.user, "authorized_keys"))
	if err != nil || !bytes.Equal(backup, orig) {
		t.Fatalf("local backup mismatch (err=%v)", err)
	}
	// meta.json records the transaction.
	if _, err := os.Stat(filepath.Join(res.LocalDir, "meta.json")); err != nil {
		t.Fatal("meta.json missing")
	}
	// Step 6 removed the remote tx dir.
	entries, _ := os.ReadDir(filepath.Join(h.sandbox, "tmp"))
	if len(entries) != 0 {
		t.Fatalf("remote tx dir not cleaned up: %v", entries)
	}

	// Independent live probes on fresh connections.
	if r, err := sshx.ProbeKey(h.target, oldPub, ssh.InsecureIgnoreHostKey(), 5*time.Second); err != nil || r.Accepted {
		t.Fatalf("old key should be rejected post-commit (err=%v accepted=%v)", err, r.Accepted)
	}
	if r, err := sshx.ProbeKey(h.target, newPub, ssh.InsecureIgnoreHostKey(), 5*time.Second); err != nil || !r.Accepted {
		t.Fatalf("new key should be accepted post-commit (err=%v accepted=%v)", err, r.Accepted)
	}
}

// TestAbortRevertsOnVerifyFailure decouples the file the transaction edits
// from the file sshd authenticates against, so the added key is never
// accepted: step 5 must fail and the abort must revert the edited file
// byte-for-byte and disarm the trap.
func TestAbortRevertsOnVerifyFailure(t *testing.T) {
	h := newHarness(t)
	guardSigner, _, guardLine := newKey(t)
	_, newPub, _ := newKey(t)
	if err := h.srv.WriteKeys(h.user, guardLine); err != nil {
		t.Fatal(err)
	}

	// Shadow tree: the tx edits here; auth still reads the real tree.
	shadow := filepath.Join(h.sandbox, "shadow", "%u", "authorized_keys")
	shadowPath := strings.ReplaceAll(shadow, "%u", h.user)
	if err := os.MkdirAll(filepath.Dir(shadowPath), 0o700); err != nil {
		t.Fatal(err)
	}
	origShadow := []byte(guardLine + "\n")
	if err := os.WriteFile(shadowPath, origShadow, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := h.config(guardSigner, []Op{
		{User: h.user, Action: ActionAdd, Spec: "new", Matcher: authkeys.Matcher{Key: newPub}, Key: newPub},
	})
	cfg.PathTemplate = shadow

	res := Run(cfg)
	if res.Outcome != OutcomeAbortedReverted {
		t.Fatalf("expected aborted-reverted, got %s err=%v", res.Outcome, res.Err)
	}
	if res.Err == nil || !strings.Contains(res.Err.Error(), "verify-added") {
		t.Fatalf("abort cause should be verify-added, got: %v", res.Err)
	}

	got, err := os.ReadFile(shadowPath)
	if err != nil || !bytes.Equal(got, origShadow) {
		t.Fatalf("edited file not reverted byte-for-byte (err=%v)\ngot:  %q\nwant: %q", err, got, origShadow)
	}

	// Abort keeps the remote tx dir for forensics, with the trap disarmed
	// (commit marker) and never fired (no restored marker).
	entries, _ := os.ReadDir(filepath.Join(h.sandbox, "tmp"))
	if len(entries) != 1 {
		t.Fatalf("expected forensic tx dir kept, got %v", entries)
	}
	txdir := filepath.Join(h.sandbox, "tmp", entries[0].Name())
	if _, err := os.Stat(filepath.Join(txdir, "commit")); err != nil {
		t.Fatal("trap not disarmed: commit marker missing after verified revert")
	}
	if _, err := os.Stat(filepath.Join(txdir, "restored")); err == nil {
		t.Fatal("trap fired despite explicit verified revert")
	}
}

// TestDeadManTrapRestoresOnConnectionLoss exercises the step-1 guard
// directly: arm it, tamper with a manifested file, then kill the TCP
// connection without any commit marker. The remote trap must restore the
// file on its own.
func TestDeadManTrapRestoresOnConnectionLoss(t *testing.T) {
	h := newHarness(t)
	guardSigner, _, guardLine := newKey(t)
	if err := h.srv.WriteKeys(h.user, guardLine); err != nil {
		t.Fatal(err)
	}
	orig := []byte("pre-transaction content\n")
	victim := filepath.Join(h.sandbox, "victim.txt")
	if err := os.WriteFile(victim, orig, 0o600); err != nil {
		t.Fatal(err)
	}

	client, err := sshx.Dial(h.target, []ssh.AuthMethod{ssh.PublicKeys(guardSigner)}, ssh.InsecureIgnoreHostKey(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	txdir, err := remote.MkTxDir(client, filepath.Join(h.sandbox, "tmp"), "trap-test")
	if err != nil {
		t.Fatal(err)
	}
	g, err := startGuard(client, txdir, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !g.alive() {
		t.Fatal("guard not alive after start")
	}

	// CAS copy + manifest, then tamper with the file.
	bak := txdir + "/backup/victim"
	if err := remote.WriteFile(client, bak, orig); err != nil {
		t.Fatal(err)
	}
	if err := remote.AppendFile(client, txdir+"/manifest", []byte("F\t"+bak+"\t"+victim+"\n")); err != nil {
		t.Fatal(err)
	}
	if err := remote.SwapFile(client, victim, []byte("TAMPERED\n"), remote.WriteOpts{Mode: "600"}); err != nil {
		t.Fatal(err)
	}

	// Kill the connection abruptly — no commit marker, no graceful close.
	_ = client.Close()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		got, err := os.ReadFile(victim)
		if err == nil && bytes.Equal(got, orig) {
			if _, err := os.Stat(filepath.Join(txdir, "restored")); err == nil {
				return // trap fired and restored — success
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	got, _ := os.ReadFile(victim)
	t.Fatalf("dead-man trap did not restore within deadline; victim=%q", got)
}

// TestMultiUserFoldsIntoOneTransaction adds one key for two users in a
// single transaction (ZT spec: multiple keys/users fold into one design).
func TestMultiUserFoldsIntoOneTransaction(t *testing.T) {
	h := newHarness(t)
	guardSigner, _, guardLine := newKey(t)
	_, newPub, _ := newKey(t)
	const second = "daemon" // exists on macOS and Linux
	if err := h.srv.WriteKeys(h.user, guardLine); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.WriteKeys(second, "# empty"); err != nil {
		t.Fatal(err)
	}

	cfg := h.config(guardSigner, []Op{
		{User: h.user, Action: ActionAdd, Spec: "new", Matcher: authkeys.Matcher{Key: newPub}, Key: newPub},
		{User: second, Action: ActionAdd, Spec: "new", Matcher: authkeys.Matcher{Key: newPub}, Key: newPub},
	})
	res := Run(cfg)
	if res.Err != nil || res.Outcome != OutcomeCommitted {
		t.Fatalf("expected committed, got %s err=%v", res.Outcome, res.Err)
	}
	for _, u := range []string{h.user, second} {
		f := mustReadKeys(t, h.srv.KeysPath(u))
		if len(f.Find(authkeys.Matcher{Key: newPub})) != 1 {
			t.Fatalf("new key missing for %s", u)
		}
	}
}

// TestProbeVerdicts pins the acceptance probe against a real publickey
// query phase: authorized key accepted, unknown key rejected, neither
// needing a private key for the target.
func TestProbeVerdicts(t *testing.T) {
	h := newHarness(t)
	_, authorizedPub, authorizedLine := newKey(t)
	_, strangerPub, _ := newKey(t)
	if err := h.srv.WriteKeys(h.user, authorizedLine); err != nil {
		t.Fatal(err)
	}
	if r, err := sshx.ProbeKey(h.target, authorizedPub, ssh.InsecureIgnoreHostKey(), 5*time.Second); err != nil || !r.Accepted {
		t.Fatalf("authorized key: want accepted, got accepted=%v err=%v", r.Accepted, err)
	}
	if r, err := sshx.ProbeKey(h.target, strangerPub, ssh.InsecureIgnoreHostKey(), 5*time.Second); err != nil || r.Accepted {
		t.Fatalf("stranger key: want rejected, got accepted=%v err=%v", r.Accepted, err)
	}
}
