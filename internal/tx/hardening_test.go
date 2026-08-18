package tx

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/caoer/sshkeytx/internal/authkeys"
)

// These tests encode failure modes found in review of ece95f8. Each one
// describes a way the transaction can lock an operator out of a host, or
// hand a local user root, while reporting success.

// TestSymlinkedTargetIsRefused: authorized_keys is a symlink (config
// management, dotfile repos, home-manager). `stat` does not dereference, so
// the swap copies the SYMLINK's mode — 0777 on Linux, 0755 on BSD — onto a
// regular file that replaces the link. sshd's StrictModes then refuses the
// file and every key is rejected. The abort path re-applies the same mode, so
// the tool's own recovery cannot undo the lockout it just created.
//
// Operating on a symlinked target must be refused before anything is written.
func TestSymlinkedTargetIsRefused(t *testing.T) {
	h := newHarness(t)
	guardSigner, _, guardLine := newKey(t)
	_, newPub, _ := newKey(t)

	real := filepath.Join(h.sandbox, "real-authorized_keys")
	if err := os.WriteFile(real, []byte(guardLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	linked := h.srv.KeysPath(h.user)
	if err := os.MkdirAll(filepath.Dir(linked), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, linked); err != nil {
		t.Fatal(err)
	}

	cfg := h.config(guardSigner, []Op{
		{User: h.user, Action: ActionAdd, Spec: "new", Matcher: authkeys.Matcher{Key: newPub}, Key: newPub},
	})
	res := Run(cfg)

	if res.Outcome == OutcomeCommitted {
		t.Errorf("committed against a symlinked authorized_keys; want refusal")
	}
	fi, err := os.Lstat(linked)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("symlink was replaced by a regular file mode %#o (sshd StrictModes would refuse it)", fi.Mode().Perm())
	}
	if got, _ := os.ReadFile(real); !bytes.Equal(got, []byte(guardLine+"\n")) {
		t.Errorf("content behind the symlink was modified: %q", got)
	}
}

// TestPlantedTempSymlinkIsNotFollowed: SwapFile writes to a fixed, predictable
// temp path inside the target user's own ~/.ssh. A local user can plant a
// symlink there in advance; the root-run `cat >` then follows it and writes
// attacker-chosen content wherever it points (and `chown` follows too).
//
// The write must fail rather than follow a pre-existing path.
func TestPlantedTempSymlinkIsNotFollowed(t *testing.T) {
	h := newHarness(t)
	guardSigner, _, guardLine := newKey(t)
	_, newPub, _ := newKey(t)
	if err := h.srv.WriteKeys(h.user, guardLine); err != nil {
		t.Fatal(err)
	}

	outside := filepath.Join(h.sandbox, "outside-the-transaction")
	const sentinel = "UNTOUCHED\n"
	if err := os.WriteFile(outside, []byte(sentinel), 0o600); err != nil {
		t.Fatal(err)
	}
	planted := h.srv.KeysPath(h.user) + ".sshkeytx.tmp"
	if err := os.Symlink(outside, planted); err != nil {
		t.Fatal(err)
	}

	cfg := h.config(guardSigner, []Op{
		{User: h.user, Action: ActionAdd, Spec: "new", Matcher: authkeys.Matcher{Key: newPub}, Key: newPub},
	})
	_ = Run(cfg)

	got, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != sentinel {
		t.Errorf("write followed the planted symlink and clobbered a file outside the transaction:\n%q", got)
	}
}

// TestSymlinkedParentDirIsNotChmodded: when the target file does not exist,
// SwapFile runs `mkdir -p DIR && chmod 700 DIR && chown UID:GID DIR`. mkdir -p
// succeeds through a symlink-to-directory, so chmod/chown land on the real
// directory. As root that hands an unprivileged user any directory they can
// point .ssh at.
func TestSymlinkedParentDirIsNotChmodded(t *testing.T) {
	h := newHarness(t)
	guardSigner, _, guardLine := newKey(t)
	_, newPub, _ := newKey(t)
	if err := h.srv.WriteKeys(h.user, guardLine); err != nil {
		t.Fatal(err)
	}

	victim := filepath.Join(h.sandbox, "victim-dir")
	if err := os.MkdirAll(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	linkedDir := filepath.Join(h.sandbox, "shadow-home", ".ssh")
	if err := os.MkdirAll(filepath.Dir(linkedDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, linkedDir); err != nil {
		t.Fatal(err)
	}

	cfg := h.config(guardSigner, []Op{
		{User: h.user, Action: ActionAdd, Spec: "new", Matcher: authkeys.Matcher{Key: newPub}, Key: newPub},
	})
	cfg.PathTemplate = filepath.Join(h.sandbox, "shadow-home", ".ssh", "authorized_keys")
	_ = Run(cfg)

	fi, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o755 {
		t.Errorf("chmod followed the symlinked .ssh and changed the real directory to %#o", fi.Mode().Perm())
	}
}

// TestRemoveOnlyEmptyingFileIsRefused: `--remove <your only key>` empties
// authorized_keys, proves on a fresh connection that you are now refused,
// disarms the trap, deletes the remote backups, and reports committed. The
// tool verifies the negative rigorously and never verifies that anyone can
// still get in.
func TestRemoveOnlyEmptyingFileIsRefused(t *testing.T) {
	h := newHarness(t)
	guardSigner, guardPub, guardLine := newKey(t)
	if err := h.srv.WriteKeys(h.user, guardLine); err != nil {
		t.Fatal(err)
	}

	cfg := h.config(guardSigner, []Op{
		{User: h.user, Action: ActionRemove, Spec: "self", Matcher: authkeys.Matcher{Key: guardPub}, Key: guardPub},
	})
	res := Run(cfg)

	if res.Outcome == OutcomeCommitted {
		t.Errorf("committed a transaction that leaves %s with no usable key", h.srv.KeysPath(h.user))
	}
	f := mustReadKeys(t, h.srv.KeysPath(h.user))
	if countKeys(f) == 0 {
		t.Errorf("authorized_keys left with zero keys — host is unreachable")
	}
}

// TestLostExitStatusDoesNotDisarmTrap: `dirty` is set only after SwapFile
// REPORTS success. When the mutation lands but the exit status is lost
// (*ssh.ExitMissingError — the remote shell was killed, the channel closed
// early), abort skips the file as untouched, finds nothing to revert, writes
// the commit marker — disarming the dead-man trap that was correctly armed for
// it — and reports "revert complete and verified".
func TestLostExitStatusDoesNotDisarmTrap(t *testing.T) {
	h := newHarness(t)
	guardSigner, _, guardLine := newKey(t)
	_, newPub, _ := newKey(t)
	if err := h.srv.WriteKeys(h.user, guardLine); err != nil {
		t.Fatal(err)
	}
	// Lose the exit status of the swap only — the mv still happens.
	h.srv.DropExitStatusFor = func(raw string) bool { return strings.Contains(raw, "mv -f") }

	cfg := h.config(guardSigner, []Op{
		{User: h.user, Action: ActionAdd, Spec: "new", Matcher: authkeys.Matcher{Key: newPub}, Key: newPub},
	})
	res := Run(cfg)

	if res.Outcome == OutcomeCommitted {
		t.Fatalf("expected the lost exit status to fail the transaction, got committed")
	}
	entries, _ := os.ReadDir(filepath.Join(h.sandbox, "tmp"))
	if len(entries) != 1 {
		t.Fatalf("expected the tx dir to be kept, got %v", entries)
	}
	txdir := filepath.Join(h.sandbox, "tmp", entries[0].Name())

	// The file really was mutated on the remote.
	f := mustReadKeys(t, h.srv.KeysPath(h.user))
	mutated := len(f.Find(authkeys.Matcher{Key: newPub})) > 0

	if _, err := os.Stat(filepath.Join(txdir, "commit")); err == nil && mutated {
		t.Errorf("abort disarmed the trap (wrote %s/commit) while the file is still mutated — "+
			"nothing will restore it, and the outcome was reported as %s", txdir, res.Outcome)
	}
	if mutated && res.Outcome == OutcomeAbortedReverted {
		t.Errorf("reported %s (revert verified) but the remote file still carries the added key", res.Outcome)
	}
}

// TestRejectionProbeNeedsPositiveControl: a probe rejection proves only that
// THIS auth attempt failed. When sshd refuses the user wholesale — AllowUsers,
// DenyUsers, a locked account, PermitRootLogin no — every probe comes back
// rejected whatever authorized_keys contains. The transaction then commits a
// revocation it never actually verified.
func TestRejectionProbeNeedsPositiveControl(t *testing.T) {
	h := newHarness(t)
	guardSigner, _, guardLine := newKey(t)
	_, victimPub, victimLine := newKey(t)
	if err := h.srv.WriteKeys(h.user, guardLine, victimLine); err != nil {
		t.Fatal(err)
	}

	cfg := h.config(guardSigner, []Op{
		{User: h.user, Action: ActionRemove, Spec: "victim", Matcher: authkeys.Matcher{Key: victimPub}, Key: victimPub},
	})
	// Start refusing the user only AFTER the guard connection is up, so the
	// transaction reaches its verification phase — otherwise the test would
	// pass merely because the guard could not connect.
	cfg.Log = func(format string, args ...any) {
		h.t.Logf(format, args...)
		if strings.Contains(format, "step 2/6 remove") {
			h.srv.DenyUsers[h.user] = true
		}
	}

	res := Run(cfg)
	if res.Outcome == OutcomeNothingChanged {
		t.Fatalf("transaction never reached verification (guard failed): %v", res.Err)
	}
	if res.Outcome == OutcomeCommitted {
		t.Errorf("committed a revocation whose only evidence is a refusal that would have " +
			"occurred with the key still in place — the probe channel is blind for this user")
	}
}

func TestAddPreservesAuthorizedKeysOptions(t *testing.T) {
	_, pub, _ := newKey(t)
	line := `command="/usr/bin/rrsync -ro /srv",restrict,no-pty ` +
		strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " backup@nas"

	m, comment, err := authkeys.ParseKeySpec(line)
	if err != nil {
		t.Fatal(err)
	}
	f := authkeys.Parse(nil)
	f.Add(m.Key, comment)
	got := string(f.Render())

	if !strings.Contains(got, "command=") || !strings.Contains(got, "restrict") {
		t.Errorf("authorized_keys options were dropped — a restricted key installs unrestricted\ngot: %s", got)
	}
}
