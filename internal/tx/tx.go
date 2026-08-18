// Package tx implements the sshkeytx transaction:
//
//  1. connect     — open the guard connection, arm the remote dead-man trap
//  2. add keys    — CAS: copy authorized_keys to remote + local backup, swap
//  3. verify      — fresh connection with each added key must be ACCEPTED
//  4. remove keys — CAS again, swap
//  5. verify      — fresh connection with each removed key must be REJECTED,
//     after a positive control proves the probe can say ACCEPTED
//  6. cleanup     — prove access, commit marker, tx dir removed, guard released
//
// The guard connection from step 1 is held for the whole transaction and
// every remote command runs through it, so a broken connection can never be
// papered over by a silent reconnect. Any failure aborts the transaction by
// reverting every touched file to its pre-transaction content; if the
// process or connection dies instead, the remote trap performs the same
// revert.
//
// Additions come first on purpose: a rotation is then never one failure away
// from a host with no usable key, because the replacement is in place and
// proven before the old key goes. Removing first bought nothing — the removal
// is verified at the end either way.
//
// Two rules keep the verdicts honest. A rejection is evidence only once some
// key that IS in the file comes back accepted for the same user — otherwise
// sshd may be refusing the user outright, and every probe would say the same
// thing with the key still in place. And nothing commits until a key in the
// final file is proven to work on a fresh connection, so a transaction cannot
// verify its way into a lockout.
//
// Files belonging to another user are written with that user's own privileges
// (remote.WriteOpts.RunAs) and symlinked targets are refused outright: a
// privileged write into a directory its owner controls is the whole of the
// escalation surface here.
package tx

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/caoer/sshkeytx/internal/authkeys"
	"github.com/caoer/sshkeytx/internal/remote"
	"github.com/caoer/sshkeytx/internal/sshx"
)

// Action is what an Op does to a key.
type Action string

const (
	ActionAdd    Action = "add"
	ActionRemove Action = "remove"
)

// Op is one requested change: add or remove one key for one user.
// Multiple ops (any mix of users and keys) fold into a single transaction.
type Op struct {
	User    string
	Action  Action
	Spec    string // raw CLI spec, for logs and meta.json
	Matcher authkeys.Matcher
	Key     ssh.PublicKey // full key when the spec carried one (always, for add)
	Comment string
	Options []string // authorized_keys restrictions (command=, restrict, from=...)
}

// Config parameterizes a transaction.
type Config struct {
	Target        sshx.Target // guard login (root for multi-user transactions)
	Ops           []Op
	PathTemplate  string // %u = username, %h = home; default "%h/.ssh/authorized_keys"
	HostKey       ssh.HostKeyCallback
	AuthMethods   []ssh.AuthMethod
	VerifySigners []ssh.Signer // added keys matching one of these verify by FULL auth
	DialTimeout   time.Duration
	RemoteTmp     string // base for the remote tx dir; default /tmp
	BackupRoot    string // local backup root; default ~/.local/state/sshkeytx
	DryRun        bool
	Log           func(format string, args ...any)
}

// Outcome classifies how a transaction ended; it maps to the process exit code.
type Outcome string

const (
	OutcomeCommitted        Outcome = "committed"
	OutcomeDryRun           Outcome = "dry-run"
	OutcomeAbortedReverted  Outcome = "aborted-reverted"    // failure, revert verified
	OutcomeRevertUnverified Outcome = "revert-unverified"   // failure, revert NOT verified — trap is the backstop
	OutcomeNothingChanged   Outcome = "failed-before-write" // failure before any mutation
)

// Result is what Run reports.
type Result struct {
	Outcome  Outcome
	TxID     string
	LocalDir string // local backup dir (empty for dry-run failures before setup)
	Err      error
}

// userFile is the per-target-file state inside a transaction.
type userFile struct {
	user       string
	path       string
	uid, gid   string
	home       string
	info       remote.FileInfo // pre-transaction
	orig       []byte          // pre-transaction content
	origExists bool
	work       *authkeys.File // working copy being edited
	dirty      bool           // a swap was ISSUED for this file (not necessarily confirmed)
	manifested bool           // trap manifest entry written
	// writeUnconfirmed records a swap whose outcome the client never
	// learned. The file may or may not have changed, so the revert must be
	// attempted and read back before anything is claimed about it.
	writeUnconfirmed bool
	remoteBak        string
}

type Meta struct {
	TxID    string     `json:"txid"`
	Target  string     `json:"target"`
	Started time.Time  `json:"started"`
	Ended   time.Time  `json:"ended"`
	Outcome Outcome    `json:"outcome"`
	Ops     []MetaOp   `json:"ops"`
	Files   []MetaFile `json:"files"`
	Steps   []string   `json:"steps"`
}

type MetaOp struct {
	User   string `json:"user"`
	Action Action `json:"action"`
	Spec   string `json:"spec"`
}

type MetaFile struct {
	User    string `json:"user"`
	Path    string `json:"path"`
	Existed bool   `json:"existed"`
	UID     string `json:"uid,omitempty"`
	GID     string `json:"gid,omitempty"`
	Mode    string `json:"mode,omitempty"`
	SHA256  string `json:"sha256,omitempty"` // of pre-transaction content
	Local   string `json:"local_backup,omitempty"`
}

// T is a running transaction.
type T struct {
	cfg    Config
	txid   string
	client *ssh.Client
	guard  *guard
	txdir  string
	local  string // local backup dir
	rootly bool   // guard uid == 0

	files map[string]*userFile // key: username
	order []string             // stable file iteration order

	connLost  chan struct{}
	connErr   error
	steps     []string
	startTime time.Time
}

// Run executes the whole transaction and never panics the host into an
// inconsistent state: every error path funnels through abort().
func Run(cfg Config) Result {
	t := &T{
		cfg:       cfg,
		files:     map[string]*userFile{},
		connLost:  make(chan struct{}),
		startTime: time.Now(),
	}
	if cfg.PathTemplate == "" {
		t.cfg.PathTemplate = "%h/.ssh/authorized_keys"
	}
	if cfg.RemoteTmp == "" {
		t.cfg.RemoteTmp = "/tmp"
	}
	if cfg.DialTimeout == 0 {
		t.cfg.DialTimeout = 15 * time.Second
	}
	if cfg.Log == nil {
		t.cfg.Log = func(string, ...any) {}
	}
	t.txid = newTxID()

	if err := t.validate(); err != nil {
		return Result{Outcome: OutcomeNothingChanged, TxID: t.txid, Err: err}
	}
	if err := t.setupLocal(); err != nil {
		return Result{Outcome: OutcomeNothingChanged, TxID: t.txid, Err: err}
	}

	// Step 1 — connect: guard connection + remote trap. Nothing is written
	// to any authorized_keys before the trap is armed.
	if err := t.connect(); err != nil {
		t.finishMeta(OutcomeNothingChanged)
		return Result{Outcome: OutcomeNothingChanged, TxID: t.txid, LocalDir: t.local, Err: err}
	}
	defer t.client.Close()

	if err := t.loadFiles(); err != nil {
		t.releaseGuardNoChanges()
		t.finishMeta(OutcomeNothingChanged)
		return Result{Outcome: OutcomeNothingChanged, TxID: t.txid, LocalDir: t.local, Err: err}
	}

	if t.cfg.DryRun {
		t.planOnly()
		t.releaseGuardNoChanges()
		t.finishMeta(OutcomeDryRun)
		return Result{Outcome: OutcomeDryRun, TxID: t.txid, LocalDir: t.local}
	}

	// Steps 2–5. Additions land and are proven BEFORE anything is removed,
	// so the host never passes through a state with no key the operator can
	// use. The end state is identical either way; the window is not.
	if err := t.phaseAdd(); err != nil {
		return t.abort(err)
	}
	if err := t.phaseVerifyAdded(); err != nil {
		return t.abort(err)
	}
	if err := t.phaseRemove(); err != nil {
		return t.abort(err)
	}
	if err := t.phaseVerifyRemoved(); err != nil {
		return t.abort(err)
	}

	// Step 6 — cleanup.
	if err := t.commit(); err != nil {
		return t.abort(err)
	}
	t.finishMeta(OutcomeCommitted)
	return Result{Outcome: OutcomeCommitted, TxID: t.txid, LocalDir: t.local}
}

func (t *T) logf(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	t.steps = append(t.steps, fmt.Sprintf("%s %s", time.Now().Format("15:04:05"), line))
	t.cfg.Log("%s", line)
}

func (t *T) validate() error {
	if len(t.cfg.Ops) == 0 {
		return fmt.Errorf("no operations: give at least one --add or --remove")
	}
	for _, op := range t.cfg.Ops {
		if !remote.ValidUsername(op.User) {
			return fmt.Errorf("invalid username %q", op.User)
		}
		if op.Action == ActionAdd && op.Key == nil {
			return fmt.Errorf("add for %s: spec %q must be a full public key (a fingerprint cannot be added)", op.User, op.Spec)
		}
	}
	return t.rejectSelfCancellingOps()
}

// rejectSelfCancellingOps refuses a transaction that both adds and removes the
// same key for the same user.
//
// Such a request has no single correct meaning: whichever phase runs last
// decides the end state, so the same command leaves the key present under one
// phase order and absent under another, while both verification steps "pass"
// and contradict each other. The same key for DIFFERENT users is an ordinary
// request (grant to alice, revoke from bob) and stays allowed.
func (t *T) rejectSelfCancellingOps() error {
	for _, add := range t.cfg.Ops {
		if add.Action != ActionAdd || add.Key == nil {
			continue
		}
		for _, rm := range t.cfg.Ops {
			if rm.Action != ActionRemove || rm.User != add.User {
				continue
			}
			if !rm.Matcher.Matches(authkeys.Line{Key: add.Key}) {
				continue
			}
			return fmt.Errorf("refusing: %s is both added (%q) and removed (%q) for %s — "+
				"the end state would depend on which step ran last; use separate transactions "+
				"if you really mean to churn this key", authkeys.Fingerprint(add.Key), add.Spec, rm.Spec, add.User)
		}
	}
	return nil
}

func (t *T) setupLocal() error {
	root := t.cfg.BackupRoot
	if root == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("resolve home for backup dir: %w", err)
		}
		if xdg := os.Getenv("XDG_STATE_HOME"); xdg != "" {
			root = filepath.Join(xdg, "sshkeytx")
		} else {
			root = filepath.Join(home, ".local", "state", "sshkeytx")
		}
	}
	t.local = filepath.Join(root, t.txid)
	if err := os.MkdirAll(filepath.Join(t.local, "files"), 0o700); err != nil {
		return err
	}
	t.logf("tx %s — local backups: %s", t.txid, t.local)
	return nil
}

// connect performs step 1: dial, keepalive watchdog, remote tx dir, guard.
// Every failure after the dial closes the connection and removes the tx dir:
// the caller's `defer t.client.Close()` is only registered once connect has
// succeeded, so without this the socket, the watchdog goroutine and a remote
// directory all leak for the life of the process.
func (t *T) connect() (err error) {
	defer func() {
		if err == nil {
			return
		}
		if t.guard != nil {
			_ = t.guard.closeGraceful(5 * time.Second)
		}
		if t.client != nil {
			if t.txdir != "" {
				_, _ = remote.Run(t.client, "rm -rf "+remote.Quote(t.txdir), nil)
			}
			_ = t.client.Close()
		}
	}()
	t.logf("step 1/6 connect: dialing guard connection %s", t.cfg.Target)
	client, err := sshx.Dial(t.cfg.Target, t.cfg.AuthMethods, t.cfg.HostKey, t.cfg.DialTimeout)
	if err != nil {
		return err
	}
	t.client = client

	// Keepalive watchdog: detects a dead transport fast on our side. The
	// remote trap covers the other side.
	//
	// SendRequest waits for a reply, so on a black-holed connection it
	// blocks exactly as long as the thing it is meant to detect — the
	// watchdog has to bound itself or it never fires at all.
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			reply := make(chan error, 1)
			go func() {
				_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
				reply <- err
			}()
			var err error
			select {
			case err = <-reply:
			case <-time.After(15 * time.Second):
				err = fmt.Errorf("keepalive unanswered for 15s")
			}
			if err != nil {
				t.connErr = err
				close(t.connLost)
				return
			}
		}
	}()

	uid, err := remote.Whoami(client)
	if err != nil {
		return fmt.Errorf("preflight whoami: %w", err)
	}
	t.rootly = uid == "0"

	t.txdir, err = remote.MkTxDir(client, t.cfg.RemoteTmp, t.txid)
	if err != nil {
		return err
	}
	t.logf("step 1/6 connect: remote tx dir %s", t.txdir)

	t.guard, err = startGuard(client, t.txdir, 15*time.Second)
	if err != nil {
		return err
	}
	t.logf("step 1/6 connect: guard held, remote trap armed (dead-man revert on connection loss)")
	return t.checkHealth("post-connect")
}

// checkHealth runs before every phase: the guard session must be alive, the
// transport must answer, and the trap must not have fired.
func (t *T) checkHealth(when string) error {
	select {
	case <-t.connLost:
		return fmt.Errorf("health(%s): guard connection lost: %v", when, t.connErr)
	default:
	}
	if !t.guard.alive() {
		return fmt.Errorf("health(%s): guard session exited prematurely", when)
	}
	out, err := remote.Run(t.client, fmt.Sprintf("test -f %s/ready && { test ! -f %s/restored || echo RESTORED; }", remote.Quote(t.txdir), remote.Quote(t.txdir)), nil)
	if err != nil {
		return fmt.Errorf("health(%s): probe through guard connection failed: %w", when, err)
	}
	if strings.Contains(string(out), "RESTORED") {
		return fmt.Errorf("health(%s): remote trap has already fired (%s/restored exists) — transaction state invalid", when, t.txdir)
	}
	t.logf("health(%s): guard alive, transport ok, trap armed", when)
	return nil
}

// loadFiles resolves each user's target file and captures pre-transaction
// state (content + stat) — the material every backup and revert derives from.
func (t *T) loadFiles() error {
	users := map[string]bool{}
	for _, op := range t.cfg.Ops {
		users[op.User] = true
	}
	names := make([]string, 0, len(users))
	for u := range users {
		names = append(names, u)
	}
	sort.Strings(names)

	for _, u := range names {
		uid, gid, home, err := remote.LookupUser(t.client, u)
		if err != nil {
			return err
		}
		path := strings.NewReplacer("%u", u, "%h", home).Replace(t.cfg.PathTemplate)
		if !t.rootly && u != t.cfg.Target.User {
			t.logf("warning: guard user %s is not root; edits for %s will likely fail", t.cfg.Target.User, u)
		}
		info, err := remote.Stat(t.client, path)
		if err != nil {
			return err
		}
		if info.IsSymlink {
			// stat does not dereference, so the swap would copy the LINK's
			// mode (0777 on GNU) onto a regular file replacing it, and sshd
			// StrictModes would then refuse every key in it. Reverting does
			// not help: the revert applies the same mode. Refuse up front,
			// before anything is written.
			return fmt.Errorf("%s is a symlink (%w) — point --path at the real file, "+
				"or at the mutable path sshd consults", path, remote.ErrSymlink)
		}
		content, exists, err := remote.ReadFile(t.client, path)
		if err != nil {
			return err
		}
		uf := &userFile{
			user: u, path: path, uid: uid, gid: gid, home: home,
			info: info, orig: content, origExists: exists,
			work: authkeys.Parse(content),
		}
		t.files[u] = uf
		t.order = append(t.order, u)
		t.logf("loaded %s (%s): exists=%v keys=%d", path, u, exists, countKeys(uf.work))
	}
	return nil
}

func countKeys(f *authkeys.File) int {
	n := 0
	for _, l := range f.Lines {
		if l.Key != nil {
			n++
		}
	}
	return n
}

// ensureCAS is the "copy" half of copy-and-swap for a file's FIRST mutation:
// the pre-transaction content is saved to the LOCAL backup dir and to the
// REMOTE tx dir, and the trap manifest entry is written. Later mutations of
// the same file keep additional forensic copies but the trap always restores
// the pre-transaction original.
func (t *T) ensureCAS(uf *userFile, phase string) error {
	// Local copy — written before anything touches the remote.
	localPath := filepath.Join(t.local, "files", uf.user, "authorized_keys")
	if !uf.manifested {
		if err := os.MkdirAll(filepath.Dir(localPath), 0o700); err != nil {
			return err
		}
		if uf.origExists {
			if err := os.WriteFile(localPath, uf.orig, 0o600); err != nil {
				return err
			}
		}
		// Remote copy + manifest entry (arming the trap for this file).
		uf.remoteBak = fmt.Sprintf("%s/backup/%s", t.txdir, uf.user)
		typ := "A"
		bak := "-"
		if uf.origExists {
			typ = "F"
			bak = uf.remoteBak
			if err := remote.WriteFile(t.client, uf.remoteBak, uf.orig); err != nil {
				return fmt.Errorf("remote backup of %s: %w", uf.path, err)
			}
		}
		line := fmt.Sprintf("%s\t%s\t%s\n", typ, bak, uf.path)
		if err := remote.AppendFile(t.client, t.txdir+"/manifest", []byte(line)); err != nil {
			return fmt.Errorf("manifest entry for %s: %w", uf.path, err)
		}
		uf.manifested = true
		t.logf("CAS copy (%s): %s saved local=%s remote=%s manifest=armed", phase, uf.path, localPath, valueOr(uf.remoteBak, "(absent)"))
		return nil
	}
	// Subsequent phase: forensic snapshot of the current intermediate state
	// (the caller invokes ensureCAS BEFORE editing, so this reads the state
	// this phase starts from).
	snap := fmt.Sprintf("%s.pre-%s", uf.remoteBak, phase)
	content, exists, err := remote.ReadFile(t.client, uf.path)
	if err != nil {
		return fmt.Errorf("forensic read of %s: %w", uf.path, err)
	}
	if exists {
		if err := remote.WriteFile(t.client, snap, content); err != nil {
			return fmt.Errorf("forensic remote copy of %s: %w", uf.path, err)
		}
		if err := os.WriteFile(localPath+".pre-"+phase, content, 0o600); err != nil {
			return err
		}
	}
	t.logf("CAS copy (%s): %s intermediate snapshot saved (local+remote)", phase, uf.path)
	return nil
}

func valueOr(s, alt string) string {
	if s == "" {
		return alt
	}
	return s
}

// swap is the "swap" half: atomic replace with ownership/mode preserved
// (or created 600, owner = target user, for new files).
// writeOpts builds the attribute policy for a write to uf. When the guard is
// root and the file belongs to someone else, the write drops to that user
// rather than chowning afterwards — a privileged write into a directory its
// owner controls is what made a planted symlink worth planting.
func (t *T) writeOpts(uf *userFile) remote.WriteOpts {
	opts := remote.WriteOpts{}
	if uf.info.Exists {
		opts.Mode = uf.info.Mode
	} else {
		opts.Mode = "600"
		opts.MkdirFor = true
	}
	if t.rootly && uf.user != t.cfg.Target.User {
		opts.RunAs = uf.user
		return opts
	}
	if t.rootly {
		if uf.info.Exists {
			opts.UID, opts.GID = uf.info.UID, uf.info.GID
		} else {
			opts.UID, opts.GID = uf.uid, uf.gid
		}
	}
	return opts
}

func (t *T) swap(uf *userFile) error {
	// Mark BEFORE the write, not after. A command whose reply is lost may
	// still have landed; treating "no confirmation" as "never happened"
	// makes abort skip the one file that changed. dirty means "a write was
	// issued", which is the only thing the client actually knows.
	uf.dirty = true
	if err := remote.SwapFile(t.client, uf.path, uf.work.Render(), t.writeOpts(uf)); err != nil {
		uf.writeUnconfirmed = true
		return fmt.Errorf("swap %s: %w", uf.path, err)
	}
	return nil
}

// phaseRemove — step 2: apply all removals, one CAS+swap per affected file.
func (t *T) phaseRemove() error {
	removals := t.opsBy(ActionRemove)
	if len(removals) == 0 {
		t.logf("step 4/6 remove: no removals requested — skipped")
		return nil
	}
	if err := t.checkHealth("pre-remove"); err != nil {
		return err
	}
	for _, u := range t.order {
		uf := t.files[u]
		ops := removals[u]
		if len(ops) == 0 {
			continue
		}
		changed := false
		for i := range ops {
			op := ops[i]
			removed := uf.work.Remove(op.Matcher)
			if len(removed) == 0 {
				t.logf("step 4/6 remove: %s: %s already absent (idempotent, nothing to do)", u, op.Matcher)
				continue
			}
			// Keep the full key for the rejection probe even when the spec
			// was only a fingerprint.
			if op.Key == nil && removed[0].Key != nil {
				op.Key = removed[0].Key
				ops[i] = op
			}
			changed = true
			t.logf("step 4/6 remove: %s: removing %d line(s) matching %s", u, len(removed), op.Matcher)
		}
		if !changed {
			continue
		}
		if err := t.ensureCAS(uf, "remove"); err != nil {
			return err
		}
		if err := t.swap(uf); err != nil {
			return err
		}
		t.logf("step 4/6 remove: %s swapped (%d keys remain)", uf.path, countKeys(uf.work))
	}
	// write back updated ops (Key enrichment) — opsBy returned copies
	t.enrichRemovalKeys(removals)
	return nil
}

// enrichRemovalKeys stores fingerprint-matched full keys back onto cfg.Ops
// so the verify phase can probe them.
func (t *T) enrichRemovalKeys(removals map[string][]Op) {
	for i := range t.cfg.Ops {
		op := &t.cfg.Ops[i]
		if op.Action != ActionRemove || op.Key != nil {
			continue
		}
		for _, enriched := range removals[op.User] {
			if enriched.Spec == op.Spec && enriched.Key != nil {
				op.Key = enriched.Key
			}
		}
	}
}

// phaseVerifyRemoved — step 3: every removed key must be REFUSED on a fresh
// connection. Uses the publickey query probe, so it works for keys whose
// private half we never had.
func (t *T) phaseVerifyRemoved() error {
	ops := t.cfg.Ops
	any := false
	for _, op := range ops {
		if op.Action == ActionRemove {
			any = true
		}
	}
	if !any {
		t.logf("step 5/6 verify-removed: no removals — skipped")
		return nil
	}
	if err := t.checkHealth("pre-verify-removed"); err != nil {
		return err
	}
	// A rejection only means something if this probe channel is capable of
	// returning an acceptance for the same user. sshd refuses some users
	// outright — AllowUsers, DenyUsers, a locked account, PermitRootLogin no
	// — and then every probe comes back rejected whatever the file holds.
	controlled := map[string]bool{}
	for _, op := range ops {
		if op.Action != ActionRemove || controlled[op.User] {
			continue
		}
		controlled[op.User] = true
		remaining := liveKeys(t.files[op.User].work)
		if len(remaining) == 0 {
			t.logf("step 5/6 verify-removed: %s: no keys remain, so no positive control is "+
				"possible — rejection verdicts below are UNVERIFIED until access is proven before commit", op.User)
			continue
		}
		ok, err := t.someKeyAccepted(op.User, remaining)
		if err != nil {
			return fmt.Errorf("verify-removed: positive control for %s: %w", op.User, err)
		}
		if !ok {
			return fmt.Errorf("verify-removed: positive control FAILED for %s: none of the %d key(s) "+
				"still in %s is accepted, so a rejection proves nothing about the removed key "+
				"(sshd may refuse this user outright, or read a different AuthorizedKeysFile)",
				op.User, len(remaining), t.files[op.User].path)
		}
		t.logf("step 5/6 verify-removed: %s: positive control ok — the probe channel answers ACCEPTED for a key that is present", op.User)
	}

	for _, op := range ops {
		if op.Action != ActionRemove {
			continue
		}
		target := t.cfg.Target.WithUser(op.User)
		if op.Key == nil {
			// Fingerprint spec and the key was never present: content check only.
			if len(t.files[op.User].work.Find(op.Matcher)) > 0 {
				return fmt.Errorf("verify-removed: %s still present in %s", op.Matcher, t.files[op.User].path)
			}
			t.logf("step 5/6 verify-removed: %s@%s: %s — content-verified absent (no key material for a live probe)", op.User, t.cfg.Target.Host, op.Matcher)
			continue
		}
		res, err := sshx.ProbeKey(target, op.Key, t.cfg.HostKey, t.cfg.DialTimeout)
		if err != nil {
			return fmt.Errorf("verify-removed: %w", err)
		}
		if res.Accepted {
			return fmt.Errorf("verify-removed: %s STILL ACCEPTED for %s — %s", op.Matcher, target, res.Detail)
		}
		t.logf("step 5/6 verify-removed: %s: new connection REJECTED ✓ (%s)", op.Matcher, res.Detail)
	}
	return nil
}

// phaseAdd — step 4: apply all additions, CAS+swap per affected file.
func (t *T) phaseAdd() error {
	adds := t.opsBy(ActionAdd)
	if len(adds) == 0 {
		t.logf("step 2/6 add: no additions requested — skipped")
		return nil
	}
	if err := t.checkHealth("pre-add"); err != nil {
		return err
	}
	for _, u := range t.order {
		uf := t.files[u]
		ops := adds[u]
		if len(ops) == 0 {
			continue
		}
		// Copy BEFORE this phase edits the file.
		if err := t.ensureCAS(uf, "add"); err != nil {
			return err
		}
		changed := false
		for _, op := range ops {
			if uf.work.Add(op.Key, op.Comment, op.Options) {
				changed = true
				t.logf("step 2/6 add: %s: adding %s %s%s", u, op.Key.Type(), authkeys.Fingerprint(op.Key), optionNote(op.Options))
			} else {
				t.logf("step 2/6 add: %s: %s already present (idempotent, nothing to do)", u, authkeys.Fingerprint(op.Key))
			}
		}
		if !changed {
			continue
		}
		if err := t.swap(uf); err != nil {
			return err
		}
		t.logf("step 2/6 add: %s swapped (%d keys now)", uf.path, countKeys(uf.work))
	}
	return nil
}

// phaseVerifyAdded — step 5: every added key must be ACCEPTED on a fresh
// connection — full authentication when we hold the private key, the
// publickey query probe otherwise.
func (t *T) phaseVerifyAdded() error {
	any := false
	for _, op := range t.cfg.Ops {
		if op.Action == ActionAdd {
			any = true
		}
	}
	if !any {
		t.logf("step 3/6 verify-added: no additions — skipped")
		return nil
	}
	if err := t.checkHealth("pre-verify-added"); err != nil {
		return err
	}
	for _, op := range t.cfg.Ops {
		if op.Action != ActionAdd {
			continue
		}
		target := t.cfg.Target.WithUser(op.User)
		fp := authkeys.Fingerprint(op.Key)
		if signer := matchSigner(t.cfg.VerifySigners, op.Key); signer != nil {
			res, err := sshx.VerifyAuth(target, signer, t.cfg.HostKey, t.cfg.DialTimeout)
			if err != nil {
				return fmt.Errorf("verify-added: %w", err)
			}
			if !res.Accepted {
				return fmt.Errorf("verify-added: %s NOT accepted for %s — %s", fp, target, res.Detail)
			}
			t.logf("step 3/6 verify-added: %s: new connection ACCEPTED ✓ (full auth)", fp)
			continue
		}
		res, err := sshx.ProbeKey(target, op.Key, t.cfg.HostKey, t.cfg.DialTimeout)
		if err != nil {
			return fmt.Errorf("verify-added: %w", err)
		}
		if !res.Accepted {
			return fmt.Errorf("verify-added: %s NOT accepted for %s — %s", fp, target, res.Detail)
		}
		t.logf("step 3/6 verify-added: %s: new connection ACCEPTED ✓ (%s; supply --verify-identity for full auth)", fp, res.Detail)
	}
	return nil
}

func matchSigner(signers []ssh.Signer, key ssh.PublicKey) ssh.Signer {
	want := key.Marshal()
	for _, s := range signers {
		if bytes.Equal(s.PublicKey().Marshal(), want) {
			return s
		}
	}
	return nil
}

// liveKeys returns the public keys currently in a working copy.
func liveKeys(f *authkeys.File) []ssh.PublicKey {
	var out []ssh.PublicKey
	for _, l := range f.Lines {
		if l.Key != nil {
			out = append(out, l.Key)
		}
	}
	return out
}

// someKeyAccepted probes keys for user on FRESH connections until one is
// accepted. A connection-level error is returned as an error (it is not a
// verdict); an all-rejected result is a false verdict, not a failure.
func (t *T) someKeyAccepted(user string, keys []ssh.PublicKey) (bool, error) {
	target := t.cfg.Target.WithUser(user)
	var lastErr error
	for _, k := range keys {
		res, err := sshx.ProbeKey(target, k, t.cfg.HostKey, t.cfg.DialTimeout)
		if err != nil {
			lastErr = err
			continue
		}
		if res.Accepted {
			return true, nil
		}
	}
	if lastErr != nil {
		return false, lastErr
	}
	return false, nil
}

// proveAccess is the gate the whole tool exists for: before the trap is
// disarmed and the backups deleted, prove on a FRESH connection that somebody
// can still get in to every file this transaction touched.
//
// Without it, `--remove <your only key>` empties the file, proves on a fresh
// connection that you are now refused, and reports success.
func (t *T) proveAccess() error {
	for _, u := range t.order {
		uf := t.files[u]
		if !uf.dirty {
			continue
		}
		keys := liveKeys(uf.work)
		if len(keys) == 0 {
			return fmt.Errorf("refusing to commit: %s would be left with no keys — "+
				"nobody could authenticate as %s afterwards", uf.path, u)
		}
		ok, err := t.someKeyAccepted(u, keys)
		if err != nil {
			return fmt.Errorf("proving access for %s: %w", u, err)
		}
		if !ok {
			return fmt.Errorf("refusing to commit: none of the %d key(s) left in %s is accepted "+
				"on a fresh connection — committing would lock %s out", len(keys), uf.path, u)
		}
		t.logf("step 6/6 cleanup: access proven for %s — a key in the final file is accepted on a fresh connection ✓", u)
	}
	return nil
}

// commit — step 6: prove access, disarm the trap (commit marker), release the
// guard, remove the remote tx dir. Local backups are kept permanently.
func (t *T) commit() error {
	if err := t.checkHealth("pre-cleanup"); err != nil {
		return err
	}
	if err := t.proveAccess(); err != nil {
		return err
	}
	t.logf("step 6/6 cleanup: writing commit marker (disarms remote trap)")
	if err := remote.WriteFile(t.client, t.txdir+"/commit", []byte(t.txid+"\n")); err != nil {
		return fmt.Errorf("write commit marker: %w", err)
	}
	if err := t.guard.closeGraceful(10 * time.Second); err != nil {
		// Committed but the guard is misbehaving: files are correct and the
		// trap is disarmed. Report, do not revert.
		t.logf("step 6/6 cleanup: warning: %v", err)
	}
	if _, err := remote.Run(t.client, "rm -rf "+remote.Quote(t.txdir), nil); err != nil {
		t.logf("step 6/6 cleanup: warning: could not remove %s: %v", t.txdir, err)
	}
	t.logf("step 6/6 cleanup: done — committed. Local backups kept: %s", t.local)
	return nil
}

// releaseGuardNoChanges tears the guard down when nothing was ever written
// (dry-run, load failure). No commit marker is needed: the manifest is empty.
func (t *T) releaseGuardNoChanges() {
	if t.guard != nil {
		_ = t.guard.closeGraceful(5 * time.Second)
	}
	if t.client != nil && t.txdir != "" {
		_, _ = remote.Run(t.client, "rm -rf "+remote.Quote(t.txdir), nil)
	}
}

// abort reverts every touched file to its pre-transaction state and verifies
// the revert by reading the content back. If verification cannot complete
// (dead connection), the guard is dropped WITHOUT a commit marker so the
// remote trap performs the same revert server-side.
func (t *T) abort(cause error) Result {
	t.logf("ABORT: %v", cause)
	t.logf("ABORT: reverting %d touched file(s) to pre-transaction state", t.dirtyCount())

	revertFailed := false
	for _, u := range t.order {
		uf := t.files[u]
		if !uf.dirty {
			continue
		}
		if uf.writeUnconfirmed {
			t.logf("ABORT: %s had a swap whose outcome was never confirmed — reverting and reading back", uf.path)
		}
		var err error
		if uf.origExists {
			err = remote.SwapFile(t.client, uf.path, uf.orig, t.writeOpts(uf))
		} else {
			err = remote.Remove(t.client, uf.path)
		}
		if err != nil {
			t.logf("ABORT: revert of %s FAILED: %v", uf.path, err)
			revertFailed = true
			continue
		}
		// Verify the revert byte-for-byte.
		got, exists, err := remote.ReadFile(t.client, uf.path)
		switch {
		case err != nil:
			t.logf("ABORT: revert verification of %s FAILED: %v", uf.path, err)
			revertFailed = true
		case uf.origExists && (!exists || !bytes.Equal(got, uf.orig)):
			t.logf("ABORT: revert verification of %s FAILED: content mismatch", uf.path)
			revertFailed = true
		case !uf.origExists && exists:
			t.logf("ABORT: revert verification of %s FAILED: file should not exist", uf.path)
			revertFailed = true
		default:
			t.logf("ABORT: %s reverted and verified (sha256 %s)", uf.path, sha256Hex(uf.orig))
		}
	}

	if !revertFailed {
		// Disarm the trap — the explicit revert already restored everything.
		if err := remote.WriteFile(t.client, t.txdir+"/commit", []byte("aborted-reverted\n")); err != nil {
			t.logf("ABORT: could not disarm trap (%v) — guard will re-restore on close; harmless (idempotent restore)", err)
		}
		if t.guard != nil {
			_ = t.guard.closeGraceful(10 * time.Second)
		}
		t.logf("ABORT: revert complete and verified. Remote forensics kept in %s; local backups in %s", t.txdir, t.local)
		t.finishMeta(OutcomeAbortedReverted)
		return Result{Outcome: OutcomeAbortedReverted, TxID: t.txid, LocalDir: t.local, Err: cause}
	}

	// Explicit revert failed — fall back to the dead-man trap: close the
	// connection WITHOUT the commit marker; the remote trap restores from
	// the remote backups as soon as sshd reaps the session.
	t.logf("ABORT: explicit revert UNVERIFIED — dropping guard connection so the remote trap restores from %s/backup", t.txdir)
	t.logf("ABORT: local pre-transaction backups: %s (sshkeytx restore can re-apply them)", t.local)
	if t.client != nil {
		_ = t.client.Close()
	}
	t.finishMeta(OutcomeRevertUnverified)
	return Result{Outcome: OutcomeRevertUnverified, TxID: t.txid, LocalDir: t.local, Err: cause}
}

func (t *T) dirtyCount() int {
	n := 0
	for _, uf := range t.files {
		if uf.dirty {
			n++
		}
	}
	return n
}

func (t *T) opsBy(a Action) map[string][]Op {
	m := map[string][]Op{}
	for _, op := range t.cfg.Ops {
		if op.Action == a {
			m[op.User] = append(m[op.User], op)
		}
	}
	return m
}

func (t *T) planOnly() {
	t.logf("dry-run: plan follows; nothing will be written")
	for _, u := range t.order {
		uf := t.files[u]
		for _, op := range t.cfg.Ops {
			if op.User != u {
				continue
			}
			switch op.Action {
			case ActionRemove:
				n := len(uf.work.Find(op.Matcher))
				t.logf("dry-run: remove %s from %s — %d matching line(s)", op.Matcher, uf.path, n)
			case ActionAdd:
				present := len(uf.work.Find(authkeys.Matcher{Key: op.Key})) > 0
				t.logf("dry-run: add %s to %s — already present: %v", authkeys.Fingerprint(op.Key), uf.path, present)
			}
		}
	}
}

func (t *T) finishMeta(outcome Outcome) {
	m := Meta{
		TxID:    t.txid,
		Target:  t.cfg.Target.String(),
		Started: t.startTime,
		Ended:   time.Now(),
		Outcome: outcome,
		Steps:   t.steps,
	}
	for _, op := range t.cfg.Ops {
		m.Ops = append(m.Ops, MetaOp{User: op.User, Action: op.Action, Spec: op.Spec})
	}
	for _, u := range t.order {
		uf := t.files[u]
		mf := MetaFile{User: uf.user, Path: uf.path, Existed: uf.origExists}
		if uf.info.Exists {
			mf.UID, mf.GID, mf.Mode = uf.info.UID, uf.info.GID, uf.info.Mode
		}
		if uf.origExists {
			mf.SHA256 = sha256Hex(uf.orig)
			mf.Local = filepath.Join(t.local, "files", uf.user, "authorized_keys")
		}
		m.Files = append(m.Files, mf)
	}
	if t.local == "" {
		return
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err == nil {
		_ = os.WriteFile(filepath.Join(t.local, "meta.json"), append(data, '\n'), 0o600)
	}
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func newTxID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b[:])
}

// ParseMeta reads a transaction's meta.json (for sshkeytx restore).
func ParseMeta(data []byte) (Meta, error) {
	var m Meta
	if err := json.Unmarshal(data, &m); err != nil {
		return Meta{}, fmt.Errorf("parse meta.json: %w", err)
	}
	return m, nil
}

// optionNote renders authorized_keys restrictions for the log, so an operator
// can see that a key went in restricted rather than inferring it.
func optionNote(options []string) string {
	if len(options) == 0 {
		return ""
	}
	return " [" + strings.Join(options, ",") + "]"
}
