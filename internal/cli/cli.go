// Package cli wires the sshkeytx commands.
package cli

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/caoer/sshkeytx/internal/authkeys"
	"github.com/caoer/sshkeytx/internal/remote"
	"github.com/caoer/sshkeytx/internal/sshx"
	"github.com/caoer/sshkeytx/internal/tx"
)

// Version is stamped by goreleaser/ldflags; "dev" otherwise.
var Version = "dev"

// Exit codes. 0 = success. 1 = transaction aborted, revert VERIFIED.
// 2 = usage error. 3 = aborted, revert UNVERIFIED (remote trap is the
// backstop — check the printed backup paths). 4 = failed before any write.
const (
	ExitOK               = 0
	ExitAbortedReverted  = 1
	ExitUsage            = 2
	ExitRevertUnverified = 3
	ExitPreflight        = 4
)

type rootFlags struct {
	target       string
	identities   []string
	noAgent      bool
	knownHosts   []string
	hostKeyFP    string
	insecureHost bool
	timeout      time.Duration
	pathTemplate string
	remoteTmp    string
}

func (rf *rootFlags) register(cmd *cobra.Command) {
	f := cmd.PersistentFlags()
	f.StringVar(&rf.target, "target", "", "guard login, user@host[:port] (required; use root@ for multi-user transactions)")
	f.StringArrayVarP(&rf.identities, "identity", "i", nil, "private key file for the guard connection (repeatable; ssh-agent is used as well)")
	f.BoolVar(&rf.noAgent, "no-agent", false, "do not use ssh-agent")
	f.StringArrayVar(&rf.knownHosts, "known-hosts", nil, "known_hosts file (repeatable; default ~/.ssh/known_hosts)")
	f.StringVar(&rf.hostKeyFP, "host-key-fp", "", "pin the host key to this SHA256:... fingerprint instead of known_hosts")
	f.BoolVar(&rf.insecureHost, "insecure-host-key", false, "accept any host key (NOT for production)")
	f.DurationVar(&rf.timeout, "timeout", 15*time.Second, "per-connection dial timeout")
	f.StringVar(&rf.pathTemplate, "path", "%h/.ssh/authorized_keys", "authorized_keys path template (%u = user, %h = home)")
	f.StringVar(&rf.remoteTmp, "remote-tmp", "/tmp", "remote base directory for the transaction dir")
}

func (rf *rootFlags) targetOrErr() (sshx.Target, error) {
	if rf.target == "" {
		return sshx.Target{}, fmt.Errorf("--target is required (user@host[:port])")
	}
	return sshx.ParseTarget(rf.target)
}

func (rf *rootFlags) hostKey() (ssh.HostKeyCallback, error) {
	files := rf.knownHosts
	if len(files) == 0 {
		files = sshx.DefaultKnownHosts()
	}
	return sshx.HostKeyPolicy{
		KnownHostsFiles: files,
		PinnedSHA256:    rf.hostKeyFP,
		Insecure:        rf.insecureHost,
	}.Callback()
}

func (rf *rootFlags) authMethods() ([]ssh.AuthMethod, error) {
	return sshx.AuthBundle{IdentityFiles: rf.identities, DisableAgent: rf.noAgent}.Methods()
}

// userSpec is a parsed "user=KEY" CLI argument.
type userSpec struct {
	user    string
	spec    string
	matcher authkeys.Matcher
	key     ssh.PublicKey
	comment string
}

// parseUserSpec accepts user=VALUE where VALUE is a .pub file path, a
// literal "type base64 [comment]" line, or a SHA256:... fingerprint.
func parseUserSpec(arg string) (userSpec, error) {
	eq := strings.Index(arg, "=")
	if eq <= 0 {
		return userSpec{}, fmt.Errorf("spec %q must be user=KEY (KEY = .pub file, public key line, or SHA256: fingerprint)", arg)
	}
	us := userSpec{user: arg[:eq], spec: arg[eq+1:]}
	if !remote.ValidUsername(us.user) {
		return userSpec{}, fmt.Errorf("invalid username %q in spec %q", us.user, arg)
	}
	value := us.spec
	if st, err := os.Stat(value); err == nil && !st.IsDir() {
		data, err := os.ReadFile(value)
		if err != nil {
			return userSpec{}, fmt.Errorf("read key file %s: %w", value, err)
		}
		value = strings.TrimSpace(string(data))
	}
	m, comment, err := authkeys.ParseKeySpec(value)
	if err != nil {
		return userSpec{}, fmt.Errorf("spec %q: %w", arg, err)
	}
	us.matcher, us.key, us.comment = m, m.Key, comment
	return us, nil
}

func parseUserSpecs(args []string) ([]userSpec, error) {
	var out []userSpec
	for _, a := range args {
		us, err := parseUserSpec(a)
		if err != nil {
			return nil, err
		}
		out = append(out, us)
	}
	return out, nil
}

// verifySigners loads --verify-identity files and, unless --no-agent, the
// agent's signers. Added keys matching one of these get full-auth
// verification instead of the acceptance probe.
func verifySigners(files []string, noAgent bool) ([]ssh.Signer, error) {
	var signers []ssh.Signer
	for _, f := range files {
		pem, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("verify-identity %s: %w", f, err)
		}
		s, err := ssh.ParsePrivateKey(pem)
		if err != nil {
			return nil, fmt.Errorf("verify-identity %s: %w", f, err)
		}
		signers = append(signers, s)
	}
	if !noAgent {
		if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
			if conn, err := net.Dial("unix", sock); err == nil {
				if agentSigners, err := agent.NewClient(conn).Signers(); err == nil {
					signers = append(signers, agentSigners...)
				}
			}
		}
	}
	return signers, nil
}

type exitError struct {
	code int
	err  error
}

func (e exitError) Error() string { return e.err.Error() }

// Main runs the CLI and returns the process exit code.
func Main() int {
	rf := &rootFlags{}
	root := &cobra.Command{
		Use:           "sshkeytx",
		Short:         "Transactional, lockout-safe authorized_keys changes over SSH",
		Long:          "sshkeytx adds and removes SSH authorized_keys entries as one guarded transaction:\na held guard connection with a remote dead-man trap, copy-and-swap file edits\nbacked up locally and remotely, live verification that removed keys are rejected\nand added keys are accepted on fresh connections, and automatic revert on any\nfailure.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	rf.register(root)
	root.AddCommand(applyCmd(rf), checkCmd(rf), probeCmd(rf), restoreCmd(rf), versionCmd())

	err := root.Execute()
	if err == nil {
		return ExitOK
	}
	var ee exitError
	if isExit := asExitError(err, &ee); isExit {
		fmt.Fprintf(os.Stderr, "error: %v\n", ee.err)
		return ee.code
	}
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	return ExitUsage
}

func asExitError(err error, target *exitError) bool {
	if ee, ok := err.(exitError); ok {
		*target = ee
		return true
	}
	return false
}

func logStderr(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

func applyCmd(rf *rootFlags) *cobra.Command {
	var removes, adds, verifyIDs []string
	var backupDir string
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Run a key transaction: remove/add keys with guard, verify, and revert-on-failure",
		Example: `  # Rotate root's key on one host (remove old, add new, verify both live):
  sshkeytx apply --target root@host \
    --remove root=SHA256:oldFingerprint... \
    --add root=./new_key.pub --verify-identity ./new_key

  # Revoke someone else's key for two users and provision a replacement:
  sshkeytx apply --target root@host \
    --remove alice=./their_old.pub --remove root=./their_old.pub \
    --add alice='ssh-ed25519 AAAA... alice@new'`,
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := rf.targetOrErr()
			if err != nil {
				return err
			}
			if len(removes)+len(adds) == 0 {
				return fmt.Errorf("nothing to do: give --remove and/or --add")
			}
			var ops []tx.Op
			rSpecs, err := parseUserSpecs(removes)
			if err != nil {
				return err
			}
			for _, us := range rSpecs {
				ops = append(ops, tx.Op{User: us.user, Action: tx.ActionRemove, Spec: us.spec, Matcher: us.matcher, Key: us.key, Comment: us.comment})
			}
			aSpecs, err := parseUserSpecs(adds)
			if err != nil {
				return err
			}
			for _, us := range aSpecs {
				if us.key == nil {
					return fmt.Errorf("--add %s=%s: additions need the full public key, not a fingerprint", us.user, us.spec)
				}
				ops = append(ops, tx.Op{User: us.user, Action: tx.ActionAdd, Spec: us.spec, Matcher: us.matcher, Key: us.key, Comment: us.comment})
			}
			hostKey, err := rf.hostKey()
			if err != nil {
				return err
			}
			auth, err := rf.authMethods()
			if err != nil {
				return err
			}
			signers, err := verifySigners(verifyIDs, rf.noAgent)
			if err != nil {
				return err
			}
			res := tx.Run(tx.Config{
				Target:        target,
				Ops:           ops,
				PathTemplate:  rf.pathTemplate,
				HostKey:       hostKey,
				AuthMethods:   auth,
				VerifySigners: signers,
				DialTimeout:   rf.timeout,
				RemoteTmp:     rf.remoteTmp,
				BackupRoot:    backupDir,
				DryRun:        dryRun,
				Log:           logStderr,
			})
			switch res.Outcome {
			case tx.OutcomeCommitted:
				fmt.Printf("committed %s (local backups: %s)\n", res.TxID, res.LocalDir)
				return nil
			case tx.OutcomeDryRun:
				fmt.Printf("dry-run complete %s — nothing written\n", res.TxID)
				return nil
			case tx.OutcomeAbortedReverted:
				return exitError{ExitAbortedReverted, fmt.Errorf("transaction aborted, all changes reverted and verified: %w", res.Err)}
			case tx.OutcomeRevertUnverified:
				return exitError{ExitRevertUnverified, fmt.Errorf("transaction aborted and revert could NOT be verified — remote trap should restore; backups: %s: %w", res.LocalDir, res.Err)}
			default:
				return exitError{ExitPreflight, fmt.Errorf("failed before any change was written: %w", res.Err)}
			}
		},
	}
	f := cmd.Flags()
	f.StringArrayVar(&removes, "remove", nil, "user=KEY to remove (repeatable; KEY = .pub file, key line, or SHA256: fingerprint)")
	f.StringArrayVar(&adds, "add", nil, "user=KEY to add (repeatable; KEY = .pub file or key line)")
	f.StringArrayVar(&verifyIDs, "verify-identity", nil, "private key file: added keys matching it verify by full authentication (repeatable; agent keys are matched automatically)")
	f.StringVar(&backupDir, "backup-dir", "", "local backup root (default $XDG_STATE_HOME/sshkeytx or ~/.local/state/sshkeytx)")
	f.BoolVar(&dryRun, "dry-run", false, "connect, read, and print the plan; write nothing")
	return cmd
}

func checkCmd(rf *rootFlags) *cobra.Command {
	var present, absent []string
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Read-only audit: assert keys present/absent in authorized_keys files",
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := rf.targetOrErr()
			if err != nil {
				return err
			}
			pSpecs, err := parseUserSpecs(present)
			if err != nil {
				return err
			}
			aSpecs, err := parseUserSpecs(absent)
			if err != nil {
				return err
			}
			if len(pSpecs)+len(aSpecs) == 0 {
				return fmt.Errorf("nothing to check: give --present and/or --absent")
			}
			hostKey, err := rf.hostKey()
			if err != nil {
				return err
			}
			auth, err := rf.authMethods()
			if err != nil {
				return err
			}
			client, err := sshx.Dial(target, auth, hostKey, rf.timeout)
			if err != nil {
				return exitError{ExitPreflight, err}
			}
			defer client.Close()

			files := map[string]*authkeys.File{}
			paths := map[string]string{}
			load := func(user string) (*authkeys.File, string, error) {
				if f, ok := files[user]; ok {
					return f, paths[user], nil
				}
				_, _, home, err := remote.LookupUser(client, user)
				if err != nil {
					return nil, "", err
				}
				path := strings.NewReplacer("%u", user, "%h", home).Replace(rf.pathTemplate)
				content, _, err := remote.ReadFile(client, path)
				if err != nil {
					return nil, "", err
				}
				files[user], paths[user] = authkeys.Parse(content), path
				return files[user], path, nil
			}

			violations := 0
			for _, us := range pSpecs {
				f, path, err := load(us.user)
				if err != nil {
					return exitError{ExitPreflight, err}
				}
				if len(f.Find(us.matcher)) == 0 {
					fmt.Printf("FAIL present %s %s — not found in %s\n", us.user, us.matcher, path)
					violations++
				} else {
					fmt.Printf("ok   present %s %s\n", us.user, us.matcher)
				}
			}
			for _, us := range aSpecs {
				f, path, err := load(us.user)
				if err != nil {
					return exitError{ExitPreflight, err}
				}
				if n := len(f.Find(us.matcher)); n > 0 {
					fmt.Printf("FAIL absent  %s %s — %d matching line(s) in %s\n", us.user, us.matcher, n, path)
					violations++
				} else {
					fmt.Printf("ok   absent  %s %s\n", us.user, us.matcher)
				}
			}
			if violations > 0 {
				return exitError{ExitAbortedReverted, fmt.Errorf("%d violation(s)", violations)}
			}
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&present, "present", nil, "user=KEY that must exist (repeatable)")
	cmd.Flags().StringArrayVar(&absent, "absent", nil, "user=KEY that must NOT exist (repeatable)")
	return cmd
}

func probeCmd(rf *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "probe user=KEY [user=KEY...]",
		Short: "Live acceptance probe: would this public key be accepted for this user? (no private key needed)",
		Long:  "probe opens a fresh connection per key and uses the SSH publickey query phase\n(RFC 4252 §7): the server reveals whether the key is authorized before any\nsignature is required. Nothing is written and no session is opened.",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := rf.targetOrErr()
			if err != nil {
				return err
			}
			specs, err := parseUserSpecs(args)
			if err != nil {
				return err
			}
			hostKey, err := rf.hostKey()
			if err != nil {
				return err
			}
			rejected := 0
			for _, us := range specs {
				if us.key == nil {
					return fmt.Errorf("probe %s=%s: needs the full public key (a fingerprint cannot be probed)", us.user, us.spec)
				}
				res, err := sshx.ProbeKey(target.WithUser(us.user), us.key, hostKey, rf.timeout)
				if err != nil {
					return exitError{ExitPreflight, err}
				}
				verdict := "ACCEPTED"
				if !res.Accepted {
					verdict = "REJECTED"
					rejected++
				}
				fmt.Printf("%s %s %s (%s)\n", verdict, us.user, authkeys.Fingerprint(us.key), res.Detail)
			}
			if rejected > 0 {
				return exitError{ExitAbortedReverted, fmt.Errorf("%d key(s) rejected", rejected)}
			}
			return nil
		},
	}
	return cmd
}

func restoreCmd(rf *rootFlags) *cobra.Command {
	var from string
	cmd := &cobra.Command{
		Use:   "restore --from <local-backup-dir>",
		Short: "Break-glass: re-apply a transaction's local pre-transaction backups to the host",
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := rf.targetOrErr()
			if err != nil {
				return err
			}
			if from == "" {
				return fmt.Errorf("--from <dir> is required (a sshkeytx local backup dir containing meta.json)")
			}
			metaRaw, err := os.ReadFile(filepath.Join(from, "meta.json"))
			if err != nil {
				return fmt.Errorf("read %s/meta.json: %w", from, err)
			}
			m, err := tx.ParseMeta(metaRaw)
			if err != nil {
				return err
			}
			hostKey, err := rf.hostKey()
			if err != nil {
				return err
			}
			auth, err := rf.authMethods()
			if err != nil {
				return err
			}
			client, err := sshx.Dial(target, auth, hostKey, rf.timeout)
			if err != nil {
				return exitError{ExitPreflight, err}
			}
			defer client.Close()
			uid, err := remote.Whoami(client)
			if err != nil {
				return exitError{ExitPreflight, err}
			}
			for _, f := range m.Files {
				if !f.Existed {
					if err := remote.Remove(client, f.Path); err != nil {
						return exitError{ExitPreflight, fmt.Errorf("remove %s: %w", f.Path, err)}
					}
					fmt.Printf("restored %s: removed (did not exist pre-transaction)\n", f.Path)
					continue
				}
				content, err := os.ReadFile(filepath.Join(from, "files", f.User, "authorized_keys"))
				if err != nil {
					return fmt.Errorf("local backup for %s: %w", f.User, err)
				}
				opts := remote.WriteOpts{Mode: f.Mode, MkdirFor: true}
				if uid == "0" {
					opts.UID, opts.GID = f.UID, f.GID
				}
				if err := remote.SwapFile(client, f.Path, content, opts); err != nil {
					return exitError{ExitPreflight, fmt.Errorf("restore %s: %w", f.Path, err)}
				}
				fmt.Printf("restored %s from %s\n", f.Path, from)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&from, "from", "", "local backup dir written by a previous transaction")
	return cmd
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("sshkeytx " + Version)
		},
	}
}
