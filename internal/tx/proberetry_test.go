package tx

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/caoer/sshkeytx/internal/authkeys"
	"github.com/caoer/sshkeytx/internal/sshx"
)

// TestProbeVerdictWaitsOutPenaltyWindow: OpenSSH 9.8+ PerSourcePenalties
// counts every probe (positive controls included — they abort at the
// signature) as a failed authentication; after step 5's probes the tool's
// own source sits in a penalty window and the next fresh connection is
// accepted and instantly closed. That surfaces as a connection-level error,
// which must be RETRIED after a pause — not returned as a failure that
// aborts (and reverts) a rotation whose writes were already verified.
// Observed live on macross-dev (NixOS, OpenSSH 9.9): two identical
// transactions aborted at step 6/6 "proving access", both on
// "handshake failed: EOF", both with correct file state.
func TestProbeVerdictWaitsOutPenaltyWindow(t *testing.T) {
	oldBackoff, oldAttempts := penaltyBackoff, probeAttempts
	penaltyBackoff, probeAttempts = time.Millisecond, 3
	t.Cleanup(func() { penaltyBackoff, probeAttempts = oldBackoff, oldAttempts })

	tr := &T{cfg: Config{Log: func(string, ...any) {}}}

	t.Run("connection errors are retried to a verdict", func(t *testing.T) {
		calls := 0
		res, err := tr.probeVerdict("probe", func() (sshx.ProbeResult, error) {
			calls++
			if calls < 3 {
				return sshx.ProbeResult{}, fmt.Errorf("probe inconclusive (connection-level error, not an auth verdict): %w", errors.New("EOF"))
			}
			return sshx.ProbeResult{Accepted: true}, nil
		})
		if err != nil || !res.Accepted {
			t.Fatalf("want accepted verdict after retries, got res=%+v err=%v", res, err)
		}
		if calls != 3 {
			t.Fatalf("want 3 attempts, got %d", calls)
		}
	})

	t.Run("an auth verdict is never retried", func(t *testing.T) {
		calls := 0
		res, err := tr.probeVerdict("probe", func() (sshx.ProbeResult, error) {
			calls++
			return sshx.ProbeResult{Accepted: false, Detail: "refused"}, nil
		})
		if err != nil || res.Accepted {
			t.Fatalf("unexpected result: res=%+v err=%v", res, err)
		}
		if calls != 1 {
			t.Fatalf("a rejection is a verdict — want 1 attempt, got %d", calls)
		}
	})

	t.Run("a persistent connection error still fails, bounded", func(t *testing.T) {
		calls := 0
		wantErr := errors.New("EOF")
		_, err := tr.probeVerdict("probe", func() (sshx.ProbeResult, error) {
			calls++
			return sshx.ProbeResult{}, wantErr
		})
		if !errors.Is(err, wantErr) {
			t.Fatalf("want the connection error surfaced, got %v", err)
		}
		if calls != probeAttempts {
			t.Fatalf("want exactly %d attempts, got %d", probeAttempts, calls)
		}
	})
}

// TestProbeRetryReachesTheRealPhases runs a COMPLETE transaction against the
// in-process sshd while every fresh-connection probe fails once, at the
// connection level, before succeeding.
//
// This is the test the retry never had. proberetry_test.go's other cases call
// probeVerdict directly with a fabricated closure, so they prove the wrapper
// counts attempts correctly and nothing more: unhook probeVerdict from all four
// call sites — i.e. undo the fix entirely — and they still pass. Here the
// injected error travels through phaseVerifyAdded, phaseVerifyRemoved (both its
// positive control and its removal probe) and proveAccess. Without the retry
// wiring, the first injected EOF aborts and reverts the transaction, so the
// commit assertion fails.
func TestProbeRetryReachesTheRealPhases(t *testing.T) {
	oldBackoff, oldAttempts := penaltyBackoff, probeAttempts
	penaltyBackoff, probeAttempts = time.Millisecond, 3
	oldProbe, oldVerify := probeKey, verifyAuth
	t.Cleanup(func() {
		penaltyBackoff, probeAttempts = oldBackoff, oldAttempts
		probeKey, verifyAuth = oldProbe, oldVerify
	})

	var mu sync.Mutex
	burned := map[string]bool{} // one injected failure per distinct probe
	injected := 0
	// A connection-level error is what a per-source penalty window looks like
	// from here: the TCP connect succeeds and the peer closes without a verdict.
	penalty := func(what string) error {
		return fmt.Errorf("probe inconclusive (connection-level error, not an auth verdict) for %s: %w", what, io.EOF)
	}
	failOnce := func(k string) bool {
		mu.Lock()
		defer mu.Unlock()
		if burned[k] {
			return false
		}
		burned[k] = true
		injected++
		return true
	}
	probeKey = func(tg sshx.Target, pub ssh.PublicKey, hk ssh.HostKeyCallback, d time.Duration) (sshx.ProbeResult, error) {
		k := "probe|" + tg.User + "|" + authkeys.Fingerprint(pub)
		if failOnce(k) {
			return sshx.ProbeResult{}, penalty(k)
		}
		return oldProbe(tg, pub, hk, d)
	}
	verifyAuth = func(tg sshx.Target, s ssh.Signer, hk ssh.HostKeyCallback, d time.Duration) (sshx.ProbeResult, error) {
		k := "auth|" + tg.User + "|" + authkeys.Fingerprint(s.PublicKey())
		if failOnce(k) {
			return sshx.ProbeResult{}, penalty(k)
		}
		return oldVerify(tg, s, hk, d)
	}

	h := newHarness(t)
	guardSigner, guardPub, guardLine := newKey(t)
	newSigner, newPub, _ := newKey(t)
	if err := h.srv.WriteKeys(h.user, guardLine); err != nil {
		t.Fatal(err)
	}

	cfg := h.config(guardSigner, []Op{
		{User: h.user, Action: ActionAdd, Spec: "new", Matcher: authkeys.Matcher{Key: newPub}, Key: newPub, Comment: "retry@test"},
		{User: h.user, Action: ActionRemove, Spec: "guard", Matcher: authkeys.Matcher{FingerprintSHA256: authkeys.Fingerprint(guardPub)}},
	})
	cfg.VerifySigners = []ssh.Signer{newSigner} // exercises the verifyAuth call site too

	res := Run(cfg)
	if res.Err != nil || res.Outcome != OutcomeCommitted {
		t.Fatalf("transaction did not survive per-source penalty windows: outcome=%s err=%v", res.Outcome, res.Err)
	}
	// The test is only meaningful if the failures actually happened. Cover the
	// verifyAuth site explicitly: it is the one that proves the successor.
	if injected == 0 {
		t.Fatal("no probe error was injected — the test proved nothing")
	}
	mu.Lock()
	sawAuth := false
	for k := range burned {
		if len(k) > 5 && k[:5] == "auth|" {
			sawAuth = true
		}
	}
	mu.Unlock()
	if !sawAuth {
		t.Error("verifyAuth was never called — the full-auth call site is unexercised by this test")
	}

	f := mustReadKeys(t, h.srv.KeysPath(h.user))
	if len(f.Find(authkeys.Matcher{Key: newPub})) != 1 {
		t.Error("new key missing after commit")
	}
	if len(f.Find(authkeys.Matcher{Key: guardPub})) != 0 {
		t.Error("removed key still present after commit")
	}
}
