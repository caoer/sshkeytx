package tx

import (
	"errors"
	"fmt"
	"testing"
	"time"

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
