package tx

import (
	"testing"

	"github.com/caoer/sshkeytx/internal/remote"
	"github.com/caoer/sshkeytx/internal/sshx"
)

// The decision itself is pinned in remote's TestDecideWriteOptsKeysOnDirectory.
// What is pinned HERE is the wiring: writeOpts must hand the transaction's own
// state — guard rootliness, guard user, entry user, entry uid/gid, the file
// AND the parent directory — to that decision. A wiring bug (most obviously:
// forgetting dirInfo, so every directory looks absent and every write drops)
// would leave the decision function perfectly correct and the tool broken.
func TestWriteOptsPassesDirectoryThrough(t *testing.T) {
	tr := &T{rootly: true, cfg: Config{Target: sshx.Target{User: "root"}}}

	rootOwnedDir := remote.FileInfo{Exists: true, UID: "0", GID: "0", Mode: "755"}
	userOwnedDir := remote.FileInfo{Exists: true, UID: "1000", GID: "100", Mode: "700"}
	nixRendered := remote.FileInfo{Exists: true, UID: "0", GID: "0", Mode: "444"}

	// Same file, same user — only the DIRECTORY differs. If dirInfo were not
	// threaded through, these two would come back identical.
	inConfigDir := tr.writeOpts(&userFile{
		user: "alice", uid: "1000", gid: "100",
		info: nixRendered, dirInfo: rootOwnedDir,
	})
	inHomeDir := tr.writeOpts(&userFile{
		user: "alice", uid: "1000", gid: "100",
		info: nixRendered, dirInfo: userOwnedDir,
	})

	if inConfigDir.RunAs != "" {
		t.Errorf("root-owned dir: RunAs = %q, want no drop (mktemp would EACCES)", inConfigDir.RunAs)
	}
	if inConfigDir.UID != "0" || inConfigDir.GID != "0" {
		t.Errorf("root-owned dir: UID/GID = %q/%q, want 0/0 preserved", inConfigDir.UID, inConfigDir.GID)
	}
	if inConfigDir.Mode != "444" {
		t.Errorf("root-owned dir: Mode = %q, want the existing 444 preserved", inConfigDir.Mode)
	}
	if inHomeDir.RunAs != "alice" {
		t.Errorf("user-owned dir: RunAs = %q, want alice — root must not write into a directory she controls", inHomeDir.RunAs)
	}
	if inHomeDir.UID != "" || inHomeDir.GID != "" {
		t.Errorf("user-owned dir: UID/GID = %q/%q, want empty when dropping", inHomeDir.UID, inHomeDir.GID)
	}
}

// A non-root guard can neither drop nor chown; the write runs as the guard.
func TestWriteOptsNonRootGuard(t *testing.T) {
	tr := &T{rootly: false, cfg: Config{Target: sshx.Target{User: "alice"}}}
	for _, exists := range []bool{true, false} {
		uf := &userFile{
			user: "alice", uid: "1000", gid: "100",
			info:    remote.FileInfo{Exists: exists, UID: "1000", GID: "100", Mode: "600"},
			dirInfo: remote.FileInfo{Exists: true, UID: "1000", GID: "100", Mode: "700"},
		}
		got := tr.writeOpts(uf)
		if got.RunAs != "" || got.UID != "" || got.GID != "" {
			t.Errorf("exists=%v: non-root guard must not set RunAs/UID/GID, got %+v", exists, got)
		}
		if got.Mode != "600" {
			t.Errorf("exists=%v: Mode = %q, want 600", exists, got.Mode)
		}
	}
}
