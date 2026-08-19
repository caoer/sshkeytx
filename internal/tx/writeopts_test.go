package tx

import (
	"testing"

	"github.com/caoer/sshkeytx/internal/remote"
	"github.com/caoer/sshkeytx/internal/sshx"
)

// TestWriteOptsDropFollowsOwnership: the privilege drop exists to keep root
// from writing into a directory a non-root user controls. Its trigger must be
// the FILE'S OWNER, not the entry's username: on config-managed hosts (NixOS
// renders /etc/ssh/authorized_keys.d/<user>) every user's file is root:root
// mode 444 inside a root-owned directory. Dropping to the entry user there
// guarantees EACCES on mktemp — neither the edit nor a revert through the
// same writeOpts path can ever land. 355ed68 keyed the drop on the username
// and broke every non-root entry on such hosts.
func TestWriteOptsDropFollowsOwnership(t *testing.T) {
	tr := &T{rootly: true, cfg: Config{Target: sshx.Target{User: "root"}}}
	cases := []struct {
		name  string
		uf    userFile
		runAs string
		uid   string
	}{
		{
			name: "user-owned home file: drop to the user, no chown",
			uf: userFile{user: "alice", uid: "1000", gid: "100",
				info: remote.FileInfo{Exists: true, UID: "1000", GID: "100", Mode: "600"}},
			runAs: "alice", uid: "",
		},
		{
			name: "root-owned config-rendered file, non-root entry: write as root, preserve root:root",
			uf: userFile{user: "alice", uid: "1000", gid: "100",
				info: remote.FileInfo{Exists: true, UID: "0", GID: "0", Mode: "444"}},
			runAs: "", uid: "0",
		},
		{
			name: "guard's own file: no drop, ownership preserved",
			uf: userFile{user: "root", uid: "0", gid: "0",
				info: remote.FileInfo{Exists: true, UID: "0", GID: "0", Mode: "600"}},
			runAs: "", uid: "0",
		},
		{
			name: "absent file: create drops to the entry user in their own home",
			uf: userFile{user: "alice", uid: "1000", gid: "100",
				info: remote.FileInfo{Exists: false}},
			runAs: "alice", uid: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := tr.writeOpts(&c.uf)
			if got.RunAs != c.runAs {
				t.Errorf("RunAs = %q, want %q", got.RunAs, c.runAs)
			}
			if got.UID != c.uid {
				t.Errorf("UID = %q, want %q", got.UID, c.uid)
			}
			if c.uf.info.Exists && got.Mode != c.uf.info.Mode {
				t.Errorf("Mode = %q, want %q (existing mode must be preserved)", got.Mode, c.uf.info.Mode)
			}
		})
	}
}

// TestWriteOptsNonRootGuard: a non-root guard can neither drop nor chown —
// the opts must stay plain so the write runs as the guard itself.
func TestWriteOptsNonRootGuard(t *testing.T) {
	tr := &T{rootly: false, cfg: Config{Target: sshx.Target{User: "alice"}}}
	uf := userFile{user: "alice", uid: "1000", gid: "100",
		info: remote.FileInfo{Exists: true, UID: "1000", GID: "100", Mode: "600"}}
	got := tr.writeOpts(&uf)
	if got.RunAs != "" || got.UID != "" || got.GID != "" {
		t.Errorf("non-root guard must not set RunAs/UID/GID, got %+v", got)
	}
	if got.Mode != "600" {
		t.Errorf("Mode = %q, want 600", got.Mode)
	}
}
