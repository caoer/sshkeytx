package remote

import "testing"

// TestDecideWriteOptsKeysOnDirectory pins the predicate that governs the
// privilege drop: the PARENT DIRECTORY's ownership, not the file's and not the
// entry's username.
//
// Two earlier rules each got half of this right. 355ed68 keyed the drop on the
// username, so a root:root file in a root:root directory (NixOS renders
// /etc/ssh/authorized_keys.d/<user> that way) dropped to a user who could not
// write the directory — mktemp EACCES, and neither the edit nor the revert
// could land. The first fix keyed it on the FILE's owner, which unbroke that
// case and quietly opened the other one: a root-owned file inside a
// user-OWNED home took the root path, which is precisely the privileged write
// into an attacker-controlled directory the drop exists to prevent.
//
// GID is asserted everywhere. Every rootly branch sets UID and GID as a pair,
// so a test that checks only UID passes a change that drops or swaps GID.
func TestDecideWriteOptsKeysOnDirectory(t *testing.T) {
	const (
		rootDir  = "0"    // root-owned, not group/other writable
		userDir  = "1000" // alice's own home
		aliceUID = "1000"
		aliceGID = "100"
	)
	dir := func(uid, mode string) FileInfo {
		return FileInfo{Exists: true, UID: uid, GID: "0", Mode: mode}
	}
	file := func(uid, gid, mode string) FileInfo {
		return FileInfo{Exists: true, UID: uid, GID: gid, Mode: mode}
	}

	cases := []struct {
		name            string
		tgt             WriteTarget
		runAs, uid, gid string
		mode            string
		wantMkdir       bool
	}{
		{
			name: "root-owned dir, root-owned file (NixOS authorized_keys.d): root writes, ownership preserved",
			tgt: WriteTarget{GuardIsRoot: true, GuardUser: "root", EntryUser: "alice",
				EntryUID: aliceUID, EntryGID: aliceGID,
				File: file("0", "0", "444"), Dir: dir(rootDir, "755")},
			runAs: "", uid: "0", gid: "0", mode: "444",
		},
		{
			name: "root-owned dir, user-owned file: still root — alice cannot write the directory",
			tgt: WriteTarget{GuardIsRoot: true, GuardUser: "root", EntryUser: "alice",
				EntryUID: aliceUID, EntryGID: aliceGID,
				File: file(aliceUID, aliceGID, "600"), Dir: dir(rootDir, "755")},
			runAs: "", uid: aliceUID, gid: aliceGID, mode: "600",
		},
		{
			name: "user-owned dir, user-owned file (~/.ssh): DROP",
			tgt: WriteTarget{GuardIsRoot: true, GuardUser: "root", EntryUser: "alice",
				EntryUID: aliceUID, EntryGID: aliceGID,
				File: file(aliceUID, aliceGID, "600"), Dir: dir(userDir, "700")},
			runAs: "alice", uid: "", gid: "", mode: "600",
		},
		{
			// The regression the file-ownership rule introduced.
			name: "user-owned dir, ROOT-owned file (admin's sudo cp): DROP, not a root write",
			tgt: WriteTarget{GuardIsRoot: true, GuardUser: "root", EntryUser: "alice",
				EntryUID: aliceUID, EntryGID: aliceGID,
				File: file("0", "0", "600"), Dir: dir(userDir, "700")},
			runAs: "alice", uid: "", gid: "", mode: "600",
		},
		{
			name: "third party's dir: DROP — root must not write into a directory bob controls",
			tgt: WriteTarget{GuardIsRoot: true, GuardUser: "root", EntryUser: "alice",
				EntryUID: aliceUID, EntryGID: aliceGID,
				File: file(aliceUID, aliceGID, "600"), Dir: dir("1001", "755")},
			runAs: "alice", uid: "", gid: "", mode: "600",
		},
		{
			name: "root-owned but GROUP-writable dir: DROP — someone other than root can redirect the write",
			tgt: WriteTarget{GuardIsRoot: true, GuardUser: "root", EntryUser: "alice",
				EntryUID: aliceUID, EntryGID: aliceGID,
				File: file(aliceUID, aliceGID, "600"), Dir: dir(rootDir, "775")},
			runAs: "alice", uid: "", gid: "", mode: "600",
		},
		{
			name: "root-owned but WORLD-writable dir (1777, sticky): DROP",
			tgt: WriteTarget{GuardIsRoot: true, GuardUser: "root", EntryUser: "alice",
				EntryUID: aliceUID, EntryGID: aliceGID,
				File: file(aliceUID, aliceGID, "600"), Dir: dir(rootDir, "1777")},
			runAs: "alice", uid: "", gid: "", mode: "600",
		},
		{
			// The absent-file case the file-ownership rule could not answer at
			// all: there is no file to stat, so it fell back to the username.
			name: "ABSENT file in a root-owned dir: root creates it, chowned to the entry user",
			tgt: WriteTarget{GuardIsRoot: true, GuardUser: "root", EntryUser: "alice",
				EntryUID: aliceUID, EntryGID: aliceGID,
				File: FileInfo{Exists: false}, Dir: dir(rootDir, "755")},
			runAs: "", uid: aliceUID, gid: aliceGID, mode: "600", wantMkdir: true,
		},
		{
			name: "ABSENT file in the user's own dir: DROP, they create it themselves",
			tgt: WriteTarget{GuardIsRoot: true, GuardUser: "root", EntryUser: "alice",
				EntryUID: aliceUID, EntryGID: aliceGID,
				File: FileInfo{Exists: false}, Dir: dir(userDir, "700")},
			runAs: "alice", uid: "", gid: "", mode: "600", wantMkdir: true,
		},
		{
			name: "guard's own file: never drop, ownership preserved",
			tgt: WriteTarget{GuardIsRoot: true, GuardUser: "root", EntryUser: "root",
				EntryUID: "0", EntryGID: "0",
				File: file("0", "0", "600"), Dir: dir(rootDir, "700")},
			runAs: "", uid: "0", gid: "0", mode: "600",
		},
		{
			name: "non-root guard: cannot drop and cannot chown, whatever the directory says",
			tgt: WriteTarget{GuardIsRoot: false, GuardUser: "alice", EntryUser: "alice",
				EntryUID: aliceUID, EntryGID: aliceGID,
				File: file(aliceUID, aliceGID, "600"), Dir: dir(userDir, "700")},
			runAs: "", uid: "", gid: "", mode: "600",
		},
		{
			name: "non-root guard, someone else's file: still plain opts — the write will fail loudly, not silently misown",
			tgt: WriteTarget{GuardIsRoot: false, GuardUser: "bob", EntryUser: "alice",
				EntryUID: aliceUID, EntryGID: aliceGID,
				File: file(aliceUID, aliceGID, "600"), Dir: dir(userDir, "700")},
			runAs: "", uid: "", gid: "", mode: "600",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := DecideWriteOpts(c.tgt)
			if got.RunAs != c.runAs {
				t.Errorf("RunAs = %q, want %q", got.RunAs, c.runAs)
			}
			if got.UID != c.uid {
				t.Errorf("UID = %q, want %q", got.UID, c.uid)
			}
			if got.GID != c.gid {
				t.Errorf("GID = %q, want %q", got.GID, c.gid)
			}
			if got.Mode != c.mode {
				t.Errorf("Mode = %q, want %q", got.Mode, c.mode)
			}
			if got.MkdirFor != c.wantMkdir {
				t.Errorf("MkdirFor = %v, want %v", got.MkdirFor, c.wantMkdir)
			}
			// A drop and a chown are mutually exclusive: SwapFile only emits
			// the chown when RunAs is empty, so setting both would silently
			// discard the ownership half.
			if got.RunAs != "" && (got.UID != "" || got.GID != "") {
				t.Errorf("RunAs=%q set together with UID/GID %q/%q — chown is skipped when dropping", got.RunAs, got.UID, got.GID)
			}
		})
	}
}

func TestDirWritableByOthers(t *testing.T) {
	safe := []string{"755", "700", "0755", "555", "0500"}
	unsafe := []string{"775", "757", "777", "1777", "0770", "707", "", "x"}
	for _, m := range safe {
		if dirWritableByOthers(m) {
			t.Errorf("mode %q: want safe, got writable-by-others", m)
		}
	}
	for _, m := range unsafe {
		if !dirWritableByOthers(m) {
			t.Errorf("mode %q: want writable-by-others (unparseable counts), got safe", m)
		}
	}
}
