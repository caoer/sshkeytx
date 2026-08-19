package remote

import (
	"errors"
	"testing"
)

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
			// The regression the file-ownership rule introduced. NOTE: callers
			// never reach this decision — CheckWriteTarget refuses the
			// combination outright (TestCheckWriteTargetRefusesOwnershipHandover),
			// because dropping here silently hands the file to alice. The case
			// stays to pin what the raw decision is if that guard is removed.
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
	// Boundaries the sliced-last-three-bytes version got wrong: setuid/setgid
	// prefixes, and short read-only modes it reported as writable.
	safe := []string{"755", "700", "0755", "555", "0500", "2755", "4755", "44", "0", "4", "5", "55"}
	unsafe := []string{"775", "757", "777", "1777", "0770", "707", "7", "70", "", "x", "-755", "08"}
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

// TestCheckWriteTargetRefusesOwnershipHandover pins the one combination that
// has no safe automatic answer: an existing file owned by somebody other than
// the entry user, in a directory the entry user controls.
//
// DecideWriteOpts would return RunAs=<entry user>, and the mv then lands a file
// THEY created — a root-owned authorized_keys silently becomes theirs, with no
// chown and no log line, and abort()'s revert would not notice because it
// compares content only. Writing as root instead is the escalation the whole
// predicate exists to prevent. Both answers are wrong, so the caller refuses.
func TestCheckWriteTargetRefusesOwnershipHandover(t *testing.T) {
	userDir := FileInfo{Exists: true, UID: "1000", GID: "100", Mode: "700"}
	rootDir := FileInfo{Exists: true, UID: "0", GID: "0", Mode: "755"}
	base := func(f, d FileInfo) WriteTarget {
		return WriteTarget{GuardIsRoot: true, GuardUser: "root", EntryUser: "alice",
			EntryUID: "1000", EntryGID: "100", File: f, Dir: d}
	}
	rootOwned := FileInfo{Exists: true, UID: "0", GID: "0", Mode: "600"}
	aliceOwned := FileInfo{Exists: true, UID: "1000", GID: "100", Mode: "600"}

	if err := CheckWriteTarget(base(rootOwned, userDir)); !errors.Is(err, ErrOwnershipHandover) {
		t.Errorf("root-owned file in alice's dir: want ErrOwnershipHandover, got %v", err)
	}
	// Same file, root-managed directory: root writes it, nothing is handed over.
	if err := CheckWriteTarget(base(rootOwned, rootDir)); err != nil {
		t.Errorf("root-owned file in a root-owned dir: want no error, got %v", err)
	}
	// Alice's own file in her own directory is the ordinary drop.
	if err := CheckWriteTarget(base(aliceOwned, userDir)); err != nil {
		t.Errorf("alice's file in alice's dir: want no error, got %v", err)
	}
	// Nothing exists yet: no ownership to hand over.
	if err := CheckWriteTarget(base(FileInfo{Exists: false}, userDir)); err != nil {
		t.Errorf("absent file: want no error, got %v", err)
	}
	// A non-root guard cannot hand anything over; it writes as itself or fails.
	nonRoot := base(rootOwned, userDir)
	nonRoot.GuardIsRoot = false
	if err := CheckWriteTarget(nonRoot); err != nil {
		t.Errorf("non-root guard: want no error, got %v", err)
	}
	// The guard's own file is never a handover.
	own := base(rootOwned, userDir)
	own.EntryUser = "root"
	if err := CheckWriteTarget(own); err != nil {
		t.Errorf("guard's own file: want no error, got %v", err)
	}
}
