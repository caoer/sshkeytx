package authkeys

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func genKey(t *testing.T) (ssh.PublicKey, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer.PublicKey(), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
}

func TestParseRenderRoundTrip(t *testing.T) {
	_, line := genKey(t)
	content := []byte("# comment\n\n" + line + " user@host\ngarbage line that is not a key\n")
	f := Parse(content)
	if !bytes.Equal(f.Render(), content) {
		t.Fatalf("round trip mismatch:\n%q\n%q", f.Render(), content)
	}
	if got := countParsed(f); got != 1 {
		t.Fatalf("want 1 parsed key, got %d", got)
	}
	// No trailing newline is preserved too.
	f2 := Parse([]byte(line))
	if !bytes.Equal(f2.Render(), []byte(line)) {
		t.Fatal("missing-final-newline not preserved")
	}
	// Empty file renders empty.
	if out := Parse(nil).Render(); len(out) != 0 {
		t.Fatalf("empty parse rendered %q", out)
	}
}

func countParsed(f *File) int {
	n := 0
	for _, l := range f.Lines {
		if l.Key != nil {
			n++
		}
	}
	return n
}

func TestRemoveByMaterialAndFingerprint(t *testing.T) {
	k1, l1 := genKey(t)
	k2, l2 := genKey(t)
	f := Parse([]byte(l1 + " a@x\n" + l2 + " b@y\n"))

	removed := f.Remove(Matcher{Key: k1})
	if len(removed) != 1 || removed[0].Key == nil {
		t.Fatalf("remove by material: %v", removed)
	}
	if len(f.Find(Matcher{Key: k1})) != 0 || len(f.Find(Matcher{Key: k2})) != 1 {
		t.Fatal("wrong survivor set")
	}

	f = Parse([]byte(l1 + "\n" + l2 + "\n"))
	removed = f.Remove(Matcher{FingerprintSHA256: Fingerprint(k2)})
	if len(removed) != 1 {
		t.Fatalf("remove by fingerprint: %v", removed)
	}
	if len(f.Find(Matcher{Key: k1})) != 1 {
		t.Fatal("fingerprint removal took the wrong key")
	}
	// Options-bearing lines still match by key material.
	f = Parse([]byte(`no-agent-forwarding,command="/bin/true" ` + l1 + "\n"))
	if len(f.Find(Matcher{Key: k1})) != 1 {
		t.Fatal("options line not matched")
	}
}

func TestAddDedupes(t *testing.T) {
	k1, l1 := genKey(t)
	f := Parse([]byte(l1 + " existing@comment\n"))
	if f.Add(k1, "dup") {
		t.Fatal("added a duplicate key")
	}
	k2, _ := genKey(t)
	if !f.Add(k2, "fresh@host") {
		t.Fatal("failed to add a fresh key")
	}
	out := string(f.Render())
	if !strings.Contains(out, "fresh@host") || strings.Contains(out, "dup") {
		t.Fatalf("render wrong: %q", out)
	}
}

func TestParseKeySpec(t *testing.T) {
	k, line := genKey(t)
	m, comment, err := ParseKeySpec(line + " who@where")
	if err != nil || m.Key == nil || comment != "who@where" {
		t.Fatalf("literal spec: m=%v comment=%q err=%v", m, comment, err)
	}
	fp := Fingerprint(k)
	m, _, err = ParseKeySpec(fp)
	if err != nil || m.FingerprintSHA256 != fp {
		t.Fatalf("fingerprint spec: %v err=%v", m, err)
	}
	if _, _, err := ParseKeySpec("not a key"); err == nil {
		t.Fatal("garbage spec accepted")
	}
}
