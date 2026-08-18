// Package authkeys parses and edits OpenSSH authorized_keys content.
//
// Editing is line-preserving: comments, blank lines, options and unparseable
// lines pass through byte-for-byte. Only lines explicitly matched by an edit
// are touched, so a transaction's diff is exactly the requested change.
package authkeys

import (
	"bytes"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Line is one line of an authorized_keys file. Key is nil for blanks,
// comments, and lines that do not parse as a public key.
type Line struct {
	Raw     string
	Key     ssh.PublicKey
	Comment string
	Options []string
}

// File is parsed authorized_keys content.
type File struct {
	Lines []Line
	// noFinalNewline preserves a missing trailing newline on render.
	noFinalNewline bool
}

// Parse splits content into Lines. It never fails: unparseable lines are
// preserved as raw text with a nil Key.
func Parse(content []byte) *File {
	f := &File{}
	if len(content) == 0 {
		return f
	}
	if !bytes.HasSuffix(content, []byte("\n")) {
		f.noFinalNewline = true
	}
	for _, raw := range strings.Split(strings.TrimSuffix(string(content), "\n"), "\n") {
		l := Line{Raw: raw}
		trimmed := strings.TrimSpace(raw)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			if key, comment, options, _, err := ssh.ParseAuthorizedKey([]byte(raw)); err == nil {
				l.Key, l.Comment, l.Options = key, comment, options
			}
		}
		f.Lines = append(f.Lines, l)
	}
	return f
}

// Render reassembles the file content.
func (f *File) Render() []byte {
	if len(f.Lines) == 0 {
		return nil
	}
	var b bytes.Buffer
	for _, l := range f.Lines {
		b.WriteString(l.Raw)
		b.WriteByte('\n')
	}
	out := b.Bytes()
	if f.noFinalNewline {
		out = bytes.TrimSuffix(out, []byte("\n"))
	}
	return out
}

// Fingerprint returns the SHA256:... fingerprint of a public key.
func Fingerprint(k ssh.PublicKey) string { return ssh.FingerprintSHA256(k) }

// Matcher selects authorized_keys lines by key material or by SHA256
// fingerprint. Exactly one of Key / FingerprintSHA256 is set.
type Matcher struct {
	Key               ssh.PublicKey
	FingerprintSHA256 string // "SHA256:..." form
}

func (m Matcher) String() string {
	if m.Key != nil {
		return fmt.Sprintf("%s %s", m.Key.Type(), Fingerprint(m.Key))
	}
	return m.FingerprintSHA256
}

// Matches reports whether the line's key equals the matcher's target.
func (m Matcher) Matches(l Line) bool {
	if l.Key == nil {
		return false
	}
	if m.Key != nil {
		return bytes.Equal(l.Key.Marshal(), m.Key.Marshal())
	}
	return Fingerprint(l.Key) == m.FingerprintSHA256
}

// Find returns the parsed keys of all lines matched by m.
func (f *File) Find(m Matcher) []ssh.PublicKey {
	var out []ssh.PublicKey
	for _, l := range f.Lines {
		if m.Matches(l) {
			out = append(out, l.Key)
		}
	}
	return out
}

// Remove deletes every line matched by m and returns the removed lines.
func (f *File) Remove(m Matcher) []Line {
	var kept []Line
	var removed []Line
	for _, l := range f.Lines {
		if m.Matches(l) {
			removed = append(removed, l)
		} else {
			kept = append(kept, l)
		}
	}
	f.Lines = kept
	if len(f.Lines) == 0 {
		f.noFinalNewline = false
	}
	return removed
}

// Add appends an authorized_keys line for key (with optional comment) unless
// a line with the same key material already exists. Returns true if added.
func (f *File) Add(key ssh.PublicKey, comment string) bool {
	if len(f.Find(Matcher{Key: key})) > 0 {
		return false
	}
	raw := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	if comment != "" {
		raw += " " + comment
	}
	f.noFinalNewline = false
	f.Lines = append(f.Lines, Line{Raw: raw, Key: key, Comment: comment})
	return true
}

// ParseKeySpec turns a CLI key argument into a Matcher. Accepted forms:
// a SHA256:... fingerprint, a literal "type base64 [comment]" public key
// line, or raw file content of a .pub file. Literal/file forms also return
// the parsed key and its comment.
func ParseKeySpec(spec string) (Matcher, string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return Matcher{}, "", fmt.Errorf("empty key spec")
	}
	if strings.HasPrefix(spec, "SHA256:") {
		return Matcher{FingerprintSHA256: spec}, "", nil
	}
	key, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(spec))
	if err != nil {
		return Matcher{}, "", fmt.Errorf("key spec is neither a SHA256: fingerprint nor a public key line: %w", err)
	}
	return Matcher{Key: key}, comment, nil
}
