package remote

import "testing"

func TestQuote(t *testing.T) {
	cases := map[string]string{
		"plain":      "'plain'",
		"with space": "'with space'",
		"it's":       `'it'\''s'`,
		"a`b$(x)\\":  "'a`b$(x)\\'",
		"":           "''",
	}
	for in, want := range cases {
		if got := Quote(in); got != want {
			t.Errorf("Quote(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestValidUsername(t *testing.T) {
	for _, ok := range []string{"root", "alice", "a.b-c_d", "user1", "_apt"} {
		if !ValidUsername(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "-flag", "a b", "a;b", "a'b", "a$b", "a/b"} {
		if ValidUsername(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
}
