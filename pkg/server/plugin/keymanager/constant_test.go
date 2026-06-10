package keymanager

import "testing"

func TestIsSharedKeyID(t *testing.T) {
	cases := map[string]bool{
		JWTSignerKeyIDPrefix + "A": true,
		JWTSignerKeyIDPrefix + "B": true,
		X509CAKeyIDPrefix + "A":    false,
		WITSignerKeyIDPrefix + "A": false,
		"some-other-id":            false,
		"":                         false,
	}
	for id, want := range cases {
		if got := IsSharedKeyID(id); got != want {
			t.Errorf("IsSharedKeyID(%q) = %v, want %v", id, got, want)
		}
	}
}
