package keychainauth

import (
	"strings"
	"testing"
)

func TestChecksumForAsset(t *testing.T) {
	list := "abc  keychain-auth_4.1.0_linux_amd64.tar.gz\ndef  keychain-auth_4.1.0_darwin_arm64.tar.gz\n"
	got, err := checksumForAsset(list, "keychain-auth_4.1.0_linux_amd64.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if got != "abc" {
		t.Errorf("digest = %q", got)
	}
	if _, err := checksumForAsset(list, "missing.tar.gz"); err == nil {
		t.Fatal("a missing asset must fail closed")
	}
	if strings.Contains(got, " ") {
		t.Fatalf("digest contains whitespace: %q", got)
	}
}
