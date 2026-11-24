package provider

// A saved Claude account whose keychain item can't be read (the login
// keychain out of reach from an ssh session: `security` exits 36,
// errSecInteractionNotAllowed) is unknown. The file Claude Code emptied
// beside it once it kept the sign-in in the keychain is not read in its
// place, so the account is not marked refused, and no file is written
// with the saved sign-in to become a second holder of its refresh token.

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/yetone/magpie/internal/testenv"
)

func emptiedClaudeFileBeside(t *testing.T, exit int) (Provider, savedLogin, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("a shell script stands in for the keychain")
	}
	p, side := claudeAuthFixture(t, "")
	dir := claudeAccountDir(side.User)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	creds := filepath.Join(dir, ".credentials.json")
	writeFile(t, creds, map[string]any{"claudeAiOauth": map[string]any{
		"accessToken": "", "refreshToken": "", "expiresAt": 0, "subscriptionType": "max",
	}})
	bin := t.TempDir()
	testenv.Program(t, filepath.Join(bin, "security"), "#!/bin/sh\nexit "+strconv.Itoa(exit)+"\n")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	old := claudeKeychain
	claudeKeychain = true
	t.Cleanup(func() { claudeKeychain = old })
	return p, side, creds
}

func TestClaudeUnreadKeychainIsNotARefusedSignIn(t *testing.T) {
	p, side, creds := emptiedClaudeFileBeside(t, 36)
	_, err := sideToken(t, p, side.User)
	if !errors.Is(err, errClaudeKeychainUnread) {
		t.Fatalf("run on an unreadable keychain: %v", err)
	}
	if ClaudeSignInRequired(err.Error()) {
		t.Fatalf("an unreadable keychain reads as a sign-in to make again: %v", err)
	}
	if l := claudeLapseOf(side.User); l != "" {
		t.Fatalf("marked lapsed for a keychain it couldn't read: %q", l)
	}
	for _, l := range readLogins() {
		if strings.EqualFold(l.User, side.User) && l.Refused != "" {
			t.Fatalf("refused kept: %q", l.Refused)
		}
	}
	if b, _ := os.ReadFile(creds); strings.Contains(string(b), "old-refresh") {
		t.Fatal("the saved sign-in was written beside the keychain: a second holder of its refresh token")
	}
}

// An item that isn't there (exit 44) still leaves the file as Claude
// Code's word, emptied or not: what it read before stands.
func TestClaudeMissingKeychainItemStillReadsTheFile(t *testing.T) {
	p, side, _ := emptiedClaudeFileBeside(t, 44)
	if _, err := sideToken(t, p, side.User); err == nil {
		t.Fatal("ran on a sign-in Claude Code emptied")
	}
	if claudeLapseOf(side.User) != claudeAuthLapse {
		t.Fatalf("lapse: %q", claudeLapseOf(side.User))
	}
}
