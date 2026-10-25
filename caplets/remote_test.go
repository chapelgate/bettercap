package caplets

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestParseRemoteSourceRejectsUnpinnedAndPlain(t *testing.T) {
	sum := stringsRepeat("ab", 32)
	cases := []string{
		"",
		"http://github.com/bettercap/caplets/archive/0123456789abcdef0123456789abcdef01234567.zip",
		"https://github.com/bettercap/caplets/archive/master.zip",
		"https://github.com/bettercap/caplets/archive/refs/heads/master.zip",
		"https://github.com/bettercap/caplets/archive/refs/tags/master.zip",
		"https://github.com/bettercap/caplets/archive/refs/tags/main.zip",
		"https://example.com/bettercap/caplets/archive/0123456789abcdef0123456789abcdef01234567.zip",
		"https://github.com/other/caplets/archive/0123456789abcdef0123456789abcdef01234567.zip",
		"https://127.0.0.1/bettercap/caplets/archive/0123456789abcdef0123456789abcdef01234567.zip",
	}
	for _, raw := range cases {
		if _, err := ParseRemoteSource(raw, sum); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	if _, err := ParseRemoteSource("https://github.com/bettercap/caplets/archive/0123456789abcdef0123456789abcdef01234567.zip", "abcd"); err == nil {
		t.Fatal("accepted a short checksum")
	}
}

func TestParseRemoteSourceAcceptsPinnedCommitAndTag(t *testing.T) {
	sum := stringsRepeat("ab", 32)
	commit := "https://github.com/bettercap/caplets/archive/0123456789abcdef0123456789abcdef01234567.zip"
	got, err := ParseRemoteSource(commit, sum)
	if err != nil {
		t.Fatal(err)
	}
	if got.Ref != "0123456789abcdef0123456789abcdef01234567" {
		t.Fatalf("ref = %s", got.Ref)
	}
	tag := "https://codeload.github.com/bettercap/caplets/zip/refs/tags/v1.2.3"
	got, err = ParseRemoteSource(tag, stringsRepeat("CD", 32))
	if err != nil {
		t.Fatal(err)
	}
	if got.Ref != "v1.2.3" || got.SHA256 != stringsRepeat("cd", 32) {
		t.Fatalf("parsed %+v", got)
	}
}

func TestAuthorizeRemoteUpdateDefaultsOff(t *testing.T) {
	t.Setenv(EnvRemoteUpdate, "")
	t.Setenv(EnvCapletsURL, "https://github.com/bettercap/caplets/archive/0123456789abcdef0123456789abcdef01234567.zip")
	t.Setenv(EnvCapletsSHA256, stringsRepeat("ab", 32))
	if _, err := AuthorizeRemoteUpdate(); err == nil {
		t.Fatal("remote update ran without the flag")
	}
}

func TestDigestMatches(t *testing.T) {
	got := sha256.Sum256([]byte("caplet"))
	sum := hex.EncodeToString(got[:])
	if !digestMatches(got[:], sum) {
		t.Fatal("expected match")
	}
	if digestMatches(got[:], stringsRepeat("00", 32)) {
		t.Fatal("expected mismatch")
	}
}

func TestExtractZipSafely(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "caplets.zip")
	writeTestZip(t, zipPath, map[string]string{
		"caplets-0123456789abcdef0123456789abcdef01234567/demo.cap": "set",
	})
	dest := filepath.Join(dir, "out")
	if err := os.Mkdir(dest, 0755); err != nil {
		t.Fatal(err)
	}
	root, err := extractZipSafely(zipPath, dest)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(root, "demo.cap"))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "set" {
		t.Fatalf("body = %q", body)
	}
}

func TestExtractZipRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "bad.zip")
	writeTestZip(t, zipPath, map[string]string{
		"../evil.txt": "no",
	})
	dest := filepath.Join(dir, "out")
	if err := os.Mkdir(dest, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := extractZipSafely(zipPath, dest); err == nil {
		t.Fatal("accepted a traversing zip entry")
	}
	if _, err := os.Stat(filepath.Join(dir, "evil.txt")); !os.IsNotExist(err) {
		t.Fatal("zip slip wrote outside the destination")
	}
}

func writeTestZip(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := zip.NewWriter(f)
	defer w.Close()
	for name, body := range files {
		entry, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = entry.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
}

func stringsRepeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
