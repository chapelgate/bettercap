package caplets

import (
	"archive/zip"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	EnvRemoteUpdate  = "BETTERCAP_CAPLETS_REMOTE_UPDATE"
	EnvCapletsURL    = "BETTERCAP_CAPLETS_URL"
	EnvCapletsSHA256 = "BETTERCAP_CAPLETS_SHA256"
	maxZipEntries    = 4000
	maxZipFile       = 8 << 20
	maxZipTotal      = 64 << 20
)

type RemoteSource struct {
	URL    string
	SHA256 string
	Ref    string
}

var (
	sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)
	tagRef    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

func AuthorizeRemoteUpdate() (RemoteSource, error) {
	if os.Getenv(EnvRemoteUpdate) != "1" {
		return RemoteSource{}, fmt.Errorf("caplets.update is disabled; set %s=1 plus %s and %s", EnvRemoteUpdate, EnvCapletsURL, EnvCapletsSHA256)
	}
	return ParseRemoteSource(os.Getenv(EnvCapletsURL), os.Getenv(EnvCapletsSHA256))
}

func ParseRemoteSource(rawURL, sum string) (RemoteSource, error) {
	sum = strings.ToLower(strings.TrimSpace(sum))
	if !sha256Hex.MatchString(sum) {
		return RemoteSource{}, fmt.Errorf("caplets checksum must be a SHA-256 hex digest")
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme != "https" || u.User != nil || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" {
		return RemoteSource{}, fmt.Errorf("caplets URL must be HTTPS with no user, query, or fragment")
	}
	host := strings.ToLower(u.Hostname())
	if host != "github.com" && host != "codeload.github.com" {
		return RemoteSource{}, fmt.Errorf("caplets URL host must be github.com or codeload.github.com")
	}
	ref, err := pinnedRef(host, u.EscapedPath())
	if err != nil {
		return RemoteSource{}, err
	}
	if floatingRef(ref) {
		return RemoteSource{}, fmt.Errorf("caplets URL must pin a commit or tag")
	}
	return RemoteSource{URL: u.String(), SHA256: sum, Ref: ref}, nil
}

func pinnedRef(host, escapedPath string) (string, error) {
	p := path.Clean("/" + escapedPath)
	switch host {
	case "github.com":
		if m := regexp.MustCompile(`^/bettercap/caplets/archive/([0-9a-fA-F]{40})\.zip$`).FindStringSubmatch(p); m != nil {
			return strings.ToLower(m[1]), nil
		}
		if m := regexp.MustCompile(`^/bettercap/caplets/archive/refs/tags/([^/]+)\.zip$`).FindStringSubmatch(p); m != nil {
			return checkTag(m[1])
		}
	case "codeload.github.com":
		if m := regexp.MustCompile(`^/bettercap/caplets/zip/([0-9a-fA-F]{40})$`).FindStringSubmatch(p); m != nil {
			return strings.ToLower(m[1]), nil
		}
		if m := regexp.MustCompile(`^/bettercap/caplets/zip/refs/tags/([^/]+)$`).FindStringSubmatch(p); m != nil {
			return checkTag(m[1])
		}
	}
	return "", fmt.Errorf("caplets URL is not a pinned bettercap/caplets archive")
}

func checkTag(tag string) (string, error) {
	tag, err := url.PathUnescape(tag)
	if err != nil || !tagRef.MatchString(tag) || strings.Contains(tag, "..") {
		return "", fmt.Errorf("caplets tag is not allowed")
	}
	if floatingRef(tag) {
		return "", fmt.Errorf("caplets URL must pin a commit or tag")
	}
	return tag, nil
}

func floatingRef(ref string) bool {
	switch strings.ToLower(ref) {
	case "master", "main", "head", "latest":
		return true
	default:
		return false
	}
}

func DownloadAndInstall(src RemoteSource, installBase, installPath, archivePath string) error {
	if err := assertPublicGitHub(src.URL); err != nil {
		return err
	}
	if err := downloadVerified(src, archivePath); err != nil {
		return err
	}
	defer os.Remove(archivePath)

	tmp, err := os.MkdirTemp(installBase, "caplets-unpack-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	root, err := extractZipSafely(archivePath, tmp)
	if err != nil {
		return err
	}
	if err = os.RemoveAll(installPath); err != nil {
		return err
	}
	return os.Rename(root, installPath)
}

func assertPublicGitHub(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	host := strings.ToLower(u.Hostname())
	if host != "github.com" && host != "codeload.github.com" {
		return fmt.Errorf("caplets URL host is not allowed")
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("caplets host lookup failed")
	}
	if len(ips) == 0 {
		return fmt.Errorf("caplets host has no addresses")
	}
	for _, ip := range ips {
		if !publicIP(ip) {
			return fmt.Errorf("caplets host resolved to a non-public address")
		}
	}
	return nil
}

func publicIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 0 || ip4[0] >= 240 || (ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 2) || (ip4[0] == 198 && ip4[1] == 51 && ip4[2] == 100) || (ip4[0] == 203 && ip4[1] == 0 && ip4[2] == 113) {
			return false
		}
	}
	return true
}

func downloadVerified(src RemoteSource, archivePath string) error {
	client := &http.Client{
		Timeout: 60 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			if req.URL.Scheme != "https" {
				return fmt.Errorf("redirect left https")
			}
			host := strings.ToLower(req.URL.Hostname())
			if host != "github.com" && host != "codeload.github.com" {
				return fmt.Errorf("redirect left the allowed hosts")
			}
			return nil
		},
	}
	resp, err := client.Get(src.URL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("caplets download status %d", resp.StatusCode)
	}

	partial := archivePath + ".partial"
	out, err := os.OpenFile(partial, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer os.Remove(partial)

	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, hash), io.LimitReader(resp.Body, maxZipTotal+1))
	closeErr := out.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if n > maxZipTotal {
		return fmt.Errorf("caplets download is too large")
	}
	if !digestMatches(hash.Sum(nil), src.SHA256) {
		return fmt.Errorf("caplets checksum does not match")
	}
	return os.Rename(partial, archivePath)
}

func digestMatches(got []byte, sum string) bool {
	want, err := hex.DecodeString(sum)
	if err != nil || len(want) != len(got) {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

func extractZipSafely(zipPath, dest string) (string, error) {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", err
	}
	defer r.Close()
	if len(r.File) == 0 || len(r.File) > maxZipEntries {
		return "", fmt.Errorf("caplets archive has an unexpected number of entries")
	}

	var total uint64
	roots := map[string]struct{}{}
	for _, f := range r.File {
		cleanName, full, err := safeZipPath(dest, f.Name)
		if err != nil {
			return "", err
		}
		top := strings.Split(cleanName, "/")[0]
		roots[top] = struct{}{}
		info := f.FileInfo()
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("caplets archive contains a symlink")
		}
		if info.IsDir() {
			if err = os.MkdirAll(full, 0755); err != nil {
				return "", err
			}
			continue
		}
		if f.UncompressedSize64 > maxZipFile {
			return "", fmt.Errorf("caplets archive entry is too large")
		}
		total += f.UncompressedSize64
		if total > maxZipTotal {
			return "", fmt.Errorf("caplets archive is too large")
		}
		if err = os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			return "", err
		}
		if err = writeZipFile(f, full); err != nil {
			return "", err
		}
	}
	if len(roots) != 1 {
		return "", fmt.Errorf("caplets archive must contain one top-level directory")
	}
	var rootName string
	for name := range roots {
		rootName = name
	}
	rootPath := filepath.Join(dest, rootName)
	st, err := os.Stat(rootPath)
	if err != nil || !st.IsDir() {
		return "", fmt.Errorf("caplets archive root is not a directory")
	}
	return rootPath, nil
}

func safeZipPath(dest, name string) (string, string, error) {
	name = strings.ReplaceAll(name, "\\", "/")
	if name == "" || path.IsAbs(name) || strings.Contains(name, "\x00") {
		return "", "", fmt.Errorf("zip entry path rejected")
	}
	clean := path.Clean(name)
	if clean == "." || clean == "/" || strings.HasPrefix(clean, "../") || clean == ".." {
		return "", "", fmt.Errorf("zip entry path rejected")
	}
	full := filepath.Join(dest, filepath.FromSlash(clean))
	rel, err := filepath.Rel(dest, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", "", fmt.Errorf("zip entry path rejected")
	}
	return clean, full, nil
}

func writeZipFile(f *zip.File, full string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.OpenFile(full, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer out.Close()
	n, err := io.Copy(out, io.LimitReader(rc, int64(maxZipFile)+1))
	if err != nil {
		return err
	}
	if n > maxZipFile {
		return fmt.Errorf("caplets archive entry is too large")
	}
	return nil
}
