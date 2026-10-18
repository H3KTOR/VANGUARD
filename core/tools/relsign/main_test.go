package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const goodSBOM = `{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:4c8cc0a8-9d2e-47e8-8ddb-e2d0d5006f47","version":1,
"metadata":{"tools":{"components":[{"type":"application","name":"cyclonedx-gomod","version":"v1.12.0"}]}},
"components":[{"bom-ref":"pkg:golang/example.com/a@v1.0.0","type":"library","name":"example.com/a","version":"v1.0.0","purl":"pkg:golang/example.com/a@v1.0.0"}]}`

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func sumsOf(t *testing.T, dir string) {
	t.Helper()
	ents, _ := os.ReadDir(dir)
	var b strings.Builder
	for _, e := range ents {
		if e.Name() == "SHA256SUMS" || strings.HasSuffix(e.Name(), ".sig") {
			continue
		}
		d, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		h := sha256.Sum256(d)
		b.WriteString(hex.EncodeToString(h[:]) + "  " + e.Name() + "\n")
	}
	write(t, dir, "SHA256SUMS", b.String())
}

func release(t *testing.T, withSBOM bool, keyID string) string {
	t.Helper()
	d := t.TempDir()
	write(t, d, "vanguard-v1.0.0-linux-amd64", "binary-amd64")
	write(t, d, "vanguard-v1.0.0-linux-arm64", "binary-arm64")
	if withSBOM {
		write(t, d, "vanguard-v1.0.0-linux-amd64.cdx.json", goodSBOM)
		write(t, d, "vanguard-v1.0.0-linux-arm64.cdx.json", goodSBOM)
	}
	args := []string{"-dir", d, "-version", "v1.0.0", "-commit", "abc", "-dirty", "no", "-go", "go version go1.27.2 linux/amd64", "-build-date", "2026-10-10T00:00:00Z"}
	if keyID != "" {
		args = append(args, "-sign-key-id", keyID)
	}
	if err := cmdManifest(args); err != nil {
		t.Fatal(err)
	}
	sumsOf(t, d)
	return d
}

func TestManifestMatchesArtifacts_AndDetectsEveryKindOfDrift(t *testing.T) {
	d := release(t, true, "")
	if err := cmdManifestCheck([]string{"-dir", d}); err != nil {
		t.Fatalf("a freshly built release must check out: %v", err)
	}

	mut := map[string]func(dir string){
		"binary changed": func(dir string) { write(t, dir, "vanguard-v1.0.0-linux-amd64", "tampered") },
		"binary missing": func(dir string) { os.Remove(filepath.Join(dir, "vanguard-v1.0.0-linux-arm64")) },
		"unlisted artifact": func(dir string) {
			write(t, dir, "vanguard-v1.0.0-linux-amd64.exe", "x")
			write(t, dir, "vanguard-v1.0.0-windows-amd64.exe", "x")
		},
		"sbom changed": func(dir string) { write(t, dir, "vanguard-v1.0.0-linux-amd64.cdx.json", goodSBOM+" ") },
		"sbom missing": func(dir string) { os.Remove(filepath.Join(dir, "vanguard-v1.0.0-linux-amd64.cdx.json")) },
		"checksum file edited": func(dir string) {
			write(t, dir, "SHA256SUMS", strings.Replace(readFile(t, dir, "SHA256SUMS"), "a", "b", 1))
		},
		"manifest edited": func(dir string) {
			write(t, dir, "RELEASE-MANIFEST.json", strings.Replace(readFile(t, dir, "RELEASE-MANIFEST.json"), `"v1.0.0"`, `"v9.9.9"`, 1))
		},
		"checksums missing": func(dir string) { os.Remove(filepath.Join(dir, "SHA256SUMS")) },
		"stray signature":   func(dir string) { write(t, dir, "SHA256SUMS.sig", "{}") },
	}
	for name, f := range mut {
		dir := release(t, true, "")
		f(dir)
		if err := cmdManifestCheck([]string{"-dir", dir}); err == nil {
			t.Errorf("%s must be detected", name)
		}
	}
}

func readFile(t *testing.T, dir, name string) string {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestManifestWithoutSBOM_SaysSoHonestly(t *testing.T) {
	d := release(t, false, "")
	m := readFile(t, d, "RELEASE-MANIFEST.json")
	if !strings.Contains(m, `"sbom": null`) || !strings.Contains(m, "not generated") {
		t.Fatalf("the absence of an SBOM must be recorded as such:\n%s", m)
	}
	if err := cmdManifestCheck([]string{"-dir", d}); err != nil {
		t.Fatal(err)
	}
}

func TestSignAndVerify_AndWhatItDoesNotAccept(t *testing.T) {
	dir := t.TempDir()
	priv, pub := filepath.Join(dir, "k.priv"), filepath.Join(dir, "k.pub")
	if err := cmdKeygen([]string{"-private", priv, "-public", pub}); err != nil {
		t.Fatal(err)
	}
	if err := cmdKeygen([]string{"-private", priv, "-public", pub + "2"}); err == nil {
		t.Fatal("keygen must never overwrite an existing private key")
	}
	if st, _ := os.Stat(priv); st.Mode().Perm()&0o077 != 0 && !strings.Contains(strings.ToLower(os.Getenv("OS")), "windows") {
		t.Fatalf("private key mode %v", st.Mode().Perm())
	}
	write(t, dir, "SHA256SUMS", "abc  file\n")
	sig := filepath.Join(dir, "SHA256SUMS.sig")
	if err := cmdSign([]string{"-private", priv, "-in", filepath.Join(dir, "SHA256SUMS"), "-out", sig}); err != nil {
		t.Fatal(err)
	}
	if err := cmdVerify([]string{"-public", pub, "-in", filepath.Join(dir, "SHA256SUMS"), "-sig", sig}); err != nil {
		t.Fatalf("valid signature: %v", err)
	}
	// content changed
	write(t, dir, "SHA256SUMS", "abd  file\n")
	if err := cmdVerify([]string{"-public", pub, "-in", filepath.Join(dir, "SHA256SUMS"), "-sig", sig}); err == nil {
		t.Fatal("a modified file must fail verification")
	}
	write(t, dir, "SHA256SUMS", "abc  file\n")
	// same bytes under another name: the signature is bound to the file name
	other := filepath.Join(dir, "OTHER")
	write(t, dir, "OTHER", "abc  file\n")
	if err := cmdVerify([]string{"-public", pub, "-in", other, "-sig", sig}); err == nil {
		t.Fatal("a signature must not be replayable onto another file name")
	}
	// a different key is reported as a different key
	priv2, pub2 := filepath.Join(dir, "k2.priv"), filepath.Join(dir, "k2.pub")
	if err := cmdKeygen([]string{"-private", priv2, "-public", pub2}); err != nil {
		t.Fatal(err)
	}
	err := cmdVerify([]string{"-public", pub2, "-in", filepath.Join(dir, "SHA256SUMS"), "-sig", sig})
	if err == nil || !strings.Contains(err.Error(), "signed by key") {
		t.Fatalf("%v", err)
	}
	// edited signature bytes
	raw := readFile(t, dir, "SHA256SUMS.sig")
	i := strings.Index(raw, `"signature": "`) + len(`"signature": "`)
	flipped := raw[:i] + map[bool]string{true: "B", false: "A"}[raw[i] == 'A'] + raw[i+1:]
	write(t, dir, "SHA256SUMS.sig", flipped)
	if err := cmdVerify([]string{"-public", pub, "-in", filepath.Join(dir, "SHA256SUMS"), "-sig", sig}); err == nil {
		t.Fatal("a corrupted signature must fail")
	}
	// garbage keys
	write(t, dir, "bad.pub", "not base64 !!")
	if err := cmdVerify([]string{"-public", filepath.Join(dir, "bad.pub"), "-in", filepath.Join(dir, "SHA256SUMS"), "-sig", sig}); err == nil {
		t.Fatal("bad key file")
	}
}

func TestSignedRelease_ManifestCheckWithPublicKey(t *testing.T) {
	keys := t.TempDir()
	priv, pub := filepath.Join(keys, "k.priv"), filepath.Join(keys, "k.pub")
	if err := cmdKeygen([]string{"-private", priv, "-public", pub}); err != nil {
		t.Fatal(err)
	}
	sk, _ := loadPrivate(priv)
	_ = sk
	d := release(t, true, "will-be-checked")
	// the manifest claims a signature that is not there yet
	if err := cmdManifestCheck([]string{"-dir", d}); err == nil {
		t.Fatal("a manifest that promises a signature without the file must fail")
	}
	if err := cmdSign([]string{"-private", priv, "-in", filepath.Join(d, "SHA256SUMS"), "-out", filepath.Join(d, "SHA256SUMS.sig")}); err != nil {
		t.Fatal(err)
	}
	if err := cmdManifestCheck([]string{"-dir", d, "-pub", pub}); err != nil {
		t.Fatalf("a correctly signed release must verify: %v", err)
	}
	// a binary swapped after signing breaks the checksums, which breaks the signature coverage
	write(t, d, "vanguard-v1.0.0-linux-amd64", "swapped")
	if err := cmdManifestCheck([]string{"-dir", d, "-pub", pub}); err == nil {
		t.Fatal("a swapped binary must be caught")
	}
}

func TestValidateSBOM(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "ok.json", goodSBOM)
	if n, err := validateSBOMFile(filepath.Join(dir, "ok.json")); err != nil || n != 1 {
		t.Fatalf("%d %v", n, err)
	}
	bad := map[string]string{
		"not json":          "{",
		"wrong format":      strings.Replace(goodSBOM, "CycloneDX", "SPDX", 1),
		"old spec":          strings.Replace(goodSBOM, `"1.6"`, `"1.1"`, 1),
		"no serial":         strings.Replace(goodSBOM, "urn:uuid:4c8cc0a8-9d2e-47e8-8ddb-e2d0d5006f47", "x", 1),
		"no tool recorded":  strings.Replace(goodSBOM, `"metadata":{"tools":{"components":[{"type":"application","name":"cyclonedx-gomod","version":"v1.12.0"}]}}`, `"metadata":{}`, 1),
		"no components":     strings.Replace(goodSBOM, `"components":[{"bom-ref"`, `"x":[{"bom-ref"`, 1),
		"no purl":           strings.Replace(goodSBOM, `"purl":"pkg:golang/example.com/a@v1.0.0"`, `"purl":""`, 1),
		"local path leaked": strings.Replace(goodSBOM, `"name":"example.com/a"`, `"name":"C:\\Users\\bob\\src\\a"`, 1),
		"duplicate ref":     strings.Replace(goodSBOM, `"components":[{"bom-ref"`, `"components":[{"bom-ref":"pkg:golang/example.com/a@v1.0.0","type":"library","name":"b","version":"1","purl":"pkg:golang/b@1"},{"bom-ref"`, 1),
	}
	for name, body := range bad {
		write(t, dir, "bad.json", body)
		if _, err := validateSBOMFile(filepath.Join(dir, "bad.json")); err == nil {
			t.Errorf("%s must be rejected", name)
		}
	}
}
