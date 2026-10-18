// Command relsign is VANGUARD's small release-assurance tool. It uses only the
// Go standard library and has no network access.
//
//	relsign manifest       -dir D -version V -commit C -dirty yes|no -go "go version ..." -build-date T [-sign-key-id ID] [-toolchain-below-min]
//	relsign manifest-check -dir D [-pub FILE]
//	relsign validate-sbom  -in FILE
//	relsign keygen         -private FILE -public FILE
//	relsign pubkey         -private FILE
//	relsign sign           -private FILE -in FILE -out FILE.sig
//	relsign verify         -public FILE -in FILE -sig FILE.sig
//
// What a signature here means: the holder of the private key signed the exact
// bytes of the file (SHA-256) at some time. It says nothing about whether the
// key is trustworthy; that depends on how you obtained the PUBLIC key
// (docs/PHASE17.md). A checksum, by contrast, only detects corruption.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	manifestName  = "RELEASE-MANIFEST.json"
	sumsName      = "SHA256SUMS"
	sigFormat     = "vanguard-release-signature-v1"
	manifestVer   = 1
	artifactRegex = `^vanguard-(.+)-(linux|darwin|windows)-(amd64|arm64)(\.exe)?$`
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "manifest":
		err = cmdManifest(os.Args[2:])
	case "manifest-check":
		err = cmdManifestCheck(os.Args[2:])
	case "validate-sbom":
		err = cmdValidateSBOM(os.Args[2:])
	case "keygen":
		err = cmdKeygen(os.Args[2:])
	case "pubkey":
		err = cmdPubkey(os.Args[2:])
	case "sign":
		err = cmdSign(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "relsign:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: relsign manifest|manifest-check|validate-sbom|keygen|pubkey|sign|verify [flags]")
	os.Exit(2)
}

// ---------------------------------------------------------------- helpers

func fileSHA256(path string) (string, int64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), int64(len(b)), nil
}

// ---------------------------------------------------------------- manifest

// Artifact is one released binary.
type Artifact struct {
	File       string   `json:"file"`
	OS         string   `json:"os"`
	Arch       string   `json:"arch"`
	Size       int64    `json:"size_bytes"`
	SHA256     string   `json:"sha256"`
	SBOM       *SBOMRef `json:"sbom"`
	SBOMStatus string   `json:"sbom_status"`
}

// SBOMRef points at the SBOM that describes an artifact.
type SBOMRef struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Format string `json:"format"`
}

// Manifest ties artifacts to build metadata. It is JSON so tools can read it;
// it is itself covered by SHA256SUMS (and by its signature when signed).
type Manifest struct {
	Format    int        `json:"format"`
	Version   string     `json:"version"`
	Commit    string     `json:"commit"`
	Dirty     bool       `json:"dirty_tree"`
	BuildDate string     `json:"build_date"`
	GoVersion string     `json:"go_version"`
	Flags     string     `json:"build_flags"`
	BelowMin  bool       `json:"toolchain_below_required_minimum"`
	Artifacts []Artifact `json:"artifacts"`
	// Signature records the INTENT recorded at build time: which key id will
	// sign SHA256SUMS. The signature itself is the detached file SHA256SUMS.sig.
	Signature *struct {
		File      string `json:"file"`
		Algorithm string `json:"algorithm"`
		KeyID     string `json:"key_id"`
		Covers    string `json:"covers"`
	} `json:"signature"`
	Notes []string `json:"notes"`
}

func cmdManifest(args []string) error {
	fs := flag.NewFlagSet("manifest", flag.ContinueOnError)
	dir := fs.String("dir", "", "release directory")
	version := fs.String("version", "", "")
	commit := fs.String("commit", "unknown", "")
	dirty := fs.String("dirty", "unknown", "yes|no")
	goVer := fs.String("go", "", "output of `go version`")
	date := fs.String("build-date", "", "")
	keyID := fs.String("sign-key-id", "", "key id that will sign SHA256SUMS (empty = unsigned)")
	below := fs.Bool("toolchain-below-min", false, "the build used a toolchain older than deploy/MIN_GO_TOOLCHAIN")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *version == "" {
		return errors.New("-dir and -version are required")
	}
	m := Manifest{Format: manifestVer, Version: *version, Commit: *commit, Dirty: *dirty == "yes", BuildDate: *date, GoVersion: *goVer,
		Flags: "CGO_ENABLED=0 -trimpath -buildvcs=false -ldflags '-s -w -X main.version=<version> -X main.buildDate=<build date>'", BelowMin: *below}
	re := regexp.MustCompile(artifactRegex)
	ents, err := os.ReadDir(*dir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		name := e.Name()
		sm := re.FindStringSubmatch(name)
		if sm == nil || e.IsDir() {
			continue
		}
		sum, size, err := fileSHA256(filepath.Join(*dir, name))
		if err != nil {
			return err
		}
		a := Artifact{File: name, OS: sm[2], Arch: sm[3], Size: size, SHA256: sum, SBOMStatus: "not generated: no SBOM tool was available at build time"}
		sbom := name + ".cdx.json"
		if ssum, _, err := fileSHA256(filepath.Join(*dir, sbom)); err == nil {
			a.SBOM = &SBOMRef{File: sbom, SHA256: ssum, Format: "CycloneDX JSON"}
			a.SBOMStatus = "generated and structurally validated (see docs/PHASE17.md for what that does and does not mean)"
		}
		m.Artifacts = append(m.Artifacts, a)
	}
	if len(m.Artifacts) == 0 {
		return errors.New("no artifacts named vanguard-<version>-<os>-<arch> found")
	}
	sort.Slice(m.Artifacts, func(i, j int) bool { return m.Artifacts[i].File < m.Artifacts[j].File })
	if *keyID != "" {
		m.Signature = &struct {
			File      string `json:"file"`
			Algorithm string `json:"algorithm"`
			KeyID     string `json:"key_id"`
			Covers    string `json:"covers"`
		}{File: sumsName + ".sig", Algorithm: "ed25519", KeyID: *keyID, Covers: sumsName}
	}
	m.Notes = []string{
		"A checksum detects corruption; it does not identify the publisher.",
		"A signature identifies the holder of a private key only if you obtained the matching public key from a source you trust.",
		"This build was produced on one machine; no cross-machine reproducibility is claimed unless docs/PHASE17.md says it was observed.",
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	return os.WriteFile(filepath.Join(*dir, manifestName), append(b, '\n'), 0o644)
}

func cmdManifestCheck(args []string) error {
	fs := flag.NewFlagSet("manifest-check", flag.ContinueOnError)
	dir := fs.String("dir", "", "release directory")
	pub := fs.String("pub", "", "public key file: also verify SHA256SUMS.sig")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var problems []string
	add := func(f string, a ...any) { problems = append(problems, fmt.Sprintf(f, a...)) }
	raw, err := os.ReadFile(filepath.Join(*dir, manifestName))
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", manifestName, err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("%s is not valid JSON: %w", manifestName, err)
	}
	if m.Format != manifestVer {
		add("unknown manifest format %d", m.Format)
	}
	listed := map[string]bool{}
	re := regexp.MustCompile(artifactRegex)
	for _, a := range m.Artifacts {
		listed[a.File] = true
		if sm := re.FindStringSubmatch(a.File); sm == nil || sm[2] != a.OS || sm[3] != a.Arch {
			add("%s: file name does not match its declared os/arch (%s/%s)", a.File, a.OS, a.Arch)
		}
		sum, size, err := fileSHA256(filepath.Join(*dir, a.File))
		switch {
		case err != nil:
			add("%s: listed but missing", a.File)
		case sum != a.SHA256:
			add("%s: SHA-256 differs from the manifest", a.File)
		case size != a.Size:
			add("%s: size differs from the manifest", a.File)
		}
		if a.SBOM != nil {
			listed[a.SBOM.File] = true
			if s, _, err := fileSHA256(filepath.Join(*dir, a.SBOM.File)); err != nil {
				add("%s: SBOM listed but missing", a.File)
			} else if s != a.SBOM.SHA256 {
				add("%s: SBOM SHA-256 differs from the manifest", a.File)
			} else if _, err := validateSBOMFile(filepath.Join(*dir, a.SBOM.File)); err != nil {
				add("%s: SBOM does not validate: %v", a.File, err)
			}
		}
	}
	ents, _ := os.ReadDir(*dir)
	for _, e := range ents {
		if re.MatchString(e.Name()) && !listed[e.Name()] {
			add("%s: an artifact that the manifest does not list", e.Name())
		}
	}
	// SHA256SUMS must agree with the manifest for every artifact it names
	if sums, err := os.ReadFile(filepath.Join(*dir, sumsName)); err == nil {
		seen := map[string]string{}
		for _, l := range strings.Split(string(sums), "\n") {
			f := strings.Fields(l)
			if len(f) == 2 {
				seen[strings.TrimPrefix(f[1], "*")] = f[0]
			}
		}
		for _, a := range m.Artifacts {
			if s, ok := seen[a.File]; !ok || s != a.SHA256 {
				add("%s: missing from or different in %s", a.File, sumsName)
			}
		}
		if s, ok := seen[manifestName]; ok {
			if ms, _, _ := fileSHA256(filepath.Join(*dir, manifestName)); ms != s {
				add("%s does not match %s", manifestName, sumsName)
			}
		}
	} else {
		add("%s is missing", sumsName)
	}
	if m.Signature != nil {
		sigPath := filepath.Join(*dir, m.Signature.File)
		if _, err := os.Stat(sigPath); err != nil {
			add("the manifest says the release is signed but %s is missing", m.Signature.File)
		} else if *pub != "" {
			if err := verifyFile(*pub, filepath.Join(*dir, sumsName), sigPath); err != nil {
				add("signature: %v", err)
			}
		}
	} else if _, err := os.Stat(filepath.Join(*dir, sumsName+".sig")); err == nil {
		add("a signature file exists but the manifest records an unsigned release")
	}
	if len(problems) > 0 {
		for _, p := range problems {
			fmt.Fprintln(os.Stderr, "MISMATCH:", p)
		}
		return fmt.Errorf("%d problem(s)", len(problems))
	}
	signed := "UNSIGNED"
	if m.Signature != nil {
		signed = "signature file present"
		if *pub != "" {
			signed = "signature VERIFIED against the supplied public key"
		}
	}
	fmt.Printf("manifest matches %d artifact(s); %s\n", len(m.Artifacts), signed)
	return nil
}

// ---------------------------------------------------------------- SBOM

var purlRE = regexp.MustCompile(`^pkg:[a-z]+/.+@.+`)
var absPathRE = regexp.MustCompile(`\b[A-Za-z]:\\|"/(home|Users|root|tmp|var)/`)

func validateSBOMFile(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var d struct {
		BomFormat    string `json:"bomFormat"`
		SpecVersion  string `json:"specVersion"`
		SerialNumber string `json:"serialNumber"`
		Version      int    `json:"version"`
		Metadata     struct {
			Tools json.RawMessage `json:"tools"`
		} `json:"metadata"`
		Components []struct {
			BomRef  string `json:"bom-ref"`
			Name    string `json:"name"`
			Version string `json:"version"`
			Purl    string `json:"purl"`
			Type    string `json:"type"`
		} `json:"components"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return 0, fmt.Errorf("not valid JSON: %w", err)
	}
	switch {
	case d.BomFormat != "CycloneDX":
		return 0, fmt.Errorf("bomFormat is %q, want CycloneDX", d.BomFormat)
	case !regexp.MustCompile(`^1\.[4-9]$`).MatchString(d.SpecVersion):
		return 0, fmt.Errorf("unsupported specVersion %q", d.SpecVersion)
	case !regexp.MustCompile(`^urn:uuid:[0-9a-f-]{36}$`).MatchString(d.SerialNumber):
		return 0, errors.New("serialNumber is not a urn:uuid")
	case d.Version < 1:
		return 0, errors.New("version must be >= 1")
	case !strings.Contains(string(d.Metadata.Tools), "\"name\"") || !strings.Contains(string(d.Metadata.Tools), "\"version\""):
		return 0, errors.New("metadata.tools is missing: the generating tool and version must be recorded")
	case len(d.Components) == 0:
		return 0, errors.New("no components")
	}
	refs := map[string]bool{}
	for i, c := range d.Components {
		if c.Name == "" || c.Version == "" || c.Type == "" {
			return 0, fmt.Errorf("component %d lacks name/version/type", i)
		}
		if !purlRE.MatchString(c.Purl) {
			return 0, fmt.Errorf("component %s has no valid purl", c.Name)
		}
		if c.BomRef != "" {
			if refs[c.BomRef] {
				return 0, fmt.Errorf("duplicate bom-ref %q", c.BomRef)
			}
			refs[c.BomRef] = true
		}
	}
	if m := absPathRE.FindString(string(b)); m != "" {
		return 0, fmt.Errorf("the document contains what looks like a local filesystem path (%q)", m)
	}
	return len(d.Components), nil
}

func cmdValidateSBOM(args []string) error {
	fs := flag.NewFlagSet("validate-sbom", flag.ContinueOnError)
	in := fs.String("in", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	n, err := validateSBOMFile(*in)
	if err != nil {
		return err
	}
	fmt.Printf("structurally valid CycloneDX document with %d components (this is a structural check, not validation against the official JSON schema)\n", n)
	return nil
}

// ---------------------------------------------------------------- signing

type sigFile struct {
	Format    string `json:"format"`
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	File      string `json:"file"`
	SHA256    string `json:"file_sha256"`
	Signature string `json:"signature"`
}

func keyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:8])
}

// message is what is actually signed: a domain tag, the file name and the
// SHA-256 of the file, so a signature cannot be replayed onto another file name
// or another format.
func message(name, sum string) []byte {
	return []byte(sigFormat + "\n" + name + "\n" + sum + "\n")
}

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	priv := fs.String("private", "", "private key file to create (must not exist; mode 0600)")
	pubf := fs.String("public", "", "public key file to create (must not exist)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *priv == "" || *pubf == "" {
		return errors.New("-private and -public are required")
	}
	pub, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*priv, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("cannot create the private key file (it must not exist): %w", err)
	}
	fmt.Fprintln(f, base64.StdEncoding.EncodeToString(sk.Seed()))
	f.Close()
	if err := os.WriteFile(*pubf, []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Printf("key id %s\nprivate key: %s (keep it OFF this repository and out of CI logs)\npublic key:  %s (publish it through a channel your users already trust)\n", keyID(pub), *priv, *pubf)
	return nil
}

func loadPrivate(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("the private key file is not a valid key")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func loadPublic(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("the public key file is not a valid key")
	}
	return ed25519.PublicKey(raw), nil
}

func cmdPubkey(args []string) error {
	fs := flag.NewFlagSet("pubkey", flag.ContinueOnError)
	priv := fs.String("private", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	sk, err := loadPrivate(*priv)
	if err != nil {
		return err
	}
	pub := sk.Public().(ed25519.PublicKey)
	fmt.Println(keyID(pub))
	return nil
}

func cmdSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	priv := fs.String("private", "", "")
	in := fs.String("in", "", "")
	out := fs.String("out", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	sk, err := loadPrivate(*priv)
	if err != nil {
		return err
	}
	sum, _, err := fileSHA256(*in)
	if err != nil {
		return err
	}
	name := filepath.Base(*in)
	s := sigFile{Format: sigFormat, Algorithm: "ed25519", KeyID: keyID(sk.Public().(ed25519.PublicKey)), File: name, SHA256: sum,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(sk, message(name, sum)))}
	b, _ := json.MarshalIndent(s, "", "  ")
	return os.WriteFile(*out, append(b, '\n'), 0o644)
}

func verifyFile(pubPath, in, sigPath string) error {
	pub, err := loadPublic(pubPath)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(sigPath)
	if err != nil {
		return err
	}
	var s sigFile
	if err := json.Unmarshal(raw, &s); err != nil || s.Format != sigFormat || s.Algorithm != "ed25519" {
		return errors.New("not a vanguard release signature")
	}
	if s.KeyID != keyID(pub) {
		return fmt.Errorf("signed by key %s, but the supplied public key is %s", s.KeyID, keyID(pub))
	}
	sum, _, err := fileSHA256(in)
	if err != nil {
		return err
	}
	if sum != s.SHA256 || filepath.Base(in) != s.File {
		return errors.New("the file differs from the one that was signed")
	}
	sig, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil || !ed25519.Verify(pub, message(s.File, sum), sig) {
		return errors.New("INVALID signature")
	}
	return nil
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	pub := fs.String("public", "", "")
	in := fs.String("in", "", "")
	sig := fs.String("sig", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := verifyFile(*pub, *in, *sig); err != nil {
		return err
	}
	p, _ := loadPublic(*pub)
	fmt.Printf("signature OK for %s (key id %s). This proves the key holder signed these bytes; trust in the key itself comes only from how you obtained %s.\n", filepath.Base(*in), keyID(p), *pub)
	return nil
}
