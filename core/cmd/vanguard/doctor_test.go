package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"vanguard/core/internal/backup"
	"vanguard/core/internal/database"
)

func byName(cs []doctorCheck) map[string]doctorCheck {
	m := map[string]doctorCheck{}
	for _, c := range cs {
		m[c.Name] = c
	}
	return m
}

func baseOpts(t *testing.T) doctorOptions {
	dir := t.TempDir()
	return doctorOptions{DBPath: filepath.Join(dir, "v.db"), HTTPAddr: "127.0.0.1:8080", AuthLog: ""}
}

func TestDoctor_FreshHost(t *testing.T) {
	o := baseOpts(t)
	c := byName(runDoctor(context.Background(), o))
	if c["db_file"].Status != checkOK || !strings.Contains(c["db_file"].Detail, "will be created") {
		t.Fatalf("%+v", c["db_file"])
	}
	if c["listen_address"].Status != checkOK {
		t.Fatalf("%+v", c["listen_address"])
	}
	for _, name := range []string{"ufw", "health", "env_file", "auth_log"} {
		if c[name].Status != checkSkip {
			t.Errorf("%s should be skipped unless requested: %+v", name, c[name])
		}
	}
	if c["backup_dir"].Status != checkWarn {
		t.Errorf("no backups yet is advice, not a failure: %+v", c["backup_dir"])
	}
}

func TestDoctor_MissingDatabaseDirectoryFails(t *testing.T) {
	o := baseOpts(t)
	o.DBPath = filepath.Join(t.TempDir(), "nope", "v.db")
	if c := byName(runDoctor(context.Background(), o)); c["db_directory"].Status != checkFail {
		t.Fatalf("%+v", c["db_directory"])
	}
}

func TestDoctor_IsReadOnly_AndSeesSchemaState(t *testing.T) {
	o := baseOpts(t)
	db, err := database.Open(database.Config{Path: o.DBPath})
	if err != nil {
		t.Fatal(err)
	}
	// keep a writer connection open: doctor must work against a live database
	defer db.Close()
	before := dirSnapshot(t, filepath.Dir(o.DBPath))
	c := byName(runDoctor(context.Background(), o))
	if c["db_integrity"].Status != checkOK || c["db_schema"].Status != checkOK {
		t.Fatalf("a healthy current database: integrity=%+v schema=%+v", c["db_integrity"], c["db_schema"])
	}
	after := dirSnapshot(t, filepath.Dir(o.DBPath))
	for name, size := range before {
		if strings.HasSuffix(name, "-wal") || strings.HasSuffix(name, "-shm") {
			continue // SQLite's own sidecars may be touched by any reader
		}
		if after[name] != size {
			t.Fatalf("doctor modified %s (%d -> %d bytes)", name, size, after[name])
		}
	}
	for name := range after {
		if _, ok := before[name]; !ok && !strings.HasSuffix(name, "-wal") && !strings.HasSuffix(name, "-shm") {
			t.Fatalf("doctor created %s", name)
		}
	}
}

func dirSnapshot(t *testing.T, dir string) map[string]int64 {
	t.Helper()
	m := map[string]int64{}
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range es {
		if st, err := e.Info(); err == nil {
			m[e.Name()] = st.Size()
		}
	}
	return m
}

func TestDoctor_NewerSchemaIsAFailure_PendingMigrationIsAWarning(t *testing.T) {
	// legacy database: migration will add tables -> warn (backup first), not fail
	src, err := os.ReadFile(filepath.Join("..", "..", "internal", "backup", "testdata", "legacy_1208a94.db"))
	if err != nil {
		t.Fatal(err)
	}
	o := baseOpts(t)
	if err := os.WriteFile(o.DBPath, src, 0o600); err != nil {
		t.Fatal(err)
	}
	c := byName(runDoctor(context.Background(), o))
	if c["db_schema"].Status != checkWarn || !strings.Contains(c["db_schema"].Detail, "backup") {
		t.Fatalf("a pending migration should warn and advise a backup: %+v", c["db_schema"])
	}

	// a database with a table this build does not know -> fail (no downgrade)
	o2 := baseOpts(t)
	db, err := database.Open(database.Config{Path: o2.DBPath})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("CREATE TABLE from_the_future (id integer)").Error; err != nil {
		t.Fatal(err)
	}
	db.Close()
	c = byName(runDoctor(context.Background(), o2))
	if c["db_schema"].Status != checkFail || !strings.Contains(c["db_schema"].Detail, "NEWER") {
		t.Fatalf("%+v", c["db_schema"])
	}
}

func TestDoctor_CorruptDatabaseFails(t *testing.T) {
	o := baseOpts(t)
	if err := os.WriteFile(o.DBPath, []byte("this is not a sqlite database at all, just text padding "+strings.Repeat("x", 4096)), 0o600); err != nil {
		t.Fatal(err)
	}
	c := byName(runDoctor(context.Background(), o))
	if s := c["db_integrity"].Status; s == checkOK {
		t.Fatalf("garbage must never be reported ok: %+v", c["db_integrity"])
	}
}

func TestDoctor_EnvFile_SecretChecksNeverPrintTheValue(t *testing.T) {
	o := baseOpts(t)
	dir := t.TempDir()
	write := func(name, body string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(p, mode)
		return p
	}
	secret := strings.Repeat("A1b2", 12)
	o.EnvFile = write("good.env", "VANGUARD_JWT_SECRET="+secret+"\n", 0o600)
	cs := runDoctor(context.Background(), o)
	c := byName(cs)
	if c["jwt_secret"].Status != checkOK {
		t.Fatalf("%+v", c["jwt_secret"])
	}
	for _, x := range cs {
		if strings.Contains(x.Detail, secret) {
			t.Fatalf("the secret value was printed: %+v", x)
		}
	}

	o.EnvFile = write("short.env", "VANGUARD_JWT_SECRET=tooshort\n", 0o600)
	if c := byName(runDoctor(context.Background(), o)); c["jwt_secret"].Status != checkFail {
		t.Fatalf("a short secret would be refused by the daemon: %+v", c["jwt_secret"])
	}
	o.EnvFile = write("none.env", "# nothing\n", 0o600)
	if c := byName(runDoctor(context.Background(), o)); c["jwt_secret"].Status != checkWarn {
		t.Fatalf("%+v", c["jwt_secret"])
	}
	o.EnvFile = filepath.Join(dir, "missing.env")
	if c := byName(runDoctor(context.Background(), o)); c["env_file"].Status != checkFail {
		t.Fatalf("%+v", c["env_file"])
	}
	if runtime.GOOS != "windows" {
		o.EnvFile = write("open.env", "VANGUARD_JWT_SECRET="+secret+"\n", 0o644)
		if c := byName(runDoctor(context.Background(), o)); c["env_file_perms"].Status != checkFail {
			t.Fatalf("a world-readable secrets file must fail: %+v", c["env_file_perms"])
		}
	}
}

func TestDoctor_ListenAddressAdvice(t *testing.T) {
	o := baseOpts(t)
	o.HTTPAddr = ":8080"
	if c := byName(runDoctor(context.Background(), o)); c["listen_address"].Status != checkWarn {
		t.Fatalf("%+v", c["listen_address"])
	}
}

func TestDoctor_Health(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/health" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer ok.Close()
	o := baseOpts(t)
	o.HealthURL = ok.URL
	if c := byName(runDoctor(context.Background(), o)); c["health"].Status != checkOK || !strings.Contains(c["health"].Detail, "not that detectors are working") {
		t.Fatalf("%+v", c["health"])
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer bad.Close()
	o.HealthURL = bad.URL
	if c := byName(runDoctor(context.Background(), o)); c["health"].Status != checkFail {
		t.Fatalf("%+v", c["health"])
	}
	o.HealthURL = "http://127.0.0.1:1"
	o.HTTPClient = &http.Client{Timeout: 500 * time.Millisecond}
	if c := byName(runDoctor(context.Background(), o)); c["health"].Status != checkFail {
		t.Fatalf("%+v", c["health"])
	}
}

func TestDoctor_BackupDirectoryReport(t *testing.T) {
	o := baseOpts(t)
	db, err := database.Open(database.Config{Path: o.DBPath})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	root := defaultBackupDir(o.DBPath)
	if _, _, err := backup.Create(db, backup.CreateOptions{Dir: root, Label: "t", Actor: "test", Now: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	c := byName(runDoctor(context.Background(), o))
	if c["backup_dir"].Status != checkOK || !strings.Contains(c["backup_dir"].Detail, "1 backup") {
		t.Fatalf("%+v", c["backup_dir"])
	}
}

func TestDoctor_PermissionAdvice_Posix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows; run on Linux")
	}
	o := baseOpts(t)
	db, err := database.Open(database.Config{Path: o.DBPath})
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	_ = os.Chmod(o.DBPath, 0o644)
	_ = os.Chmod(filepath.Dir(o.DBPath), 0o777)
	c := byName(runDoctor(context.Background(), o))
	if c["db_perms"].Status != checkWarn || c["db_dir_perms"].Status != checkFail {
		t.Fatalf("db_perms=%+v db_dir_perms=%+v", c["db_perms"], c["db_dir_perms"])
	}
}

func TestVersionInfo(t *testing.T) {
	b := currentBuildInfo()
	if b.Version == "" || b.GoVersion == "" || b.OS == "" || b.Arch == "" {
		t.Fatalf("%+v", b)
	}
}

func TestValidateStartupPaths(t *testing.T) {
	dir := t.TempDir()
	ok := serveConfig{DBPath: filepath.Join(dir, "v.db")}
	if err := validateStartupPaths(&ok); err != nil {
		t.Fatal(err)
	}
	if err := validateStartupPaths(&serveConfig{DBPath: ":memory:"}); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, "afile")
	_ = os.WriteFile(f, []byte("x"), 0o600)
	for name, c := range map[string]serveConfig{
		"missing directory": {DBPath: filepath.Join(dir, "no", "such", "v.db")},
		"db is a directory": {DBPath: dir},
		"uri characters":    {DBPath: filepath.Join(dir, "v.db?mode=memory&cache=shared")},
		"backup dir a file": {DBPath: filepath.Join(dir, "v.db"), BackupDir: f},
	} {
		c := c
		if err := validateStartupPaths(&c); err == nil {
			t.Errorf("%s must fail startup", name)
		}
	}
}

func TestParseServeFlagsE_ReturnsErrorsInsteadOfExiting(t *testing.T) {
	var sink strings.Builder
	for name, args := range map[string][]string{
		"unknown flag":  {"-no-such-flag"},
		"short secret":  {"-jwt-secret", "short"},
		"queue range":   {"-ingest-queue", "0"},
		"query range":   {"-query-limit", "99"},
		"timeout range": {"-query-timeout", "1ms"},
		"bad admin ip":  {"-admin-ip", "10.0.0.0/8"},
		"missing dbdir": {"-db", filepath.Join(t.TempDir(), "x", "y", "v.db")},
		"origin *":      {"-allowed-origins", "*"},
		"bind no port":  {"-http-addr", "localhost"},
	} {
		if _, err := parseServeFlagsE(args, &sink); err == nil {
			t.Errorf("%s must be rejected", name)
		}
	}
	if _, err := parseServeFlagsE([]string{"-db", filepath.Join(t.TempDir(), "v.db"), "-jwt-secret", strings.Repeat("k", 32)}, &sink); err != nil {
		t.Fatalf("a valid configuration must parse: %v", err)
	}
}
