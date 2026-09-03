package main

import (
	"os"
	"path/filepath"
	"testing"
)

// withDotEnvPath temporarily redirects dotEnvPath to a test file and restores
// the original value (and clears any env vars the test set) on cleanup.
func withDotEnvPath(t *testing.T, path string) {
	t.Helper()
	orig := dotEnvPath
	dotEnvPath = path
	t.Cleanup(func() { dotEnvPath = orig })
}

// unsetEnv ensures a key is absent before the test runs and restores its
// prior state (present or absent) afterwards, so dotenv tests never leak
// into each other or into unrelated tests in this package.
func unsetEnv(t *testing.T, key string) {
	t.Helper()
	prevVal, wasSet := os.LookupEnv(key)
	os.Unsetenv(key)
	t.Cleanup(func() {
		if wasSet {
			os.Setenv(key, prevVal)
		} else {
			os.Unsetenv(key)
		}
	})
}

func writeTempEnvFile(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, ".env")
	if err := os.WriteFile(p, []byte(contents), 0o600); err != nil {
		t.Fatalf("failed to write temp .env file: %v", err)
	}
	return p
}

func TestLoadDotEnvFileMissingFileIsNoOp(t *testing.T) {
	withDotEnvPath(t, filepath.Join(t.TempDir(), "does-not-exist.env"))
	unsetEnv(t, "VANGUARD_TEST_MISSING")

	loadDotEnvFile() // must not panic or error on a missing file

	if v, ok := os.LookupEnv("VANGUARD_TEST_MISSING"); ok {
		t.Fatalf("expected VANGUARD_TEST_MISSING to remain unset, got %q", v)
	}
}

func TestLoadDotEnvFileSetsSimpleKeyValuePairs(t *testing.T) {
	unsetEnv(t, "TELEGRAM_BOT_TOKEN")
	unsetEnv(t, "TELEGRAM_CHAT_ID")
	path := writeTempEnvFile(t, "TELEGRAM_BOT_TOKEN=123:abc\nTELEGRAM_CHAT_ID=456789\n")
	withDotEnvPath(t, path)

	loadDotEnvFile()

	if got := os.Getenv("TELEGRAM_BOT_TOKEN"); got != "123:abc" {
		t.Errorf("TELEGRAM_BOT_TOKEN = %q, want %q", got, "123:abc")
	}
	if got := os.Getenv("TELEGRAM_CHAT_ID"); got != "456789" {
		t.Errorf("TELEGRAM_CHAT_ID = %q, want %q", got, "456789")
	}
}

func TestLoadDotEnvFileSkipsCommentsAndBlankLines(t *testing.T) {
	unsetEnv(t, "VANGUARD_TEST_FOO")
	path := writeTempEnvFile(t, "# a comment\n\n   \nVANGUARD_TEST_FOO=bar\n# trailing comment\n")
	withDotEnvPath(t, path)

	loadDotEnvFile()

	if got := os.Getenv("VANGUARD_TEST_FOO"); got != "bar" {
		t.Errorf("VANGUARD_TEST_FOO = %q, want %q", got, "bar")
	}
}

func TestLoadDotEnvFileStripsMatchingQuotes(t *testing.T) {
	unsetEnv(t, "VANGUARD_TEST_QUOTED")
	unsetEnv(t, "VANGUARD_TEST_SINGLE")
	path := writeTempEnvFile(t, `VANGUARD_TEST_QUOTED="hello world"`+"\n"+`VANGUARD_TEST_SINGLE='single quoted'`+"\n")
	withDotEnvPath(t, path)

	loadDotEnvFile()

	if got := os.Getenv("VANGUARD_TEST_QUOTED"); got != "hello world" {
		t.Errorf("VANGUARD_TEST_QUOTED = %q, want %q", got, "hello world")
	}
	if got := os.Getenv("VANGUARD_TEST_SINGLE"); got != "single quoted" {
		t.Errorf("VANGUARD_TEST_SINGLE = %q, want %q", got, "single quoted")
	}
}

func TestLoadDotEnvFileNeverOverwritesExistingEnvVar(t *testing.T) {
	unsetEnv(t, "VANGUARD_TEST_ALREADY_SET")
	os.Setenv("VANGUARD_TEST_ALREADY_SET", "real-value")
	path := writeTempEnvFile(t, "VANGUARD_TEST_ALREADY_SET=dotenv-value\n")
	withDotEnvPath(t, path)

	loadDotEnvFile()

	if got := os.Getenv("VANGUARD_TEST_ALREADY_SET"); got != "real-value" {
		t.Errorf("VANGUARD_TEST_ALREADY_SET = %q, want %q (real env must win)", got, "real-value")
	}
}

func TestLoadDotEnvFileSkipsMalformedAndEmptyKeyLines(t *testing.T) {
	unsetEnv(t, "VANGUARD_TEST_VALID")
	path := writeTempEnvFile(t, "this-line-has-no-equals\n=orphan_value\nVANGUARD_TEST_VALID=yes\n")
	withDotEnvPath(t, path)

	loadDotEnvFile()

	if got := os.Getenv("VANGUARD_TEST_VALID"); got != "yes" {
		t.Errorf("VANGUARD_TEST_VALID = %q, want %q", got, "yes")
	}
	if _, ok := os.LookupEnv("orphan_value"); ok {
		t.Errorf("expected no env var set from the malformed '=orphan_value' line")
	}
}
