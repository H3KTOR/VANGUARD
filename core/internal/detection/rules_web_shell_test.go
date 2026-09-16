package detection

import "testing"

func TestClassifyWebShellRequest_ExtensionOnly(t *testing.T) {
	sig := classifyWebShellRequest("/blog/post.php")
	if !sig.hasExtension {
		t.Fatalf("expected .php path to match hasExtension")
	}
	if sig.inUploadPath || sig.suspiciousParam {
		t.Fatalf("expected ONLY hasExtension to match for an ordinary .php path, got %+v", sig)
	}
	if sig.count() != 1 {
		t.Fatalf("expected count()==1, got %d", sig.count())
	}
}

func TestClassifyWebShellRequest_UploadPathOnly(t *testing.T) {
	sig := classifyWebShellRequest("/uploads/user-avatar.png")
	if sig.hasExtension {
		t.Fatalf("expected .png (not a web-shell extension) to NOT match hasExtension")
	}
	if !sig.inUploadPath {
		t.Fatalf("expected /uploads/ path to match inUploadPath")
	}
	if sig.suspiciousParam {
		t.Fatalf("expected suspiciousParam to NOT match")
	}
}

func TestClassifyWebShellRequest_SuspiciousQueryParamOnly(t *testing.T) {
	sig := classifyWebShellRequest("/api/debug?cmd=whoami")
	if sig.hasExtension || sig.inUploadPath {
		t.Fatalf("expected ONLY suspiciousParam to match, got %+v", sig)
	}
	if !sig.suspiciousParam {
		t.Fatalf("expected 'cmd=' query param to match suspiciousParam")
	}
}

func TestClassifyWebShellRequest_AllThreeSignals(t *testing.T) {
	sig := classifyWebShellRequest("/uploads/shell.php?cmd=whoami")
	if !sig.hasExtension || !sig.inUploadPath || !sig.suspiciousParam {
		t.Fatalf("expected all three signals to match, got %+v", sig)
	}
	if sig.count() != 3 {
		t.Fatalf("expected count()==3, got %d", sig.count())
	}
	if !sig.any() {
		t.Fatalf("expected any() to be true")
	}
}

func TestClassifyWebShellRequest_ExtensionInQueryStringOnly_NoFalsePositive(t *testing.T) {
	// The requested resource itself is NOT a script -- ".php" only
	// appears inside a query-string value (e.g. a redirect target).
	// hasExtension must only look at the path portion before '?'.
	sig := classifyWebShellRequest("/redirect?to=/legit-page.php")
	if sig.hasExtension {
		t.Fatalf("expected hasExtension to NOT match when '.php' only appears in the query string, got %+v", sig)
	}
}

func TestClassifyWebShellRequest_OrdinaryRequest_NoSignals(t *testing.T) {
	cases := []string{
		"/",
		"/index.html",
		"/api/v1/users/123",
		"/static/style.css",
		"",
	}
	for _, path := range cases {
		sig := classifyWebShellRequest(path)
		if sig.any() {
			t.Errorf("expected ordinary path %q to match NO web-shell signals, got %+v", path, sig)
		}
	}
}

func TestClassifyWebShellRequest_CaseInsensitive(t *testing.T) {
	sig := classifyWebShellRequest("/UPLOADS/Shell.PHP?CMD=whoami")
	if !sig.hasExtension || !sig.inUploadPath || !sig.suspiciousParam {
		t.Fatalf("expected case-insensitive matching for all three signals, got %+v", sig)
	}
}
