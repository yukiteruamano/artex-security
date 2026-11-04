package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A data volume the runtime user cannot write is the failure mode that made every agent command
// fail in a running deployment, so the start-up helper has to create the roots and, when it
// cannot, say what to do about it.
func TestEnsureWorkDirs(t *testing.T) {
	dir := t.TempDir()
	if err := EnsureWorkDirs(dir); err != nil {
		t.Fatalf("EnsureWorkDirs: %v", err)
	}
	for _, sub := range []string{"tasks", "sessions"} {
		info, err := os.Stat(filepath.Join(dir, sub))
		if err != nil || !info.IsDir() {
			t.Errorf("%s was not created: %v", sub, err)
		}
	}
	if err := EnsureWorkDirs(dir); err != nil {
		t.Errorf("a second call must be a no-op, got %v", err)
	}

	nested := filepath.Join(dir, "a", "b")
	if err := EnsureWorkDirs(nested); err != nil {
		t.Errorf("a nested data dir must be created: %v", err)
	}

	if err := EnsureWorkDirs(""); err == nil {
		t.Error("an empty data dir must be rejected")
	}

	// Root ignores permission bits, so only assert the diagnostic path when it can apply.
	if os.Geteuid() != 0 {
		ro := filepath.Join(dir, "ro")
		if err := os.Mkdir(ro, 0o555); err != nil {
			t.Fatal(err)
		}
		err := EnsureWorkDirs(ro)
		if err == nil {
			t.Fatal("an unwritable data dir must return an error")
		}
		if !strings.Contains(err.Error(), "chown -R") {
			t.Errorf("the error must name the fix, got: %v", err)
		}
	}
}
