package deploy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestImageProvidesTheAgentWorkspace pins the two image-level requirements without which the
// agents cannot execute a single command, whatever their prompt says:
//
//  1. bash exists. The agent Bash tool spawns /usr/bin/bash, and the python:slim base image does
//     not ship it, so every call failed with "fork/exec /usr/bin/bash: no such file or directory"
//     while the offensive tools it wanted were installed and on PATH.
//  2. the data directory is a volume owned by the unprivileged runtime user, so the per-task run
//     directories can be created at start-up instead of failing on the first tool call.
func TestImageProvidesTheAgentWorkspace(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "Dockerfile"))
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	text := string(raw)
	joined := strings.ReplaceAll(text, "\\\n", " ")

	t.Run("bash is installed", func(t *testing.T) {
		i := strings.Index(joined, "apt-get install")
		if i < 0 {
			t.Fatal("Dockerfile: no apt-get install block found")
		}
		line := joined[i:]
		if j := strings.Index(line, "\n"); j >= 0 {
			line = line[:j]
		}
		found := false
		for _, pkg := range strings.Fields(line) {
			if pkg == "bash" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Dockerfile: the apt package list must include bash (the agent Bash tool execs /usr/bin/bash): %s", line)
		}
	})

	t.Run("data directory is a volume owned by the runtime user", func(t *testing.T) {
		if !strings.Contains(text, `VOLUME ["/app/data"]`) {
			t.Error("Dockerfile: /app/data must stay a VOLUME (task and session work directories live there)")
		}
		if !strings.Contains(text, "chown -R ${ARTEX_UID}:${ARTEX_GID} /app") {
			t.Error("Dockerfile: /app must be owned by the unprivileged runtime user, or the agents cannot write their run directories")
		}
	})
}
