package server

import (
	"fmt"
	"os"
	"path/filepath"
)

// EnsureWorkDirs creates the directories every agent run needs inside dataDir: the per-task run
// directories (tasks/, where each worker gets tasks/<id>/i<intent>/) and the chat session
// directories (sessions/). They are created at start-up on purpose: when the data volume is not
// writable by the runtime user - a bind mount owned by root is the usual cause - the operator gets
// one line naming the path, the uid and the fix, instead of every tool call in every run failing
// with a bare "permission denied" or "no such file or directory" that looks like a broken agent.
//
// The error is returned rather than logged here so the caller can decide how loud to be; it is
// never fatal, because the UI stays usable and is how the operator inspects the broken state.
func EnsureWorkDirs(dataDir string) error {
	if dataDir == "" {
		return fmt.Errorf("no data directory configured")
	}
	for _, sub := range []string{"tasks", "sessions"} {
		dir := filepath.Join(dataDir, sub)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("cannot create the agent work directory %s: %w (the data volume must be writable by uid %d gid %d; on the host: chown -R %d:%d data, or set ARTEX_UID=$(id -u))",
				dir, err, os.Getuid(), os.Getgid(), os.Getuid(), os.Getgid())
		}
	}
	return nil
}
