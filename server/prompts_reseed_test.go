package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The reseed guard decides whether a shipped default may replace a stored prompt, so its
// fingerprinting has to be stable and collision-resistant in the obvious ways.
func TestPromptHashAndGuardKey(t *testing.T) {
	if got, want := defaultHashKey("planner"), "prompt_default_hash_planner"; got != want {
		t.Errorf("defaultHashKey = %q, want %q", got, want)
	}
	body := "You are the planner."
	h := promptHash(body)
	if len(h) != 64 {
		t.Errorf("promptHash returned %d hex chars, want 64", len(h))
	}
	if h != promptHash(body) {
		t.Error("promptHash is not deterministic")
	}
	for _, other := range []string{"You are the planner", "You are the planner. ", "you are the planner."} {
		if promptHash(other) == h {
			t.Errorf("promptHash collided with %q", other)
		}
	}
}

// Every shipped skill is loaded from a directory by name and shown to the agents by its
// frontmatter, so a malformed one is invisible rather than broken: assert the shape instead.
func TestSkillDirsHaveValidFrontmatter(t *testing.T) {
	root := filepath.Join("..", "skills")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read skills dir: %v", err)
	}
	checked := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if strings.ContainsRune(e.Name(), os.PathSeparator) {
			t.Errorf("unexpected nested entry %q in the skills root", e.Name())
			continue
		}
		path := filepath.Join(root, e.Name(), "SKILL.md")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("%s: missing SKILL.md", e.Name())
			continue
		}
		body := string(raw)
		if !strings.HasPrefix(body, "---\n") {
			t.Errorf("%s: SKILL.md must start with a YAML frontmatter block", e.Name())
			continue
		}
		end := strings.Index(body[4:], "\n---")
		if end < 0 {
			t.Errorf("%s: frontmatter is not closed", e.Name())
			continue
		}
		front := body[4 : 4+end]
		if !strings.Contains(front, "name: "+e.Name()) {
			t.Errorf("%s: frontmatter name must equal the directory name", e.Name())
		}
		if !strings.Contains(front, "description:") {
			t.Errorf("%s: frontmatter has no description", e.Name())
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no skill directories checked")
	}
}
