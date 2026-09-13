package moduleboundary

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestMaterialScopeGuard compares the complete crypto tree with its source baseline.
// A mismatch requires attribution; it must not be hidden by refreshing the baseline.
func TestMaterialScopeGuard(t *testing.T) {
	root := lifecycleModuleRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "internal/guards/moduleboundary/testdata/material_scope_baseline.json"))
	if err != nil {
		t.Fatal(err)
	}
	var baseline struct {
		Revision string
		Files    map[string]string
	}
	if err := json.Unmarshal(raw, &baseline); err != nil {
		t.Fatal(err)
	}
	if baseline.Revision == "" || len(baseline.Files) == 0 {
		t.Fatal("missing crypto source baseline")
	}
	seen := map[string]bool{}
	err = filepath.WalkDir(filepath.Join(root, "pkg/crypto"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		hash := sha256.Sum256(body)
		if baseline.Files[rel] != hex.EncodeToString(hash[:]) {
			t.Errorf("crypto source differs from baseline: %s", rel)
		}
		seen[rel] = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for name := range baseline.Files {
		if !seen[name] {
			t.Errorf("crypto source removed: %s", name)
		}
	}
	t.Logf("crypto scope: %d files compared with %s", len(seen), baseline.Revision)
}
