package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSessionRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sess.json")
	orig := &Session{UUID: "0123456789abcdef0123456789abcdef", SessionKey: 1234567890}
	if err := orig.save(path); err != nil {
		t.Fatalf("save failed: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0600 {
		t.Fatalf("expected mode 0600, got %o", perm)
	}
	loaded, err := loadSession(path)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if loaded == nil || *loaded != *orig {
		t.Fatalf("round trip mismatch: %+v vs %+v", loaded, orig)
	}
}

func TestLoadSessionMissing(t *testing.T) {
	sess, err := loadSession(filepath.Join(t.TempDir(), "nonexistent.json"))
	if err != nil {
		t.Fatalf("expected nil error for missing file, got %v", err)
	}
	if sess != nil {
		t.Fatalf("expected nil session for missing file, got %+v", sess)
	}
}

func TestLoadSessionInvalid(t *testing.T) {
	dir := t.TempDir()

	badJSON := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badJSON, []byte("{nope"), 0600); err != nil {
		t.Fatal(err)
	}
	if sess, err := loadSession(badJSON); err != nil || sess != nil {
		t.Fatalf("expected nil session for invalid JSON, got %+v, %v", sess, err)
	}

	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, []byte(`{"uuid":"","sessionKey":0}`), 0600); err != nil {
		t.Fatal(err)
	}
	if sess, err := loadSession(empty); err != nil || sess != nil {
		t.Fatalf("expected nil session for empty fields, got %+v, %v", sess, err)
	}
}

func TestSessionSaveDisabled(t *testing.T) {
	sess := &Session{UUID: "abc", SessionKey: 1}
	if err := sess.save(""); err != nil {
		t.Fatalf("save with empty path should be a no-op, got %v", err)
	}
}
