package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Session holds the reusable Hola session credentials. The file format
// is shared with python-hola's ~/.hola_session.json so both clients can
// reuse the same session.
type Session struct {
	UUID       string `json:"uuid"`
	SessionKey int64  `json:"sessionKey"`
}

func loadSession(path string) (*Session, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var sess Session
	if err := json.Unmarshal(data, &sess); err != nil {
		return nil, nil
	}
	if sess.UUID == "" || sess.SessionKey == 0 {
		return nil, nil
	}
	return &sess, nil
}

func (s *Session) save(path string) error {
	if path == "" || s == nil || s.UUID == "" || s.SessionKey == 0 {
		return nil
	}
	// Write to a temp file and rename so a crash mid-write cannot leave a
	// corrupt session file behind.
	f, err := os.CreateTemp(filepath.Dir(path), ".hola_session-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	// Enforce mode explicitly: O_CREATE's mode does not apply when the
	// target already exists with looser permissions (e.g. written by
	// python-hola under a permissive umask).
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if err := json.NewEncoder(f).Encode(s); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
