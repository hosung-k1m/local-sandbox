package trustrecord

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const FileName = "trust-record.json"

func Write(sessionDir string, record Record) error {
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("trust record: marshal envelope: %w", err)
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(sessionDir, ".trust-record-*.tmp")
	if err != nil {
		return fmt.Errorf("trust record: create temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("trust record: chmod temporary file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("trust record: write temporary file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("trust record: fsync temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("trust record: close temporary file: %w", err)
	}
	path := filepath.Join(sessionDir, FileName)
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("trust record: install envelope: %w", err)
	}
	dir, err := os.Open(sessionDir)
	if err != nil {
		return fmt.Errorf("trust record: open session directory for fsync: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("trust record: fsync session directory: %w", err)
	}
	return nil
}
