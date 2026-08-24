// Package staging is the handoff between the two halves of an update.
//
// The program downloads and verifies a new binary, writes it beside the current
// one, and records what it did. The shim reads that record at the next start
// and performs the swap. Nothing else crosses between them.
//
// Splitting it this way is what makes the swap simple. The program never
// replaces a running binary — by the time the shim acts, the target is not
// executing, so a plain rename works identically on Unix and Windows and there
// is no window in which the path is missing.
package staging

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/dbuslaev/selfupdate-agent/internal/fsutil"
)

// Record describes a staged binary awaiting installation.
type Record struct {
	// Target is the path the staged file should be renamed to.
	Target string `json:"target"`
	// Staged is the downloaded file.
	Staged string `json:"staged"`
	// Version is what the staged binary reports.
	Version string `json:"version"`
	// FromVersion is what is currently installed, kept so the shim can label
	// the trial without consulting the running binary.
	FromVersion string `json:"from_version"`
	// SHA256 is the digest the program verified against the signed manifest.
	SHA256 string `json:"sha256"`
	// StagedAt is when it was written, for diagnostics and staleness.
	StagedAt time.Time `json:"staged_at"`
}

// Write records a staged binary.
func Write(path string, r Record) error {
	r.StagedAt = time.Now().UTC()
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal staging record: %w", err)
	}
	return fsutil.WriteFileAtomic(path, append(data, '\n'), 0o644)
}

// Read returns the staging record, reporting whether one exists.
func Read(path string) (Record, bool, error) {
	raw, found, err := fsutil.ReadJSONFile(path)
	if err != nil || !found {
		return Record{}, false, err
	}
	var r Record
	if err := json.Unmarshal(raw, &r); err != nil {
		// A corrupt record means we cannot know what the staged file is, and a
		// binary we cannot describe must never be installed.
		return Record{}, false, fmt.Errorf("parse staging record: %w", err)
	}
	if err := r.validate(); err != nil {
		return Record{}, false, err
	}
	return r, true, nil
}

// Clear removes a staging record and its staged file.
func Clear(recordPath string, r Record) error {
	if r.Staged != "" {
		if err := fsutil.Remove(r.Staged); err != nil {
			return err
		}
	}
	return fsutil.Remove(recordPath)
}

// Verify re-checks the staged file against the digest in the record.
//
// The program already verified this against the signed manifest before writing
// it. Checking again costs a single hash and closes a real hole: without it,
// anyone who can write to the install directory gets code execution at the next
// start by dropping a file with the expected name. The shim needs no release key
// for this and consults nothing remote — it compares a hash it was handed.
func (r Record) Verify() error {
	digest, _, err := fsutil.SHA256File(r.Staged)
	if err != nil {
		return fmt.Errorf("hash staged binary: %w", err)
	}
	if digest != r.SHA256 {
		return fmt.Errorf("staged binary digest %s does not match record %s", digest, r.SHA256)
	}
	return nil
}

func (r Record) validate() error {
	switch {
	case r.Target == "":
		return fmt.Errorf("staging record has no target")
	case r.Staged == "":
		return fmt.Errorf("staging record has no staged path")
	case r.Version == "":
		return fmt.Errorf("staging record has no version")
	case len(r.SHA256) != 64:
		return fmt.Errorf("staging record has a malformed digest")
	}
	return nil
}
