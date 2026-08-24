// Package state persists what the agent needs to remember across restarts.
//
// One file, rewritten atomically. The fields are written together at the same
// moments — a swap sets the pending version and resets the boot counter, a
// rollback clears the pending version and adds to the poisoned list — so
// splitting them across files would create windows where a crash leaves two
// files disagreeing.
//
// Everything here is a hint. The binary on disk is the only authoritative
// record of what version is installed, which is why a corrupt or missing state
// file degrades to a fresh one instead of being fatal.
package state

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/dbuslaev/selfupdate-agent/internal/fsutil"
)

// maxPoisoned bounds the poisoned list so a pathological crash loop cannot grow
// the state file without limit. The newest entries are the ones that matter.
const maxPoisoned = 32

// State is the persisted record.
type State struct {
	// InstallID identifies this installation. It is issued at enrollment, or
	// generated locally for an unenrolled install, and is used both to report
	// events and to bucket this install for staged rollout.
	InstallID string `json:"install_id"`

	// PendingVersion is a version that has been swapped in but has not yet
	// proven it can run. BootAttempts counts starts since the swap.
	PendingVersion string `json:"pending_version,omitempty"`
	BootAttempts   int    `json:"boot_attempts,omitempty"`

	// PreviousVersion is what BackupPath contains, retained until the pending
	// version commits.
	PreviousVersion string `json:"previous_version,omitempty"`

	// Poisoned lists versions that failed on this machine. They are never
	// downloaded again, which is what stops a crash loop from re-fetching the
	// same broken build indefinitely.
	Poisoned []string `json:"poisoned,omitempty"`

	// ReinstallFor is a version the agent cannot install itself. Held so the
	// requirement is reported once rather than on every poll, and so --status
	// can surface it long after the log line has scrolled away.
	ReinstallFor string `json:"reinstall_for,omitempty"`

	// Diagnostics. Not load-bearing, but they are the first things anyone asks
	// for during an incident.
	LastCommitted string    `json:"last_committed,omitempty"`
	LastCheck     time.Time `json:"last_check,omitempty"`
	UpdatedAt     time.Time `json:"updated_at,omitempty"`
}

// Store reads and writes the state file.
type Store struct {
	path string
}

// NewStore returns a store backed by path.
func NewStore(path string) *Store { return &Store{path: path} }

// Load reads the state, returning a fresh one if the file is absent or corrupt.
//
// Corruption is deliberately not an error. The alternative — refusing to start
// because a hint file is unreadable — turns a cosmetic problem into an outage,
// and the only thing actually lost is the rollout bucket and the poisoned list.
func (s *Store) Load() (*State, error) {
	raw, found, err := fsutil.ReadJSONFile(s.path)
	if err != nil {
		return nil, err
	}
	if !found {
		return New(), nil
	}

	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		return New(), nil
	}
	if st.InstallID == "" {
		st.InstallID = NewInstallID()
	}
	return &st, nil
}

// Save writes the state atomically.
func (s *Store) Save(st *State) error {
	st.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	// 0600: the state file carries the install ID, which identifies this machine
	// to the fleet API.
	return fsutil.WriteFileAtomic(s.path, append(data, '\n'), 0o600)
}

// Path returns the backing file, for diagnostics.
func (s *Store) Path() string { return s.path }

// New returns a fresh state with a generated install ID.
func New() *State { return &State{InstallID: NewInstallID()} }

// NewInstallID mints a random identifier. It is deliberately not derived from
// anything about the machine or the user: it exists to distinguish installs,
// not to fingerprint them.
func NewInstallID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// This value is not security-sensitive, so degrade rather than take the
		// whole program down over an exhausted entropy source.
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// BeginTrial records that a new version has been swapped in and is unproven.
func (s *State) BeginTrial(newVersion, previousVersion string) {
	s.PendingVersion = newVersion
	s.PreviousVersion = previousVersion
	s.BootAttempts = 0
}

// OnTrial reports whether a version is awaiting proof that it can run.
func (s *State) OnTrial() bool { return s.PendingVersion != "" }

// RecordBoot counts a start of a pending version and reports the new count.
func (s *State) RecordBoot() int {
	s.BootAttempts++
	return s.BootAttempts
}

// Commit clears the trial after a version proves healthy.
func (s *State) Commit(version string) {
	s.LastCommitted = version
	s.PendingVersion = ""
	s.PreviousVersion = ""
	s.BootAttempts = 0
}

// Abandon clears the trial after a rollback and poisons the failed version.
func (s *State) Abandon(restoredVersion string) {
	if s.PendingVersion != "" {
		s.Poison(s.PendingVersion)
	}
	s.LastCommitted = restoredVersion
	s.PendingVersion = ""
	s.PreviousVersion = ""
	s.BootAttempts = 0
}

// NeedsReinstall records that a version requires a new installer, reporting
// whether this is the first time it has been seen. The caller uses that to log
// and report once instead of on every poll.
func (s *State) NeedsReinstall(version string) (firstTime bool) {
	if s.ReinstallFor == version {
		return false
	}
	s.ReinstallFor = version
	return true
}

// ClearReinstall forgets a reinstall requirement, for when a later release
// supersedes it and can be installed normally.
func (s *State) ClearReinstall() { s.ReinstallFor = "" }

// Poison marks a version as never to be installed on this machine again.
func (s *State) Poison(version string) {
	if version == "" || s.IsPoisoned(version) {
		return
	}
	s.Poisoned = append(s.Poisoned, version)
	if len(s.Poisoned) > maxPoisoned {
		s.Poisoned = s.Poisoned[len(s.Poisoned)-maxPoisoned:]
	}
}

// IsPoisoned reports whether a version has already failed here.
func (s *State) IsPoisoned(version string) bool {
	return slices.Contains(s.Poisoned, version)
}
