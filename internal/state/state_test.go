package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store := NewStore(path)

	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if st.InstallID == "" {
		t.Fatal("a fresh state should mint an install ID")
	}

	st.BeginTrial("1.1.0", "1.0.0")
	st.RecordBoot()
	st.Poison("0.9.0")
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}

	got, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.InstallID != st.InstallID || got.PendingVersion != "1.1.0" || got.BootAttempts != 1 {
		t.Errorf("round trip lost data: %+v", got)
	}
	if !got.IsPoisoned("0.9.0") {
		t.Error("the poisoned list did not survive; a crash loop would re-download the same broken build")
	}
}

// A corrupt state file must not stop the agent from starting: the binary on
// disk is the source of truth and everything here is a recoverable hint.
func TestCorruptStateDegradesGracefully(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	st, err := NewStore(path).Load()
	if err != nil {
		t.Fatalf("Load on a corrupt file returned %v, want a fresh state", err)
	}
	if st.InstallID == "" {
		t.Error("expected a replacement install ID")
	}
}

func TestTrialLifecycle(t *testing.T) {
	st := New()

	if st.OnTrial() {
		t.Error("a fresh state should not be on trial")
	}

	st.BeginTrial("1.1.0", "1.0.0")
	if !st.OnTrial() || st.BootAttempts != 0 {
		t.Fatalf("after BeginTrial: %+v", st)
	}
	if got := st.RecordBoot(); got != 1 {
		t.Errorf("RecordBoot = %d, want 1", got)
	}

	st.Commit("1.1.0")
	if st.OnTrial() || st.LastCommitted != "1.1.0" || st.BootAttempts != 0 {
		t.Fatalf("after Commit: %+v", st)
	}
	if st.IsPoisoned("1.1.0") {
		t.Error("a committed version must not be poisoned")
	}
}

// Abandoning a trial has to poison the failed version, or the restored binary
// immediately downloads and installs the same broken build again.
func TestAbandonPoisonsTheFailedVersion(t *testing.T) {
	st := New()
	st.BeginTrial("1.1.0", "1.0.0")
	st.RecordBoot()

	st.Abandon("1.0.0")

	if !st.IsPoisoned("1.1.0") {
		t.Error("the failed version was not poisoned")
	}
	if st.OnTrial() {
		t.Error("the trial should be cleared; otherwise the restored binary counts its own boots")
	}
	if st.LastCommitted != "1.0.0" {
		t.Errorf("last committed = %q, want the restored version", st.LastCommitted)
	}
}

func TestPoisonIsBoundedAndDeduplicated(t *testing.T) {
	st := New()

	st.Poison("1.0.0")
	st.Poison("1.0.0")
	if len(st.Poisoned) != 1 {
		t.Errorf("poisoned = %v, want no duplicates", st.Poisoned)
	}

	for i := 0; i < maxPoisoned*2; i++ {
		st.Poison(string(rune('a'+i%26)) + string(rune('0'+i/26)))
	}
	if len(st.Poisoned) > maxPoisoned {
		t.Errorf("poisoned list grew to %d entries, want at most %d", len(st.Poisoned), maxPoisoned)
	}
}

// The requirement must be reported once, not on every poll, and must survive
// until a release supersedes it.
func TestReinstallIsReportedOnce(t *testing.T) {
	st := New()

	if !st.NeedsReinstall("1.1.0") {
		t.Fatal("the first sighting should report")
	}
	if st.NeedsReinstall("1.1.0") {
		t.Error("a repeat sighting of the same version should not report again")
	}
	if !st.NeedsReinstall("1.2.0") {
		t.Error("a different version should report")
	}

	st.ClearReinstall()
	if st.ReinstallFor != "" {
		t.Error("ClearReinstall did not clear the requirement")
	}
}
