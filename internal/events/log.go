// Package events records what happened and delivers it to the fleet API.
//
// # Why append-only
//
// The obvious design is a single "pending payload" file that is overwritten,
// sent, and deleted. It loses data exactly when it matters: if a second event
// occurs before the first is delivered, the first is overwritten — and events
// cluster during a crash loop, which is the situation you most need to see.
//
// So the log is append-only JSON Lines. Appends of short lines are atomic on
// every supported platform, so a crash mid-write costs the last line rather
// than the file. Delivery reads the whole file, sends it, and truncates only
// after the server acknowledges.
//
// The same file doubles as the local record that `agent status` prints, which
// is why there is no separate log file. Two files carrying nearly the same
// content, with two rotation policies and two disk-full risks, is worse.
package events

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"crypto/rand"

	"github.com/dbuslaev/selfupdate-agent/internal/fsutil"
)

// Kinds of event. Kept as a closed set so the server can aggregate on them
// without parsing free text.
const (
	KindShimStart      = "shim.start"
	KindShimSwap       = "shim.swap"
	KindShimRollback   = "shim.rollback"
	KindUpdateFound    = "update.found"
	KindUpdateSkipped  = "update.skipped"
	KindUpdateStaged   = "update.staged"
	KindUpdateRejected = "update.rejected"
	KindUpdateFailed   = "update.failed"
	KindCommitted      = "update.committed"
	KindReinstall      = "update.requires_reinstall"
	KindStale          = "agent.stale"
	KindPanic          = "agent.panic"
	KindShutdown       = "agent.shutdown"
)

// maxLogBytes caps the log. A crash loop that appends forever must not fill the
// disk, because that turns one broken release into an unbootable machine.
const maxLogBytes = 1 << 20 // 1 MiB

// Event is one thing that happened.
type Event struct {
	ID      string            `json:"id"` // lets the server deduplicate a redelivered batch
	Time    time.Time         `json:"time"`
	Kind    string            `json:"kind"`
	Source  string            `json:"source"` // "shim" or "app"
	Version string            `json:"version"`
	Fields  map[string]string `json:"fields,omitempty"`
}

// Log is an append-only event file.
//
// Delivery truncates, so exactly one process may drain at a time. That holds by
// construction: the shim drains once before launching the program, and the
// program drains for the rest of its life. They never overlap on Unix, where
// the shim has already exec'd away; on Windows the shim waits but does not
// drain after launch.
type Log struct {
	path   string
	source string
}

// NewLog returns a log backed by path. source identifies the writing component.
func NewLog(path, source string) *Log {
	return &Log{path: path, source: source}
}

// Append records an event. Failures are returned but callers generally ignore
// them: losing telemetry must never break the thing being reported on.
func (l *Log) Append(ev Event) error {
	ev.ID = newEventID()
	ev.Time = time.Now().UTC()
	ev.Source = l.source

	line, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	if err := l.trimIfOversized(); err != nil {
		return err
	}

	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open event log: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("append event: %w", err)
	}
	return nil
}

// Record is Append with the error discarded, for the many call sites where
// there is nothing useful to do about a telemetry failure.
func (l *Log) Record(kind, version string, fields map[string]string) {
	_ = l.Append(Event{Kind: kind, Version: version, Fields: fields})
}

// Read returns every buffered event. Malformed lines are skipped rather than
// failing the batch: one torn line from a crash should not strand every event
// behind it.
func (l *Log) Read() ([]Event, error) {
	f, err := os.Open(l.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open event log: %w", err)
	}
	defer f.Close()

	var out []Event
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		var ev Event
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			continue
		}
		out = append(out, ev)
	}
	return out, scanner.Err()
}

// Tail returns the most recent n events, for `agent status`.
func (l *Log) Tail(n int) ([]Event, error) {
	all, err := l.Read()
	if err != nil || len(all) <= n {
		return all, err
	}
	return all[len(all)-n:], nil
}

// Deliver sends everything buffered and clears the log on success.
//
// On failure the log is left intact and the events go out on the next attempt,
// which is what makes a crash on a disconnected machine still reportable once
// it comes back.
func (l *Log) Deliver(ctx context.Context, r Reporter) error {
	if r == nil {
		return nil
	}
	batch, err := l.Read()
	if err != nil || len(batch) == 0 {
		return err
	}
	if err := r.Report(ctx, batch); err != nil {
		return err
	}
	return fsutil.Remove(l.path)
}

// trimIfOversized keeps the newest half of an oversized log. Dropping the
// oldest events is the right bias: during a crash loop the recent ones describe
// the current failure.
func (l *Log) trimIfOversized() error {
	fi, err := os.Stat(l.path)
	if err != nil || fi.Size() <= maxLogBytes {
		return nil
	}
	all, err := l.Read()
	if err != nil {
		return err
	}
	keep := all[len(all)/2:]

	var buf []byte
	for _, ev := range keep {
		line, err := json.Marshal(ev)
		if err != nil {
			continue
		}
		buf = append(append(buf, line...), '\n')
	}
	return fsutil.WriteFileAtomic(l.path, buf, 0o600)
}

func newEventID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
