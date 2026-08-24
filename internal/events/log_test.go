package events

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"crypto/ed25519"

	"github.com/dbuslaev/selfupdate-agent/internal/identity"
)

func newTestLog(t *testing.T) *Log {
	t.Helper()
	return NewLog(filepath.Join(t.TempDir(), "events.jsonl"), "test")
}

func TestAppendAndRead(t *testing.T) {
	log := newTestLog(t)

	for _, kind := range []string{KindShimStart, KindUpdateFound, KindCommitted} {
		if err := log.Append(Event{Kind: kind, Version: "1.0.0"}); err != nil {
			t.Fatal(err)
		}
	}

	got, err := log.Read()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("read %d events, want 3", len(got))
	}
	for _, ev := range got {
		if ev.ID == "" || ev.Time.IsZero() || ev.Source != "test" {
			t.Errorf("event was not stamped: %+v", ev)
		}
	}
}

// The reason for append-only. A single overwritten payload slot loses events
// that arrive faster than they are delivered — which is exactly what happens
// during a crash loop, when the events matter most.
func TestAppendPreservesEveryEvent(t *testing.T) {
	log := newTestLog(t)

	const count = 50
	for i := 0; i < count; i++ {
		log.Record(KindShimStart, "1.0.0", map[string]string{"n": string(rune('a' + i%26))})
	}

	got, err := log.Read()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != count {
		t.Fatalf("read %d events, want %d", len(got), count)
	}
}

// A torn final line from a crash must not strand every event behind it.
func TestReadSkipsMalformedLines(t *testing.T) {
	log := newTestLog(t)
	log.Record(KindShimStart, "1.0.0", nil)

	f, err := os.OpenFile(log.path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("{\"kind\":\"tru\n")
	f.Close()

	log.Record(KindCommitted, "1.0.0", nil)

	got, err := log.Read()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("read %d events, want the 2 well-formed ones", len(got))
	}
}

func TestDeliverClearsTheLogOnSuccess(t *testing.T) {
	log := newTestLog(t)
	log.Record(KindShimStart, "1.0.0", nil)

	var delivered int
	err := log.Deliver(context.Background(), reporterFunc(func(_ context.Context, batch []Event) error {
		delivered = len(batch)
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if delivered != 1 {
		t.Errorf("delivered %d events, want 1", delivered)
	}

	remaining, err := log.Read()
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 0 {
		t.Errorf("%d events remain after a successful delivery", len(remaining))
	}
}

// Retention on failure is what makes a crash on a disconnected machine still
// reportable once it reconnects.
func TestDeliverRetainsEventsOnFailure(t *testing.T) {
	log := newTestLog(t)
	log.Record(KindPanic, "1.0.0", map[string]string{"panic": "boom"})

	err := log.Deliver(context.Background(), reporterFunc(func(context.Context, []Event) error {
		return errors.New("network is down")
	}))
	if err == nil {
		t.Fatal("Deliver reported success despite a failing reporter")
	}

	remaining, readErr := log.Read()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(remaining) != 1 {
		t.Errorf("%d events remain, want the undelivered one retained", len(remaining))
	}
}

func TestDeliverIsANoOpWithNothingBuffered(t *testing.T) {
	log := newTestLog(t)

	called := false
	err := log.Deliver(context.Background(), reporterFunc(func(context.Context, []Event) error {
		called = true
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("an empty log should not produce a request")
	}
}

func TestTailReturnsTheMostRecent(t *testing.T) {
	log := newTestLog(t)
	for i := 0; i < 20; i++ {
		log.Record(KindShimStart, "1.0.0", map[string]string{"n": string(rune('a' + i))})
	}

	got, err := log.Tail(5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("Tail(5) returned %d", len(got))
	}
	if got[4].Fields["n"] != string(rune('a'+19)) {
		t.Error("Tail did not return the newest events")
	}
}

// A crash loop appending forever must not fill the disk, because that turns one
// broken release into an unbootable machine.
func TestLogIsBounded(t *testing.T) {
	log := newTestLog(t)
	blob := make(map[string]string, 1)
	blob["payload"] = string(make([]byte, 4096))

	for i := 0; i < 1000; i++ {
		log.Record(KindPanic, "1.0.0", blob)
	}

	info, err := os.Stat(log.path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > 4*maxLogBytes {
		t.Errorf("log grew to %d bytes, want it bounded near %d", info.Size(), maxLogBytes)
	}
}

// The HTTP reporter must sign, because unsigned events would let anyone forge a
// check-in for any install — reporting a compromised machine as healthy, or
// fabricating failures to halt a good rollout.
func TestHTTPReporterSignsRequests(t *testing.T) {
	id, pub := testIdentity(t)
	signer, err := identity.NewSigner(id)
	if err != nil {
		t.Fatal(err)
	}

	verified := make(chan bool, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)

		sig, err := decodeBase64(r.Header.Get(identity.HeaderSignature))
		if err != nil {
			verified <- false
			return
		}
		signed := identity.SigningString(
			r.Method, r.URL.Path,
			r.Header.Get(identity.HeaderInstallID),
			r.Header.Get(identity.HeaderTimestamp),
			r.Header.Get(identity.HeaderNonce),
			body,
		)
		verified <- ed25519.Verify(pub, signed, sig)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	reporter := NewHTTPReporter(srv.URL+"/v1/events", signer, 0)
	if err := reporter.Report(context.Background(), []Event{{Kind: KindShimStart}}); err != nil {
		t.Fatal(err)
	}
	if !<-verified {
		t.Error("the server could not verify the request signature")
	}
}

// Each request must carry a fresh nonce, or a captured one is replayable for
// the whole clock-skew window.
func TestEachRequestCarriesAFreshNonce(t *testing.T) {
	id, _ := testIdentity(t)
	signer, err := identity.NewSigner(id)
	if err != nil {
		t.Fatal(err)
	}

	seen := make(map[string]bool)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := r.Header.Get(identity.HeaderNonce)
		if nonce == "" || seen[nonce] {
			t.Errorf("nonce %q was reused or missing", nonce)
		}
		seen[nonce] = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	reporter := NewHTTPReporter(srv.URL+"/v1/events", signer, 0)
	for i := 0; i < 5; i++ {
		if err := reporter.Report(context.Background(), []Event{{Kind: KindShimStart}}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHTTPReporterSurfacesServerErrors(t *testing.T) {
	id, _ := testIdentity(t)
	signer, _ := identity.NewSigner(id)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unknown install", http.StatusUnauthorized)
	}))
	defer srv.Close()

	reporter := NewHTTPReporter(srv.URL+"/v1/events", signer, 0)
	if err := reporter.Report(context.Background(), []Event{{Kind: KindShimStart}}); err == nil {
		t.Fatal("Report treated a 401 as success")
	}
}

func testIdentity(t *testing.T) (*identity.Identity, ed25519.PublicKey) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "identity.json")
	id, pub, err := identity.Create(path, "install-under-test")
	if err != nil {
		t.Fatal(err)
	}
	return id, pub
}

func decodeBase64(s string) ([]byte, error) {
	var out []byte
	err := json.Unmarshal([]byte(`"`+s+`"`), &out)
	return out, err
}

type reporterFunc func(context.Context, []Event) error

func (f reporterFunc) Report(ctx context.Context, batch []Event) error { return f(ctx, batch) }
