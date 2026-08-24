package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/dbuslaev/selfupdate-agent/internal/events"
	"github.com/dbuslaev/selfupdate-agent/internal/identity"
	"github.com/dbuslaev/selfupdate-agent/internal/state"
)

// fleet is an in-memory stand-in for the fleet database.
//
// A real deployment stores public keys, install metadata and events durably,
// and issues one-time enrollment codes to administrators. This keeps only what
// the contract requires so the client side can be exercised honestly: it
// verifies real signatures against real keys and rejects real replays.
//
// Note what it stores: public keys only. A breach of this table leaks nothing
// that can impersonate an install, which is the reason the client generates its
// own keypair rather than being handed a shared secret.
type fleet struct {
	mu     sync.Mutex
	keys   map[string]ed25519.PublicKey // install ID -> public key
	nonces map[string]time.Time         // seen nonces, for replay rejection
}

func newFleet() *fleet {
	return &fleet{
		keys:   make(map[string]ed25519.PublicKey),
		nonces: make(map[string]time.Time),
	}
}

func registerFleetAPI(mux *http.ServeMux, log *slog.Logger) {
	f := newFleet()
	mux.HandleFunc("/v1/enroll", f.handleEnroll(log))
	mux.HandleFunc("/v1/events", f.handleEvents(log))
}

type enrollRequest struct {
	Code      string           `json:"code"`
	PublicKey string           `json:"public_key"`
	Machine   identity.Machine `json:"machine"`
}

// handleEnroll exchanges a one-time code for an install ID.
//
// A real implementation looks the code up, checks it is unused and unexpired,
// marks it consumed, and records which administrator issued it to whom. This
// accepts any non-empty code so the demo can run unattended, which is the one
// place it deliberately diverges from the contract.
func (f *fleet) handleEnroll(log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req enrollRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.Code == "" {
			http.Error(w, "enrollment code required", http.StatusBadRequest)
			return
		}
		pub, err := base64.StdEncoding.DecodeString(req.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			http.Error(w, "malformed public key", http.StatusBadRequest)
			return
		}

		// The install ID is freshly generated here, never derived from the
		// one-time code. Reusing the code as a long-lived identifier would put
		// an emailed bearer secret into every subsequent request and log line.
		installID := state.NewInstallID()

		f.mu.Lock()
		f.keys[installID] = ed25519.PublicKey(pub)
		f.mu.Unlock()

		log.Info("enrolled install",
			"install_id", installID,
			"hostname", req.Machine.Hostname,
			"os", req.Machine.OS,
			"arch", req.Machine.Arch,
			"version", req.Machine.Version)

		writeJSON(w, map[string]string{"install_id": installID})
	}
}

type eventsRequest struct {
	Events []events.Event `json:"events"`
}

// handleEvents ingests a signed batch.
//
// The request is authenticated even though the response carries nothing. The
// value protected is the request: unsigned events would let anyone forge a
// check-in for any install — reporting a compromised machine as healthy, or
// fabricating crash reports to halt a good rollout.
func (f *fleet) handleEvents(log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		installID, err := f.authenticate(r, body)
		if err != nil {
			log.Warn("rejected event batch", "error", err)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		var req eventsRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		for _, ev := range req.Events {
			// Real ingestion deduplicates on ev.ID, which is what makes it safe
			// for a client to resend a batch whose acknowledgement was lost.
			log.Info("event",
				"install_id", installID,
				"kind", ev.Kind,
				"source", ev.Source,
				"version", ev.Version,
				"fields", ev.Fields)
		}
		writeJSON(w, map[string]any{"accepted": len(req.Events)})
	}
}

// authenticate verifies the signature headers on a request.
//
// Three checks, each closing a different hole: the timestamp bounds how long a
// captured request stays useful, the nonce stops replay inside that window, and
// the signature covers method, path, install ID, timestamp, nonce and body
// digest together, so none of them can be altered or lifted onto another
// endpoint.
func (f *fleet) authenticate(r *http.Request, body []byte) (string, error) {
	installID := r.Header.Get(identity.HeaderInstallID)
	timestamp := r.Header.Get(identity.HeaderTimestamp)
	nonce := r.Header.Get(identity.HeaderNonce)
	encodedSig := r.Header.Get(identity.HeaderSignature)

	if installID == "" || timestamp == "" || nonce == "" || encodedSig == "" {
		return "", errors.New("missing signature headers")
	}

	seconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return "", errors.New("malformed timestamp")
	}
	if skew := time.Since(time.Unix(seconds, 0)); skew > identity.MaxClockSkew || skew < -identity.MaxClockSkew {
		// Reporting the server's own time lets a client with a drifting clock
		// correct itself instead of being permanently locked out.
		return "", fmt.Errorf("timestamp outside the accepted window; server time is %d", time.Now().Unix())
	}

	signature, err := base64.StdEncoding.DecodeString(encodedSig)
	if err != nil {
		return "", errors.New("malformed signature")
	}

	f.mu.Lock()
	pub, known := f.keys[installID]
	replayed := false
	if known {
		if _, seen := f.nonces[nonce]; seen {
			replayed = true
		} else {
			f.nonces[nonce] = time.Now()
			f.expireNoncesLocked()
		}
	}
	f.mu.Unlock()

	if !known {
		return "", errors.New("unknown install")
	}
	if replayed {
		return "", errors.New("nonce already used")
	}

	signed := identity.SigningString(r.Method, r.URL.Path, installID, timestamp, nonce, body)
	if !ed25519.Verify(pub, signed, signature) {
		return "", errors.New("signature verification failed")
	}
	return installID, nil
}

// expireNoncesLocked drops nonces older than the clock-skew window. Beyond it
// the timestamp check already rejects the request, so remembering them longer
// only grows memory.
func (f *fleet) expireNoncesLocked() {
	cutoff := time.Now().Add(-identity.MaxClockSkew)
	for nonce, seen := range f.nonces {
		if seen.Before(cutoff) {
			delete(f.nonces, nonce)
		}
	}
}

func writeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(payload)
}
