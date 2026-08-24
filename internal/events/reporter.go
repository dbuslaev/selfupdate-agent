package events

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dbuslaev/selfupdate-agent/internal/identity"
)

// Reporter delivers a batch of events. It is an interface so that the fleet API
// — which lives in its own repository — is a swappable detail here, and so an
// unenrolled install can run with no reporter at all.
type Reporter interface {
	Report(ctx context.Context, batch []Event) error
}

// HTTPReporter posts events to the fleet API, signing each request with the
// install's private key.
//
// Requests are signed even though the response is not checked. The thing worth
// protecting is the report, not the reply: unsigned reports would let anyone
// send one claiming to be any install, so a compromised machine could be made to
// look healthy, or fabricated crash reports could halt a good rollout.
//
// The reply is only an acknowledgement, and a forged one would not change
// anything this client does, so it is deliberately not verified.
type HTTPReporter struct {
	Endpoint string
	Signer   *identity.Signer
	Client   *http.Client
}

// NewHTTPReporter returns a reporter posting to endpoint.
func NewHTTPReporter(endpoint string, signer *identity.Signer, timeout time.Duration) *HTTPReporter {
	return &HTTPReporter{
		Endpoint: endpoint,
		Signer:   signer,
		Client:   &http.Client{Timeout: timeout},
	}
}

type reportRequest struct {
	Events []Event `json:"events"`
}

// Report sends a batch. The response body is ignored: the reply is an
// acknowledgement, and a forged one changes nothing the client would do.
func (r *HTTPReporter) Report(ctx context.Context, batch []Event) error {
	body, err := json.Marshal(reportRequest{Events: batch})
	if err != nil {
		return fmt.Errorf("marshal events: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := r.Signer.SignRequest(req, body); err != nil {
		return fmt.Errorf("sign request: %w", err)
	}

	resp, err := r.Client.Do(req)
	if err != nil {
		return fmt.Errorf("post events: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("post events: unexpected status %s", resp.Status)
	}
	return nil
}
