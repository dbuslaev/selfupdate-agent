package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Machine is the non-secret context sent at enrollment and carried with events,
// so an operator can recognise a machine in a console and so failures can be
// correlated by platform.
//
// Deliberately narrow. Hardware fingerprints — MAC address, disk serial,
// machine UUID — are tempting for identity and are the wrong tool: they change
// on reimage, they are a privacy liability, and enrollment already provides
// real identity. Hostname is included because operators need it, and is treated
// as personal data since in practice it often is.
type Machine struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Version  string `json:"version"`
}

type enrollRequest struct {
	Code      string  `json:"code"`
	PublicKey string  `json:"public_key"` // base64 Ed25519
	Machine   Machine `json:"machine"`
}

type enrollResponse struct {
	InstallID string `json:"install_id"`
}

// Enroll exchanges a one-time code for an install ID.
//
// The code is issued out of band by an administrator, so the backend knows
// which person received which code. It is consumed here and never used again:
// the install ID returned is a fresh random identifier, which is what appears
// in every subsequent request. Reusing the one-time code as the long-lived
// identifier would put an emailed bearer secret into every access log.
//
// Only the public half of the keypair is transmitted.
func Enroll(ctx context.Context, endpoint, code string, pub ed25519.PublicKey, m Machine) (string, error) {
	payload, err := json.Marshal(enrollRequest{
		Code:      code,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Machine:   m,
	})
	if err != nil {
		return "", fmt.Errorf("marshal enrollment: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("contact enrollment endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("enrollment refused: %s", resp.Status)
	}
	var out enrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("parse enrollment response: %w", err)
	}
	if out.InstallID == "" {
		return "", fmt.Errorf("enrollment response contained no install id")
	}
	return out.InstallID, nil
}
