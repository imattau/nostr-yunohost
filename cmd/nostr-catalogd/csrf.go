package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// randomToken returns a fresh 32-byte random token, hex-encoded. Failure
// here means the system RNG is broken, which no fallback can safely paper
// over - every subsequent CSRF token would be predictable.
func randomToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("read random token: %w", err)
	}
	return hex.EncodeToString(raw), nil
}
