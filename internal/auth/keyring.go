package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"

	"golang.org/x/crypto/hkdf"
)

// Keyring derives every subordinate key from the single server secret, so an
// operator only has one value to protect and rotate.
type Keyring struct {
	secretSeal  []byte // seals TOTP secrets at rest
	tokenMAC    []byte // keys the device-token hash
	sessionSalt []byte // salts session identifier hashing
}

// NewKeyring derives the subkeys from the configured server secret.
func NewKeyring(master []byte) (*Keyring, error) {
	if len(master) < 32 {
		return nil, errors.New("server secret must be at least 32 bytes")
	}
	derive := func(label string, n int) ([]byte, error) {
		out := make([]byte, n)
		r := hkdf.New(sha256.New, master, nil, []byte("apb2:"+label))
		if _, err := r.Read(out); err != nil {
			return nil, err
		}
		return out, nil
	}
	k := &Keyring{}
	var err error
	if k.secretSeal, err = derive("secret-seal", 32); err != nil {
		return nil, err
	}
	if k.tokenMAC, err = derive("device-token", 32); err != nil {
		return nil, err
	}
	if k.sessionSalt, err = derive("session-id", 32); err != nil {
		return nil, err
	}
	return k, nil
}

// Seal encrypts a small secret for storage in the database.
func (k *Keyring) Seal(plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(k.secretSeal)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

// Open reverses Seal.
func (k *Keyring) Open(sealed []byte) ([]byte, error) {
	block, err := aes.NewCipher(k.secretSeal)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("sealed value is truncated")
	}
	nonce, body := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	out, err := gcm.Open(nil, nonce, body, nil)
	if err != nil {
		return nil, errors.New("sealed value does not decrypt: the server secret has changed")
	}
	return out, nil
}

// TokenHash is the deterministic keyed hash stored in place of a device token.
// A keyed hash rather than a password hash is deliberate: tokens carry 160
// bits of entropy, so there is nothing to brute force, and authentication has
// to be a single indexed lookup on every 15-second poll.
func (k *Keyring) TokenHash(token string) []byte {
	mac := hmac.New(sha256.New, k.tokenMAC)
	mac.Write([]byte(token))
	return mac.Sum(nil)
}

// SessionHash maps a session cookie value to its database key.
func (k *Keyring) SessionHash(value string) []byte {
	mac := hmac.New(sha256.New, k.sessionSalt)
	mac.Write([]byte(value))
	return mac.Sum(nil)
}

// tokenAlphabet avoids characters that are easy to confuse when a token is
// read off a screen and typed into a router.
const tokenAlphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// NewDeviceToken mints a token with roughly 160 bits of entropy, prefixed so
// it is recognisable in logs and in the console.
func NewDeviceToken() (string, error) {
	const n = 28
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("apb_")
	for _, c := range buf {
		b.WriteByte(tokenAlphabet[int(c)%len(tokenAlphabet)])
	}
	return b.String(), nil
}

// TokenPrefix is the recognisable, non-secret head of a token, kept so the
// console can show which credential is which.
func TokenPrefix(token string) string {
	if len(token) <= 12 {
		return token
	}
	return token[:12]
}

// NewSessionValue mints the random value carried by the session cookie.
func NewSessionValue() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// NewCSRFToken mints a per-session CSRF token.
func NewCSRFToken() (string, error) { return NewSessionValue() }

// ConstantTimeEqual compares two strings without leaking their contents
// through timing.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
