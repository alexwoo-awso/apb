// Package auth implements the credential primitives used by APB2: argon2id
// password hashing, RFC 6238 one-time passwords, authenticated encryption for
// secrets at rest, and device bearer tokens.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters. These follow the OWASP low-memory profile: 19 MiB and
// two passes, which keeps a login under ~50 ms on a small VPS while remaining
// expensive to attack offline.
const (
	argonTime    = 2
	argonMemory  = 19 * 1024 // KiB
	argonThreads = 1
	argonKeyLen  = 32
	argonSaltLen = 16
)

// ErrBadPassword is returned when a password does not match its hash.
var ErrBadPassword = errors.New("password does not match")

// HashPassword returns a PHC-formatted argon2id hash.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword checks a password against a PHC-formatted argon2id hash in
// constant time.
func VerifyPassword(encoded, password string) error {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return errors.New("unsupported password hash format")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return errors.New("unsupported argon2 version")
	}
	var memory uint32
	var time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return errors.New("malformed argon2 parameters")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return errors.New("malformed argon2 salt")
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return errors.New("malformed argon2 hash")
	}
	got := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrBadPassword
	}
	return nil
}

// MinPasswordLength is the shortest password the console accepts. Length is
// the only requirement that meaningfully resists offline attack, so there are
// no composition rules to work around.
const MinPasswordLength = 12

// CheckPasswordPolicy validates a candidate password.
func CheckPasswordPolicy(password string) error {
	if len([]rune(password)) < MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}
	if len(password) > 1024 {
		return errors.New("password must be at most 1024 bytes")
	}
	for _, r := range password {
		if unicode.IsControl(r) {
			return errors.New("password must not contain control characters")
		}
	}
	trimmed := strings.TrimSpace(password)
	if trimmed == "" {
		return errors.New("password must not be blank")
	}
	// A password made of a single repeated rune survives a length check but is
	// trivially guessable.
	distinct := map[rune]struct{}{}
	for _, r := range password {
		distinct[r] = struct{}{}
	}
	if len(distinct) < 5 {
		return errors.New("password is too repetitive")
	}
	return nil
}
