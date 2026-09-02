package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"rsc.io/qr"
)

// TOTP parameters, matching what every authenticator app defaults to.
const (
	totpDigits = 6
	totpPeriod = 30
	totpSkew   = 1 // accept the neighbouring step on each side
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// ErrBadCode is returned when a one-time code does not verify.
var ErrBadCode = errors.New("incorrect authentication code")

// NewTOTPSecret generates a 20-byte shared secret.
func NewTOTPSecret() ([]byte, error) {
	s := make([]byte, 20)
	if _, err := rand.Read(s); err != nil {
		return nil, err
	}
	return s, nil
}

// EncodeTOTPSecret renders a secret in the base32 form users can type by hand.
func EncodeTOTPSecret(secret []byte) string {
	s := b32.EncodeToString(secret)
	// Grouped in fours, which is how authenticator apps present it.
	var b strings.Builder
	for i, r := range s {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// TOTPURI builds the otpauth:// URI an authenticator scans.
func TOTPURI(issuer, account string, secret []byte) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", b32.EncodeToString(secret))
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(totpPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// TOTPQRCodePNG renders the enrolment URI as a PNG QR code.
func TOTPQRCodePNG(uri string) ([]byte, error) {
	code, err := qr.Encode(uri, qr.M)
	if err != nil {
		return nil, err
	}
	return code.PNG(), nil
}

// TOTPCode computes the code for a specific 30-second step.
func TOTPCode(secret []byte, t time.Time) string {
	counter := uint64(t.Unix()) / totpPeriod
	return hotp(secret, counter)
}

func hotp(secret []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, secret)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < totpDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, value%mod)
}

// VerifyTOTP checks a user-supplied code against the secret, allowing one step
// of clock skew in each direction. It returns the step the code belongs to so
// the caller can refuse to accept the same step twice, which is what stops an
// observed code from being replayed inside its 90-second window.
//
// Every candidate step is evaluated before returning, and the comparison is
// constant time, so neither the answer nor which step matched leaks through
// timing.
func VerifyTOTP(secret []byte, code string, now time.Time) (uint64, error) {
	code = strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, code)
	if len(code) != totpDigits {
		return 0, ErrBadCode
	}
	counter := uint64(now.Unix()) / totpPeriod
	ok := 0
	var matched uint64
	for d := -totpSkew; d <= totpSkew; d++ {
		c := counter
		if d < 0 {
			c -= uint64(-d)
		} else {
			c += uint64(d)
		}
		hit := subtle.ConstantTimeCompare([]byte(hotp(secret, c)), []byte(code))
		matched |= uint64(hit) * c
		ok |= hit
	}
	if ok != 1 {
		return 0, ErrBadCode
	}
	return matched, nil
}
