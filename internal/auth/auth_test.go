package auth

import (
	"strings"
	"testing"
	"time"
)

func TestPasswordRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("unexpected hash format: %s", hash)
	}
	if err := VerifyPassword(hash, "correct horse battery staple"); err != nil {
		t.Errorf("correct password rejected: %v", err)
	}
	if err := VerifyPassword(hash, "correct horse battery stapl"); err == nil {
		t.Error("wrong password accepted")
	}
	// Two hashes of the same password must differ: the salt is random.
	other, _ := HashPassword("correct horse battery staple")
	if other == hash {
		t.Error("hashes are not salted")
	}
}

func TestPasswordPolicy(t *testing.T) {
	bad := map[string]string{
		"too short":  "short",
		"repetitive": "aaaaaaaaaaaaaaaaaaaa",
		"blank":      "                    ",
		"control":    "abcdefghijkl\x00mnop",
	}
	for name, pw := range bad {
		if err := CheckPasswordPolicy(pw); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
	if err := CheckPasswordPolicy("a reasonable passphrase"); err != nil {
		t.Errorf("good password rejected: %v", err)
	}
}

func TestTOTPVerifies(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	code := TOTPCode(secret, now)
	if len(code) != 6 {
		t.Fatalf("expected six digits, got %q", code)
	}
	step, err := VerifyTOTP(secret, code, now)
	if err != nil {
		t.Fatalf("current code rejected: %v", err)
	}
	if step == 0 {
		t.Error("no step returned")
	}
	// One period of drift in each direction is tolerated, two is not.
	if _, err := VerifyTOTP(secret, code, now.Add(30*time.Second)); err != nil {
		t.Error("code one step early rejected")
	}
	if _, err := VerifyTOTP(secret, code, now.Add(-30*time.Second)); err != nil {
		t.Error("code one step late rejected")
	}
	if _, err := VerifyTOTP(secret, code, now.Add(5*time.Minute)); err == nil {
		t.Error("a long-expired code was accepted")
	}
	if _, err := VerifyTOTP(secret, "000000", now); err == nil {
		t.Error("a guessed code was accepted")
	}
	// Spaces and separators as pasted from an authenticator are tolerated.
	if _, err := VerifyTOTP(secret, code[:3]+" "+code[3:], now); err != nil {
		t.Error("a spaced code was rejected")
	}
}

func TestTOTPURIAndQR(t *testing.T) {
	secret, _ := NewTOTPSecret()
	uri := TOTPURI("APB", "alex", secret)
	for _, want := range []string{"otpauth://totp/", "issuer=APB", "digits=6", "period=30"} {
		if !strings.Contains(uri, want) {
			t.Errorf("uri missing %q: %s", want, uri)
		}
	}
	png, err := TOTPQRCodePNG(uri)
	if err != nil {
		t.Fatal(err)
	}
	if len(png) < 8 || string(png[1:4]) != "PNG" {
		t.Error("QR code is not a PNG")
	}
}

func TestKeyringSealAndTokens(t *testing.T) {
	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(i)
	}
	k, err := NewKeyring(master)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := k.Seal([]byte("a shared secret"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sealed), "shared") {
		t.Error("the plaintext survives in the sealed value")
	}
	out, err := k.Open(sealed)
	if err != nil || string(out) != "a shared secret" {
		t.Fatalf("open: %v %q", err, out)
	}
	// Sealing twice must produce different ciphertext: the nonce is random.
	again, _ := k.Seal([]byte("a shared secret"))
	if string(again) == string(sealed) {
		t.Error("sealing is deterministic")
	}

	// A different master key must not be able to open it.
	other := make([]byte, 32)
	k2, _ := NewKeyring(other)
	if _, err := k2.Open(sealed); err == nil {
		t.Error("a foreign key opened the sealed value")
	}

	token, err := NewDeviceToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token, "apb_") || len(token) != 32 {
		t.Errorf("unexpected token shape: %s", token)
	}
	if len(k.TokenHash(token)) != 32 {
		t.Error("token hash is not 32 bytes")
	}
	if string(k.TokenHash(token)) == string(k.TokenHash(token+"x")) {
		t.Error("token hash collides trivially")
	}
	if string(k.TokenHash(token)) != string(k.TokenHash(token)) {
		t.Error("token hash is not deterministic")
	}

	if _, err := NewKeyring(make([]byte, 16)); err == nil {
		t.Error("a short master key was accepted")
	}
}

func TestSessionValuesAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		v, err := NewSessionValue()
		if err != nil {
			t.Fatal(err)
		}
		if seen[v] {
			t.Fatal("session value repeated")
		}
		seen[v] = true
	}
}
