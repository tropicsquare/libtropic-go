package tropic01

import (
	"crypto/ecdh"
	"io"
	"testing"
)

// deterministicReader fills with a repeating byte pattern for test key generation.
type deterministicReader struct{ val byte }

func (r *deterministicReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = r.val
	}
	return len(b), nil
}

// TestSessionKeyDerivation verifies the four-step HKDF chain produces distinct
// kcmd and kres from a simulated key exchange, matching the C lt_in__session_start
// sequence:
//
//	step1: ck1, _     = hkdf(protocolName[32], ES)   // ES = ECDH(ehpriv, etpub)
//	step2: ck2, _     = hkdf(ck1[33],          SE)   // SE = ECDH(shipriv, etpub)
//	step3: ck3, kauth = hkdf(ck2[33],          ES2)  // ES2 = ECDH(ehpriv, stpub)
//	step4: kcmd, kres = hkdf(ck3[33],          "")
func TestSessionKeyDerivation(t *testing.T) {
	curve := ecdh.X25519()

	ehKey, _ := curve.GenerateKey(&deterministicReader{0x01})
	etKey, _ := curve.GenerateKey(&deterministicReader{0x80})
	shKey, _ := curve.GenerateKey(&deterministicReader{0x02})
	siKey, _ := curve.GenerateKey(&deterministicReader{0x81})

	etPubKey := etKey.PublicKey()
	siPubKey := siKey.PublicKey()

	// ES = X25519(ehpriv, etpub)
	es, _ := ehKey.ECDH(etPubKey)
	// SE = X25519(shipriv, etpub)
	se, _ := shKey.ECDH(etPubKey)
	// ES2 = X25519(ehpriv, sipub)
	es2, _ := ehKey.ECDH(siPubKey)

	// ck0: protocol_name padded/truncated to 32 bytes
	ck0 := make([]byte, 32)
	copy(ck0, []byte(noiseProtocolName))

	// step 1
	ck1, _ := noiseHKDF(ck0, es)

	// step 2 — 33-byte ck1 buffer (ck1 + trailing 0)
	ck1_33 := make([]byte, 33)
	copy(ck1_33, ck1)
	ck2, _ := noiseHKDF(ck1_33, se)

	// step 3 — 33-byte ck2 buffer
	ck2_33 := make([]byte, 33)
	copy(ck2_33, ck2)
	ck3, kauth := noiseHKDF(ck2_33, es2)

	// step 4 — 33-byte ck3 buffer, empty input
	ck3_33 := make([]byte, 33)
	copy(ck3_33, ck3)
	kcmd, kres := noiseHKDF(ck3_33, []byte{})

	// kauth must be 32 bytes and non-zero.
	if len(kauth) != 32 {
		t.Errorf("kauth length: got %d, want 32", len(kauth))
	}
	allZero := true
	for _, b := range kauth {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("kauth is all-zero")
	}

	if len(kcmd) != 32 || len(kres) != 32 {
		t.Errorf("key length: kcmd=%d kres=%d, want 32 each", len(kcmd), len(kres))
	}
	equal := true
	for i := range kcmd {
		if kcmd[i] != kres[i] {
			equal = false
			break
		}
	}
	if equal {
		t.Error("kcmd == kres, want distinct keys")
	}
}

func TestL3NoSession(t *testing.T) {
	// Both encrypt and decrypt must fail without a session.
	d := &Device{} // zero value — session.status == sessionOff
	if err := l3EncryptSend(d, []byte{0x01}); err != ErrNoSession {
		t.Errorf("l3EncryptSend no session: got %v, want ErrNoSession", err)
	}
	if _, err := l3DecryptReceive(d); err != ErrNoSession {
		t.Errorf("l3DecryptReceive no session: got %v, want ErrNoSession", err)
	}
}

var _ io.Reader = (*deterministicReader)(nil) // compile-time interface check
