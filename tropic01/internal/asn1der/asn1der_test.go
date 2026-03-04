package asn1der_test

import (
	"bytes"
	"testing"

	"libtropic-go/tropic01/internal/asn1der"
)

func TestExtractSubjectPublicKey(t *testing.T) {
	// Build a minimal DER structure containing a BIT STRING with a 32-byte key.
	pubKey := make([]byte, 32)
	for i := range pubKey {
		pubKey[i] = byte(i + 1)
	}

	// BIT STRING: tag=0x03, length=33, unused-bits=0x00, then key bytes
	bitStringContent := append([]byte{0x00}, pubKey...)
	bitString := append([]byte{0x03, byte(len(bitStringContent))}, bitStringContent...)

	// Wrap in SEQUENCE
	outer := append([]byte{0x30, byte(len(bitString))}, bitString...)

	got, err := asn1der.ExtractSubjectPublicKey(outer)
	if err != nil {
		t.Fatalf("ExtractSubjectPublicKey: %v", err)
	}
	if !bytes.Equal(got, pubKey) {
		t.Errorf("got %x, want %x", got, pubKey)
	}
}

func TestExtractSubjectPublicKeyNoBitString(t *testing.T) {
	// SEQUENCE with no BIT STRING inside — must return error.
	inner := []byte{0x02, 0x01, 0x00} // INTEGER 0
	outer := append([]byte{0x30, byte(len(inner))}, inner...)
	_, err := asn1der.ExtractSubjectPublicKey(outer)
	if err == nil {
		t.Error("expected error when no BIT STRING found, got nil")
	}
}

func TestExtractSubjectPublicKeyTruncated(t *testing.T) {
	_, err := asn1der.ExtractSubjectPublicKey([]byte{0x30, 0x10}) // claims 16 bytes but none follow
	if err == nil {
		t.Error("expected error on truncated DER, got nil")
	}
}
