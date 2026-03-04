package tropic01

import (
	"bytes"
	"testing"
)

func TestNoiseHKDF(t *testing.T) {
	// Verify structure: out1 and out2 must be 32 bytes and different.
	var ck [32]byte
	copy(ck[:], []byte(noiseProtocolName))
	input := []byte{0x01, 0x02, 0x03}

	out1, out2 := noiseHKDF(ck[:], input)

	if len(out1) != 32 {
		t.Errorf("out1 len = %d, want 32", len(out1))
	}
	if len(out2) != 32 {
		t.Errorf("out2 len = %d, want 32", len(out2))
	}
	if bytes.Equal(out1, out2) {
		t.Error("out1 == out2, want different")
	}
}

func TestAESGCMRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	plaintext := []byte("hello TROPIC01")
	aad := []byte("additional data")

	ct, tag, err := aesGCMEncrypt(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	if len(tag) != l3TagSize {
		t.Errorf("tag len = %d, want %d", len(tag), l3TagSize)
	}

	pt, err := aesGCMDecrypt(key, nonce, ct, tag, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("decrypted = %q, want %q", pt, plaintext)
	}
}

func TestAESGCMDecryptBadTag(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	plaintext := []byte("hello")

	ct, tag, _ := aesGCMEncrypt(key, nonce, plaintext, nil)
	tag[0] ^= 0xFF // corrupt tag

	_, err := aesGCMDecrypt(key, nonce, ct, tag, nil)
	if err == nil {
		t.Error("expected error on bad tag, got nil")
	}
}

func TestIncrementIV(t *testing.T) {
	tests := []struct {
		name  string
		input [12]byte
		want  [12]byte
	}{
		{
			"simple increment",
			[12]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			[12]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		},
		{
			"carry propagation",
			[12]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF},
			[12]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			iv := tc.input
			incrementIV(iv[:])
			if iv != tc.want {
				t.Errorf("incrementIV(%x) = %x, want %x", tc.input, iv, tc.want)
			}
		})
	}
}
