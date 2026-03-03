package libtropic

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
)

// noiseHKDF derives two 32-byte keys from chaining key ck and input material,
// following the Noise framework HKDF (NOT RFC 5869). Mirrors lt_hkdf.c.
//
//	tmp  = HMAC-SHA256(key=ck, data=input)
//	out1 = HMAC-SHA256(key=tmp, data=[0x01])
//	out2 = HMAC-SHA256(key=tmp, data=out1 || [0x02])
//
// The ck parameter may be 32 or 33 bytes depending on the call site, matching
// the C lt_hkdf signature which accepts ck_len as a separate parameter.
func noiseHKDF(ck, input []byte) (out1, out2 []byte) {
	mac := hmac.New(sha256.New, ck)
	mac.Write(input)
	tmp := mac.Sum(nil)

	mac = hmac.New(sha256.New, tmp)
	mac.Write([]byte{0x01})
	out1 = mac.Sum(nil)

	// helper = out1 (32 bytes) || 0x02 — mirrors the 33-byte helper[] in lt_hkdf.c
	helper := make([]byte, len(out1)+1)
	copy(helper, out1)
	helper[len(out1)] = 0x02

	mac = hmac.New(sha256.New, tmp)
	mac.Write(helper)
	out2 = mac.Sum(nil)
	return
}

// hmacSHA256 computes HMAC-SHA256(key, data).
func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// sha256Hash computes SHA-256(data).
func sha256Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// aesGCMEncrypt encrypts plaintext with AES-256-GCM.
// Returns (ciphertext, tag, error). tag is always l3TagSize (16) bytes.
func aesGCMEncrypt(key, nonce, plaintext, aad []byte) (ct, tag []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, ErrCrypto
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, l3IVSize)
	if err != nil {
		return nil, nil, ErrCrypto
	}
	combined := gcm.Seal(nil, nonce, plaintext, aad)
	ct = combined[:len(combined)-l3TagSize]
	tag = combined[len(combined)-l3TagSize:]
	return
}

// aesGCMDecrypt decrypts ciphertext with AES-256-GCM.
// Returns ErrCrypto on authentication failure.
func aesGCMDecrypt(key, nonce, ct, tag, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrCrypto
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, l3IVSize)
	if err != nil {
		return nil, ErrCrypto
	}
	combined := make([]byte, len(ct)+len(tag))
	copy(combined, ct)
	copy(combined[len(ct):], tag)
	pt, err := gcm.Open(nil, nonce, combined, aad)
	if err != nil {
		return nil, ErrCrypto
	}
	return pt, nil
}

// incrementIV adds 1 to the 96-bit IV stored big-endian in iv[:].
func incrementIV(iv []byte) {
	for i := len(iv) - 1; i >= 0; i-- {
		iv[i]++
		if iv[i] != 0 {
			break
		}
	}
}
