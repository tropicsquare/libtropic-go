package tropic01

import (
	"crypto/ecdh"
	"crypto/rand"
)

// l3IncrementIV adds 1 to the 32-bit little-endian counter stored in iv[0:4],
// matching the C lt_l3_nonce_increase which treats nonce[0..3] as a uint32 LE.
// The upper bytes (iv[4:12]) are always zero and remain unchanged.
func l3IncrementIV(iv []byte) {
	for i := range 4 {
		iv[i]++
		if iv[i] != 0 {
			break
		}
	}
}

// l3SessionStart performs the Noise_KK1_25519_AESGCM_SHA256 handshake.
//
// shPriv is the host's raw X25519 private scalar (32 bytes).
// siPub is the chip's static identity public key (32 bytes, from the chip certificate).
// pkeyIndex selects the pairing key slot (0–3).
//
// The function sends an L2 HANDSHAKE request containing the host ephemeral
// public key and pkey_index, receives the chip's ephemeral public key and auth
// tag, verifies the tag, derives session keys, and stores them in d.session.
//
// Mirrors lt_out__session_start + lt_in__session_start in libtropic_l3.c.
func l3SessionStart(d *Device, shPriv, shPub, stpub []byte, pkeyIndex byte) error {
	// Invalidate any previous session.
	d.session = sessionState{}

	// Parse host static key.
	curve := ecdh.X25519()
	shKey, err := curve.NewPrivateKey(shPriv)
	if err != nil {
		return ErrParam
	}

	// Generate ephemeral host key pair.
	ehKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return ErrCrypto
	}
	ehPub := ehKey.PublicKey().Bytes() // 32 bytes

	// Build SHA-256 hash chain for the Noise handshake transcript.
	// protocol_name is padded/truncated to exactly 32 bytes (with trailing NUL bytes).
	protocolNameFixed := make([]byte, 32)
	copy(protocolNameFixed, []byte(noiseProtocolName))

	// h = SHA256(protocol_name[32])
	h := sha256Hash(protocolNameFixed)

	// h = SHA256(h || SHiPUB)  — host's static public key
	h = sha256Hash(append(h, shPub...))

	// h = SHA256(h || STPUB)   — chip's static public key (from cert)
	h = sha256Hash(append(h, stpub...))

	// h = SHA256(h || EHPUB)   — host's ephemeral public key
	h = sha256Hash(append(h, ehPub...))

	// h = SHA256(h || PKEY_INDEX) — 1 byte
	h = sha256Hash(append(h, pkeyIndex))

	// Send L2 HANDSHAKE request: payload = [EHPUB(32) || pkey_index(1)]
	reqPayload := make([]byte, 33)
	copy(reqPayload[:32], ehPub)
	reqPayload[32] = pkeyIndex

	rspData, err := l2SendRecv(d, l2ReqHandshake, reqPayload)
	if err != nil {
		return err
	}

	// HANDSHAKE response data: [ETPUB(32) || t_tauth(16)] = 48 bytes
	// Mirrors the TR01_L2_HANDSHAKE_RSP_LEN exact-length check added in v3.2.0.
	if len(rspData) != 48 {
		return ErrL2RspLenError
	}
	etPub := rspData[:32]
	tTauth := rspData[32:48]

	// Parse chip ephemeral public key.
	etPubKey, err := curve.NewPublicKey(etPub)
	if err != nil {
		return ErrCrypto
	}

	// h = SHA256(h || ETPUB) — chip's ephemeral public key
	h = sha256Hash(append(h, etPub...))

	// Key derivation — four-step HKDF chain matching lt_in__session_start:
	//
	//   ck0           = protocol_name[32]
	//   ck1, _        = hkdf(ck0[32],  ES)   ES  = X25519(ehpriv, etpub)
	//   ck2, _        = hkdf(ck1[33],  SE)   SE  = X25519(shipriv, etpub)
	//   ck3, kauth    = hkdf(ck2[33],  ES2)  ES2 = X25519(ehpriv, stpub)
	//   kcmd, kres    = hkdf(ck3[33],  "")
	//
	// The 33-byte ck buffer is output1 (32 bytes) with a trailing 0x00,
	// matching the C output_1[33] array which is zero-initialised.

	// ES = X25519(ehpriv, etpub)
	stPubKey, err := curve.NewPublicKey(stpub)
	if err != nil {
		return ErrCrypto
	}
	es, err := ehKey.ECDH(etPubKey)
	if err != nil {
		return ErrCrypto
	}

	// SE = X25519(shipriv, etpub)
	se, err := shKey.ECDH(etPubKey)
	if err != nil {
		return ErrCrypto
	}

	// ES2 = X25519(ehpriv, stpub)
	es2, err := ehKey.ECDH(stPubKey)
	if err != nil {
		return ErrCrypto
	}

	// step 1: ck1, _ = hkdf(ck0[32], ES)
	ck1, _ := noiseHKDF(protocolNameFixed, es)

	// step 2: ck2, _ = hkdf(ck1[33], SE)
	ck1_33 := make([]byte, 33)
	copy(ck1_33, ck1)
	ck2, _ := noiseHKDF(ck1_33, se)

	// step 3: ck3, kauth = hkdf(ck2[33], ES2)
	ck2_33 := make([]byte, 33)
	copy(ck2_33, ck2)
	ck3, kauth := noiseHKDF(ck2_33, es2)

	// step 4: kcmd, kres = hkdf(ck3[33], "")
	ck3_33 := make([]byte, 33)
	copy(ck3_33, ck3)
	kcmd, kres := noiseHKDF(ck3_33, []byte{})

	// Verify the handshake authentication tag.
	// C: lt_aesgcm_decrypt(kauth, decryption_IV[12]=zeros, aad=hash, ct=[], tag=t_tauth)
	zeroNonce := make([]byte, l3IVSize)
	if _, err := aesGCMDecrypt(kauth, zeroNonce, []byte{}, tTauth, h); err != nil {
		return ErrL2HSKErr
	}

	// Store session keys and mark session active.
	copy(d.session.kcmd[:], kcmd)
	copy(d.session.kres[:], kres)
	// IVs are zero-initialised (session struct is freshly zeroed above).
	d.session.status = sessionOn

	return nil
}

// l3SessionAbort aborts the current L3 session by sending SESSION_ABORT to the
// chip and clearing local session state, regardless of whether the L2 send
// succeeds.  Mirrors lt_l3_session_abort in libtropic.c.
func l3SessionAbort(d *Device) error {
	// Always clear local session state.
	defer func() { d.session = sessionState{} }()
	_, err := l2SendRecv(d, l2ReqSessionAbort, nil)
	return err
}

// l3EncryptSend encrypts an L3 command payload with the current session key
// (kcmd/ivcmd) and sends it to the chip as an ENCRYPTED_CMD L2 request.
//
// The L3 frame format sent over L2 is:
//
//	[size_lo || size_hi || ciphertext(len=len(cmdPayload)) || tag(16)]
//
// where size is the plaintext length encoded as a 16-bit little-endian value,
// matching the C lt_l3_gen_frame_t layout.
//
// Returns ErrNoSession if no session is active.
func l3EncryptSend(d *Device, cmdPayload []byte) error {
	if d.session.status != sessionOn {
		return ErrNoSession
	}

	plen := len(cmdPayload)

	// Build L3 frame header: cmd_size as 16-bit LE.
	frameHeader := []byte{byte(plen), byte(plen >> 8)}

	// Encrypt: AAD is empty (matches C: (uint8_t*)"", 0).
	ct, tag, err := aesGCMEncrypt(d.session.kcmd[:], d.session.ivcmd[:], cmdPayload, []byte{})
	if err != nil {
		return err
	}

	// Increment the command IV (little-endian uint32 in bytes 0–3).
	l3IncrementIV(d.session.ivcmd[:])

	// Build L2 payload: [size_lo || size_hi || ciphertext || tag]
	payload := make([]byte, 2+len(ct)+len(tag))
	copy(payload[:2], frameHeader)
	copy(payload[2:], ct)
	copy(payload[2+len(ct):], tag)

	// Send the encrypted command and read the L2 acknowledgment (ReqOk).
	// The actual encrypted response is read separately by l3DecryptReceive.
	_, err = l2SendRecv(d, l2ReqEncryptedCmd, payload)
	return err
}

// l3DecryptReceive receives an ENCRYPTED_CMD response from the chip and
// decrypts it using the current session key (kres/ivres).
//
// The received L3 frame has the format:
//
//	[size_lo || size_hi || ciphertext(len=size) || tag(16)]
//
// Returns ErrNoSession if no session is active.
// Returns ErrCrypto on authentication failure.
func l3DecryptReceive(d *Device) ([]byte, error) {
	if d.session.status != sessionOn {
		return nil, ErrNoSession
	}

	// Receive the L2 response payload.
	data, err := l2Receive(d)
	if err != nil {
		return nil, err
	}

	// Minimum: 2-byte size + 16-byte tag.
	if len(data) < 2+l3TagSize {
		return nil, ErrCrypto
	}

	// Parse the size field (16-bit LE).
	size := int(data[0]) | int(data[1])<<8

	// Validate: data must contain exactly 2 + size + 16 bytes.
	if len(data) < 2+size+l3TagSize {
		return nil, ErrCrypto
	}

	ct := data[2 : 2+size]
	tag := data[2+size : 2+size+l3TagSize]

	// Decrypt: AAD is empty (matches C: (uint8_t*)"", 0).
	pt, err := aesGCMDecrypt(d.session.kres[:], d.session.ivres[:], ct, tag, []byte{})
	if err != nil {
		return nil, err
	}

	// Increment the response IV.
	l3IncrementIV(d.session.ivres[:])

	return pt, nil
}
