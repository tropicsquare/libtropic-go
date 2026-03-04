package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"

	tropic01 "libtropic-go/tropic01"
	"libtropic-go/tropic01/keys"
)

func runECCEdDSA(dev *tropic01.Device) error {
	fmt.Println("=== ECC EdDSA Example ===")

	// Reboot chip.
	fmt.Println("Rebooting chip...")
	if err := dev.Startup(tropic01.StartupReqReboot); err != nil {
		return fmt.Errorf("startup: %w", err)
	}

	// Start secure session.
	fmt.Println("Starting secure session...")
	if err := dev.SessionStart(keys.SH0PrivProd0[:], keys.SH0PubProd0[:], 0); err != nil {
		return fmt.Errorf("session start: %w", err)
	}

	const eccSlot byte = 0

	// Erase ECC slot 0 (ignore if already empty).
	fmt.Printf("Erasing ECC slot %d...\n", eccSlot)
	if err := dev.ECCKeyErase(eccSlot); err != nil && err != tropic01.ErrL3SlotEmpty {
		return fmt.Errorf("ecc key erase: %w", err)
	}

	// Generate Ed25519 key.
	fmt.Println("Generating Ed25519 key...")
	if err := dev.ECCKeyGenerate(eccSlot, tropic01.EccCurveEd25519); err != nil {
		return fmt.Errorf("ecc key generate: %w", err)
	}

	// Read public key.
	fmt.Println("Reading public key...")
	keyData, err := dev.ECCKeyRead(eccSlot)
	if err != nil {
		return fmt.Errorf("ecc key read: %w", err)
	}
	// keyData: curve(1) || origin(1) || padding(13) || pubkey(32)
	if len(keyData) < 15+32 {
		return fmt.Errorf("unexpected key data length: %d", len(keyData))
	}
	pubKey := ed25519.PublicKey(keyData[15 : 15+32])
	fmt.Printf("Public key: %x\n", pubKey)

	// Sign a SHA-256 hash.
	message := []byte("Hello from TROPIC01 EdDSA!")
	hash := sha256.Sum256(message)
	fmt.Printf("Signing SHA-256 hash of %q...\n", message)
	sig, err := dev.EdDSASign(eccSlot, hash[:])
	if err != nil {
		return fmt.Errorf("eddsa sign hash: %w", err)
	}
	fmt.Printf("Signature: %x\n", sig)

	// Verify with crypto/ed25519.
	if ed25519.Verify(pubKey, hash[:], sig) {
		fmt.Println("Hash signature verification: PASSED")
	} else {
		fmt.Println("Hash signature verification: FAILED")
	}

	// Sign a raw long message.
	longMsg := []byte("This is a longer message to demonstrate raw EdDSA signing with TROPIC01 secure element.")
	fmt.Println("Signing raw long message...")
	sig2, err := dev.EdDSASign(eccSlot, longMsg)
	if err != nil {
		return fmt.Errorf("eddsa sign raw: %w", err)
	}
	fmt.Printf("Signature: %x\n", sig2)

	if ed25519.Verify(pubKey, longMsg, sig2) {
		fmt.Println("Raw message signature verification: PASSED")
	} else {
		fmt.Println("Raw message signature verification: FAILED")
	}

	// Abort session.
	fmt.Println("Aborting session...")
	if err := dev.SessionAbort(); err != nil {
		return fmt.Errorf("session abort: %w", err)
	}

	fmt.Println("Done!")
	return nil
}
