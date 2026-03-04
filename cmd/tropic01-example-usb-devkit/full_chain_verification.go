package main

import (
	"encoding/binary"
	"fmt"
	"os"

	tropic01 "libtropic-go/tropic01"
)

func runFullChainVerification(dev *tropic01.Device) error {
	fmt.Println("=== Full Chain Verification Example ===")

	// Reboot chip.
	fmt.Println("Rebooting chip...")
	if err := dev.Startup(tropic01.StartupReqReboot); err != nil {
		return fmt.Errorf("startup: %w", err)
	}

	// Read certificate store via L2 GET_INFO (no session required).
	fmt.Println("Reading certificate store...")
	certStore, err := dev.GetInfoCertStore()
	if err != nil {
		return fmt.Errorf("get cert store: %w", err)
	}
	fmt.Printf("Certificate store size: %d bytes\n", len(certStore))

	// Parse certificate store header.
	// Header layout (first 16 bytes):
	//   magic(4) || version(2) || num_certs(2) || offsets(2*num_certs)
	// Each cert entry: offset(2 LE) || length(2 LE)
	if len(certStore) < 16 {
		return fmt.Errorf("certificate store too short: %d bytes", len(certStore))
	}

	// Try to extract up to 4 DER certificates based on the cert store layout.
	// The exact header format depends on the firmware version; we use a simple
	// heuristic: scan for DER SEQUENCE headers (0x30 0x82).
	certs := extractDERCerts(certStore)
	if len(certs) == 0 {
		fmt.Println("No DER certificates found in cert store, writing raw data.")
		if err := os.WriteFile("cert_store_raw.bin", certStore, 0644); err != nil {
			return fmt.Errorf("write raw cert store: %w", err)
		}
		fmt.Println("Wrote cert_store_raw.bin")
		return nil
	}

	certNames := []string{
		"device_cert.der",
		"intermediate_ca.der",
		"tropic01_ca.der",
		"root_ca.der",
	}
	for i, cert := range certs {
		name := fmt.Sprintf("cert_%d.der", i)
		if i < len(certNames) {
			name = certNames[i]
		}
		if err := os.WriteFile(name, cert, 0644); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
		fmt.Printf("Wrote %s (%d bytes)\n", name, len(cert))
	}

	fmt.Println("Done!")
	return nil
}

// extractDERCerts attempts to extract DER-encoded certificates from the cert
// store data. It first tries offset-based parsing, falling back to scanning
// for DER SEQUENCE headers.
func extractDERCerts(data []byte) [][]byte {
	// Try offset-based parsing: header has 4-byte entries (offset LE + length LE)
	// starting at byte 8, with number of certs at bytes 6-7.
	if len(data) >= 16 {
		numCerts := int(binary.LittleEndian.Uint16(data[6:8]))
		if numCerts > 0 && numCerts <= 8 && 8+numCerts*4 <= len(data) {
			var certs [][]byte
			valid := true
			for i := 0; i < numCerts; i++ {
				off := int(binary.LittleEndian.Uint16(data[8+i*4:]))
				length := int(binary.LittleEndian.Uint16(data[8+i*4+2:]))
				if off+length > len(data) || length == 0 {
					valid = false
					break
				}
				certs = append(certs, data[off:off+length])
			}
			if valid && len(certs) > 0 {
				return certs
			}
		}
	}

	// Fallback: scan for DER SEQUENCE headers (0x30 0x82 = long-form length).
	var certs [][]byte
	for i := 0; i < len(data)-4; {
		if data[i] == 0x30 && data[i+1] == 0x82 {
			certLen := int(data[i+2])<<8 | int(data[i+3])
			total := 4 + certLen // tag(1) + len_marker(1) + len_bytes(2) + content
			if i+total <= len(data) {
				certs = append(certs, data[i:i+total])
				i += total
				continue
			}
		}
		i++
	}
	return certs
}
