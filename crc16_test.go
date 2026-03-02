package libtropic

import "testing"

func TestCRC16(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want uint16
	}{
		// Empty input
		{"empty", []byte{}, 0x0000},
		// Single zero byte
		{"zero byte", []byte{0x00}, 0x0000},
		// Known vector: "123456789" — matches C lt_crc16.c output (MSB-first + byte-swap)
		{"123456789", []byte("123456789"), 0xE8FE},
		// Single byte 0x01 — matches C lt_crc16.c output (MSB-first + byte-swap)
		{"0x01", []byte{0x01}, 0x0580},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := crc16(tc.data)
			if got != tc.want {
				t.Errorf("crc16(%x) = 0x%04x, want 0x%04x", tc.data, got, tc.want)
			}
		})
	}
}
