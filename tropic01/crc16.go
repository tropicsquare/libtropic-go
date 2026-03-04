package tropic01

// crc16 computes the CRC-16 checksum as used by libtropic (lt_crc16.c).
// Algorithm details:
//   - Polynomial: 0x8005
//   - Initial value: 0x0000
//   - No XOR applied to the raw CRC before the byte-swap
//   - MSB-first bit processing (non-reflected)
//   - Final byte-swap of the result: return (crc<<8 | crc>>8)
//
// This exactly matches the C implementation in libtropic/src/lt_crc16.c,
// including the final byte-swap on line: return (crc << 8 | crc >> 8).
func crc16(data []byte) uint16 {
	var crc uint16
	for _, b := range data {
		crc ^= uint16(b) << 8
		for range 8 {
			if crc&0x8000 != 0 {
				crc <<= 1
				crc ^= 0x8005
			} else {
				crc <<= 1
			}
		}
	}
	// Byte-swap matches the C: return (crc << 8 | crc >> 8)
	return crc<<8 | crc>>8
}
