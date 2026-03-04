package tropic01

import (
	"encoding/binary"

	"libtropic-go/tropic01/internal/asn1der"
)

// L3 result status codes — first byte of decrypted L3 response.
// Mirrors L3ResultStatus in Rust and TR01_L3_RESULT_* in C.
const (
	l3ResultOK             = 0xC3
	l3ResultFail           = 0x3C
	l3ResultUnauthorized   = 0x01
	l3ResultInvalidCmd     = 0x02
	l3ResultSlotNotEmpty   = 0x10
	l3ResultSlotExpired    = 0x11
	l3ResultInvalidKey     = 0x12
	l3ResultUpdateErr      = 0x13
	l3ResultCounterInvalid = 0x14
	l3ResultSlotEmpty      = 0x15
	l3ResultSlotInvalid    = 0x16
	l3ResultHardwareFail   = 0x17
)

// l3Check decodes the first byte of a decrypted L3 response.
// It returns nil if the result is OK, or a specific error matching the chip's
// L3 result status code.
func l3Check(resp []byte) error {
	if len(resp) == 0 {
		return ErrFail
	}
	switch resp[0] {
	case l3ResultOK:
		return nil
	case l3ResultFail:
		return ErrL3CmdFailed
	case l3ResultUnauthorized:
		return ErrL3Unauthorized
	case l3ResultInvalidCmd:
		return ErrL3InvalidCmd
	case l3ResultSlotNotEmpty:
		return ErrL3SlotNotEmpty
	case l3ResultSlotExpired:
		return ErrL3SlotExpired
	case l3ResultInvalidKey:
		return ErrL3InvalidKey
	case l3ResultUpdateErr:
		return ErrL3UpdateErr
	case l3ResultCounterInvalid:
		return ErrL3CounterInvalid
	case l3ResultSlotEmpty:
		return ErrL3SlotEmpty
	case l3ResultSlotInvalid:
		return ErrL3SlotInvalid
	case l3ResultHardwareFail:
		return ErrL3HardwareFail
	default:
		return ErrFail
	}
}

// GetInfo sends an L2 GET_INFO request for the given object and block index
// and returns the raw response data. No L3 session is required.
// Mirrors lt_get_info_chip_id / lt_get_info_riscv_fw_ver etc. in libtropic.h.
func (d *Device) GetInfo(objectID byte, blockIndex byte) ([]byte, error) {
	payload := []byte{objectID, blockIndex}
	return l2SendRecv(d, l2ReqGetInfo, payload)
}

// Sleep puts TROPIC01 into sleep mode.
// No L3 session is required.
// Mirrors lt_sleep in libtropic.h.
func (d *Device) Sleep(sleepKind byte) error {
	_, err := l2SendRecv(d, l2ReqSleep, []byte{sleepKind})
	return err
}

// Reboot (Startup) sends an L2 STARTUP request to reboot TROPIC01.
// No L3 session is required.
// Mirrors lt_reboot in libtropic.h.
func (d *Device) Startup(startupID byte) error {
	_, err := l2SendRecv(d, l2ReqStartup, []byte{startupID})
	return err
}

// SessionStart performs the Noise_KK1_25519_AESGCM_SHA256 handshake.
// It reads the chip's certificate store to obtain the chip's static public key
// (stpub), then performs the Noise handshake using the provided host keys.
//
// shPriv is the host's 32-byte X25519 private key.
// shPub is the host's 32-byte X25519 public key.
// pkeyIndex is the pairing key slot (0–3).
//
// Mirrors Rust's session_start which calls get_info_cert_store() internally.
func (d *Device) SessionStart(shPriv, shPub []byte, pkeyIndex byte) error {
	// Read the chip's certificate store and extract stpub.
	certData, err := d.GetInfoCertStore()
	if err != nil {
		return err
	}
	stpub, err := extractChipPublicKey(certData)
	if err != nil {
		return err
	}
	return l3SessionStart(d, shPriv, shPub, stpub, pkeyIndex)
}

// SessionAbort aborts the current L3 session.
// The local session state is always cleared regardless of the L2 outcome.
// Mirrors lt_session_abort in libtropic.h.
func (d *Device) SessionAbort() error {
	return l3SessionAbort(d)
}

// Ping sends a PING command over an established L3 session and returns the
// echoed data. The response bytes start with the result status byte followed
// by the echoed payload.
// Mirrors lt_ping in libtropic.h.
func (d *Device) Ping(data []byte) ([]byte, error) {
	if d.session.status != sessionOn {
		return nil, ErrNoSession
	}
	cmd := make([]byte, 1+len(data))
	cmd[0] = l3CmdPing
	copy(cmd[1:], data)
	if err := l3EncryptSend(d, cmd); err != nil {
		return nil, err
	}
	resp, err := l3DecryptReceive(d)
	if err != nil {
		return nil, err
	}
	if err := l3Check(resp); err != nil {
		return nil, err
	}
	// Return a copy of the data bytes after the result byte.
	if len(resp) > 1 {
		data := make([]byte, len(resp)-1)
		copy(data, resp[1:])
		return data, nil
	}
	return nil, nil
}

// PairingKeyWrite writes a 32-byte pairing public key into slot 0–3.
// Requires an active L3 session.
// Mirrors lt_pairing_key_write in libtropic.h.
func (d *Device) PairingKeyWrite(slot byte, key []byte) error {
	if d.session.status != sessionOn {
		return ErrNoSession
	}
	// Payload: cmd_id(1) || slot(2 LE) || padding(1) || key(32) = 36 bytes total cmd size
	cmd := make([]byte, 36)
	cmd[0] = l3CmdPairingKeyWrite
	binary.LittleEndian.PutUint16(cmd[1:], uint16(slot))
	cmd[3] = 0x00 // padding
	copy(cmd[4:], key)
	if err := l3EncryptSend(d, cmd); err != nil {
		return err
	}
	resp, err := l3DecryptReceive(d)
	if err != nil {
		return err
	}
	return l3Check(resp)
}

// PairingKeyRead reads the 32-byte pairing public key from slot 0–3.
// Requires an active L3 session.
// Mirrors lt_pairing_key_read in libtropic.h.
func (d *Device) PairingKeyRead(slot byte) ([]byte, error) {
	if d.session.status != sessionOn {
		return nil, ErrNoSession
	}
	// Payload: cmd_id(1) || slot(2 LE) = 3 bytes cmd size
	cmd := make([]byte, 3)
	cmd[0] = l3CmdPairingKeyRead
	binary.LittleEndian.PutUint16(cmd[1:], uint16(slot))
	if err := l3EncryptSend(d, cmd); err != nil {
		return nil, err
	}
	resp, err := l3DecryptReceive(d)
	if err != nil {
		return nil, err
	}
	if err := l3Check(resp); err != nil {
		return nil, err
	}
	// Response: result(1) || padding(3) || key(32)
	if len(resp) < 4+32 {
		return nil, ErrFail
	}
	key := make([]byte, 32)
	copy(key, resp[4:4+32])
	return key, nil
}

// PairingKeyInvalidate invalidates the pairing key in slot 0–3.
// Requires an active L3 session.
// Mirrors lt_pairing_key_invalidate in libtropic.h.
func (d *Device) PairingKeyInvalidate(slot byte) error {
	if d.session.status != sessionOn {
		return ErrNoSession
	}
	cmd := make([]byte, 3)
	cmd[0] = l3CmdPairingKeyInvalidate
	binary.LittleEndian.PutUint16(cmd[1:], uint16(slot))
	if err := l3EncryptSend(d, cmd); err != nil {
		return err
	}
	resp, err := l3DecryptReceive(d)
	if err != nil {
		return err
	}
	return l3Check(resp)
}

// RMemDataWrite writes data into the given slot of the User Partition in R-Memory.
// Requires an active L3 session.
// Mirrors lt_r_mem_data_write in libtropic.h.
func (d *Device) RMemDataWrite(slot uint16, data []byte) error {
	if d.session.status != sessionOn {
		return ErrNoSession
	}
	// Payload: cmd_id(1) || udata_slot(2 LE) || padding(1) || data
	cmd := make([]byte, 4+len(data))
	cmd[0] = l3CmdRMemDataWrite
	binary.LittleEndian.PutUint16(cmd[1:], slot)
	cmd[3] = 0x00 // padding
	copy(cmd[4:], data)
	if err := l3EncryptSend(d, cmd); err != nil {
		return err
	}
	resp, err := l3DecryptReceive(d)
	if err != nil {
		return err
	}
	return l3Check(resp)
}

// RMemDataRead reads bytes from the given slot of the User Partition in R-Memory.
// Requires an active L3 session.
// Mirrors lt_r_mem_data_read in libtropic.h.
func (d *Device) RMemDataRead(slot uint16) ([]byte, error) {
	if d.session.status != sessionOn {
		return nil, ErrNoSession
	}
	// Payload: cmd_id(1) || udata_slot(2 LE) = 3 bytes
	cmd := make([]byte, 3)
	cmd[0] = l3CmdRMemDataRead
	binary.LittleEndian.PutUint16(cmd[1:], slot)
	if err := l3EncryptSend(d, cmd); err != nil {
		return nil, err
	}
	resp, err := l3DecryptReceive(d)
	if err != nil {
		return nil, err
	}
	if err := l3Check(resp); err != nil {
		return nil, err
	}
	// Response: result(1) || padding(3) || data
	if len(resp) < 4 {
		return nil, ErrFail
	}
	out := make([]byte, len(resp)-4)
	copy(out, resp[4:])
	return out, nil
}

// RMemDataErase erases the given slot of the User Partition in R-Memory.
// Requires an active L3 session.
// Mirrors lt_r_mem_data_erase in libtropic.h.
func (d *Device) RMemDataErase(slot uint16) error {
	if d.session.status != sessionOn {
		return ErrNoSession
	}
	cmd := make([]byte, 3)
	cmd[0] = l3CmdRMemDataErase
	binary.LittleEndian.PutUint16(cmd[1:], slot)
	if err := l3EncryptSend(d, cmd); err != nil {
		return err
	}
	resp, err := l3DecryptReceive(d)
	if err != nil {
		return err
	}
	return l3Check(resp)
}

// ECCKeyGenerate generates an ECC key in the specified slot.
// slot selects the ECC key slot (0–31).
// curve selects the curve type (use constants from libtropic_common.h).
// Requires an active L3 session.
// Mirrors lt_ecc_key_generate in libtropic.h.
func (d *Device) ECCKeyGenerate(slot byte, curve byte) error {
	if d.session.status != sessionOn {
		return ErrNoSession
	}
	// Payload: cmd_id(1) || slot(2 LE) || curve(1) = 4 bytes
	cmd := make([]byte, 4)
	cmd[0] = l3CmdECCKeyGenerate
	binary.LittleEndian.PutUint16(cmd[1:], uint16(slot))
	cmd[3] = curve
	if err := l3EncryptSend(d, cmd); err != nil {
		return err
	}
	resp, err := l3DecryptReceive(d)
	if err != nil {
		return err
	}
	return l3Check(resp)
}

// ECCKeyRead reads the public ECC key from the specified slot.
// Returns the raw public key bytes followed by curve type and origin.
// The full response including result, curve, origin and key bytes is returned.
// Requires an active L3 session.
// Mirrors lt_ecc_key_read in libtropic.h.
func (d *Device) ECCKeyRead(slot byte) ([]byte, error) {
	if d.session.status != sessionOn {
		return nil, ErrNoSession
	}
	// Payload: cmd_id(1) || slot(2 LE) = 3 bytes
	cmd := make([]byte, 3)
	cmd[0] = l3CmdECCKeyRead
	binary.LittleEndian.PutUint16(cmd[1:], uint16(slot))
	if err := l3EncryptSend(d, cmd); err != nil {
		return nil, err
	}
	resp, err := l3DecryptReceive(d)
	if err != nil {
		return nil, err
	}
	if err := l3Check(resp); err != nil {
		return nil, err
	}
	// Response: result(1) || curve(1) || origin(1) || padding(13) || pubkey(32 or 64)
	if len(resp) < 15 {
		return nil, ErrFail
	}
	out := make([]byte, len(resp)-1)
	copy(out, resp[1:])
	return out, nil
}

// ECCKeyErase erases the ECC key from the specified slot.
// Requires an active L3 session.
// Mirrors lt_ecc_key_erase in libtropic.h.
func (d *Device) ECCKeyErase(slot byte) error {
	if d.session.status != sessionOn {
		return ErrNoSession
	}
	// Payload: cmd_id(1) || slot(2 LE) = 3 bytes
	cmd := make([]byte, 3)
	cmd[0] = l3CmdECCKeyErase
	binary.LittleEndian.PutUint16(cmd[1:], uint16(slot))
	if err := l3EncryptSend(d, cmd); err != nil {
		return err
	}
	resp, err := l3DecryptReceive(d)
	if err != nil {
		return err
	}
	return l3Check(resp)
}

// ECDSASign signs the provided 32-byte hash with the private ECC key in slot.
// Returns 64 bytes of signature (R || S).
// Requires an active L3 session.
// Mirrors lt_ecc_ecdsa_sign in libtropic.h.
func (d *Device) ECDSASign(slot byte, hash []byte) ([]byte, error) {
	if d.session.status != sessionOn {
		return nil, ErrNoSession
	}
	// Payload: cmd_id(1) || slot(2 LE) || padding(13) || hash(32) = 48 bytes
	cmd := make([]byte, 48)
	cmd[0] = l3CmdECDSASign
	binary.LittleEndian.PutUint16(cmd[1:], uint16(slot))
	// cmd[3..15] = padding (zero)
	copy(cmd[16:], hash)
	if err := l3EncryptSend(d, cmd); err != nil {
		return nil, err
	}
	resp, err := l3DecryptReceive(d)
	if err != nil {
		return nil, err
	}
	if err := l3Check(resp); err != nil {
		return nil, err
	}
	// Response: result(1) || padding(15) || r(32) || s(32)
	if len(resp) < 1+15+64 {
		return nil, ErrFail
	}
	sig := make([]byte, 64)
	copy(sig, resp[16:16+64])
	return sig, nil
}

// EdDSASign signs the provided message with the EdDSA private key in slot.
// Returns 64 bytes of signature (R || S).
// Requires an active L3 session.
// Mirrors lt_ecc_eddsa_sign in libtropic.h.
func (d *Device) EdDSASign(slot byte, msg []byte) ([]byte, error) {
	if d.session.status != sessionOn {
		return nil, ErrNoSession
	}
	// Payload: cmd_id(1) || slot(2 LE) || padding(13) || msg
	cmd := make([]byte, 16+len(msg))
	cmd[0] = l3CmdEdDSASign
	binary.LittleEndian.PutUint16(cmd[1:], uint16(slot))
	// cmd[3..15] = padding (zero)
	copy(cmd[16:], msg)
	if err := l3EncryptSend(d, cmd); err != nil {
		return nil, err
	}
	resp, err := l3DecryptReceive(d)
	if err != nil {
		return nil, err
	}
	if err := l3Check(resp); err != nil {
		return nil, err
	}
	// Response: result(1) || padding(15) || r(32) || s(32)
	if len(resp) < 1+15+64 {
		return nil, ErrFail
	}
	sig := make([]byte, 64)
	copy(sig, resp[16:16+64])
	return sig, nil
}

// MCTRUpdate increments the monotonic counter at the given slot (index 0–15).
// Requires an active L3 session.
// Mirrors lt_mcounter_update in libtropic.h.
func (d *Device) MCTRUpdate(slot byte) error {
	if d.session.status != sessionOn {
		return ErrNoSession
	}
	// Payload: cmd_id(1) || mcounter_index(2 LE) = 3 bytes
	cmd := make([]byte, 3)
	cmd[0] = l3CmdMctrUpdate
	binary.LittleEndian.PutUint16(cmd[1:], uint16(slot))
	if err := l3EncryptSend(d, cmd); err != nil {
		return err
	}
	resp, err := l3DecryptReceive(d)
	if err != nil {
		return err
	}
	return l3Check(resp)
}

// MCTRGet returns the current value of the monotonic counter at the given slot.
// The response contains 4 bytes of counter value (little-endian uint32) after
// the result byte and 3 bytes of padding.
// Requires an active L3 session.
// Mirrors lt_mcounter_get in libtropic.h.
func (d *Device) MCTRGet(slot byte) (uint32, error) {
	if d.session.status != sessionOn {
		return 0, ErrNoSession
	}
	// Payload: cmd_id(1) || mcounter_index(2 LE) = 3 bytes
	cmd := make([]byte, 3)
	cmd[0] = l3CmdMctrGet
	binary.LittleEndian.PutUint16(cmd[1:], uint16(slot))
	if err := l3EncryptSend(d, cmd); err != nil {
		return 0, err
	}
	resp, err := l3DecryptReceive(d)
	if err != nil {
		return 0, err
	}
	if err := l3Check(resp); err != nil {
		return 0, err
	}
	// Response: result(1) || padding(3) || mcounter_val(4 LE)
	if len(resp) < 8 {
		return 0, ErrFail
	}
	val := binary.LittleEndian.Uint32(resp[4:8])
	return val, nil
}

// RandomValueGet requests n random bytes from TROPIC01.
// Requires an active L3 session.
func (d *Device) RandomValueGet(n byte) ([]byte, error) {
	if d.session.status != sessionOn {
		return nil, ErrNoSession
	}
	// Payload: cmd_id(1) || n_bytes(1) = 2 bytes
	cmd := []byte{l3CmdRandomValueGet, n}
	if err := l3EncryptSend(d, cmd); err != nil {
		return nil, err
	}
	resp, err := l3DecryptReceive(d)
	if err != nil {
		return nil, err
	}
	if err := l3Check(resp); err != nil {
		return nil, err
	}
	// Response: result(1) || padding(3) || random_bytes(n)
	if len(resp) < 4 {
		return nil, ErrFail
	}
	out := make([]byte, len(resp)-4)
	copy(out, resp[4:])
	return out, nil
}

// ECCKeyStore stores a private ECC key into the specified slot.
// Requires an active L3 session.
func (d *Device) ECCKeyStore(slot byte, curve byte, key []byte) error {
	if d.session.status != sessionOn {
		return ErrNoSession
	}
	// Payload: cmd_id(1) || slot(2 LE) || curve(1) || padding(12) || key(32) = 48 bytes
	cmd := make([]byte, 48)
	cmd[0] = l3CmdECCKeyStore
	binary.LittleEndian.PutUint16(cmd[1:], uint16(slot))
	cmd[3] = curve
	// cmd[4..15] = padding (zero)
	copy(cmd[16:], key)
	if err := l3EncryptSend(d, cmd); err != nil {
		return err
	}
	resp, err := l3DecryptReceive(d)
	if err != nil {
		return err
	}
	return l3Check(resp)
}

// RConfigWrite writes a 32-bit value to the R-Config address.
// Requires an active L3 session.
func (d *Device) RConfigWrite(address uint16, value uint32) error {
	if d.session.status != sessionOn {
		return ErrNoSession
	}
	// Payload: cmd_id(1) || address(2 LE) || padding(1) || value(4 LE) = 8 bytes
	cmd := make([]byte, 8)
	cmd[0] = l3CmdRConfigWrite
	binary.LittleEndian.PutUint16(cmd[1:], address)
	cmd[3] = 0x00
	binary.LittleEndian.PutUint32(cmd[4:], value)
	if err := l3EncryptSend(d, cmd); err != nil {
		return err
	}
	resp, err := l3DecryptReceive(d)
	if err != nil {
		return err
	}
	return l3Check(resp)
}

// RConfigRead reads a 32-bit value from the R-Config address.
// Requires an active L3 session.
func (d *Device) RConfigRead(address uint16) (uint32, error) {
	if d.session.status != sessionOn {
		return 0, ErrNoSession
	}
	// Payload: cmd_id(1) || address(2 LE) = 3 bytes
	cmd := make([]byte, 3)
	cmd[0] = l3CmdRConfigRead
	binary.LittleEndian.PutUint16(cmd[1:], address)
	if err := l3EncryptSend(d, cmd); err != nil {
		return 0, err
	}
	resp, err := l3DecryptReceive(d)
	if err != nil {
		return 0, err
	}
	if err := l3Check(resp); err != nil {
		return 0, err
	}
	// Response: result(1) || padding(3) || value(4 LE)
	if len(resp) < 8 {
		return 0, ErrFail
	}
	return binary.LittleEndian.Uint32(resp[4:8]), nil
}

// RConfigErase erases the R-Config area.
// Requires an active L3 session.
func (d *Device) RConfigErase() error {
	if d.session.status != sessionOn {
		return ErrNoSession
	}
	cmd := []byte{l3CmdRConfigErase}
	if err := l3EncryptSend(d, cmd); err != nil {
		return err
	}
	resp, err := l3DecryptReceive(d)
	if err != nil {
		return err
	}
	return l3Check(resp)
}

// IConfigWrite writes a single bit in the I-Config area.
// Requires an active L3 session.
func (d *Device) IConfigWrite(address uint16, bitIndex byte) error {
	if d.session.status != sessionOn {
		return ErrNoSession
	}
	// Payload: cmd_id(1) || address(2 LE) || bit_index(1) = 4 bytes
	cmd := make([]byte, 4)
	cmd[0] = l3CmdIConfigWrite
	binary.LittleEndian.PutUint16(cmd[1:], address)
	cmd[3] = bitIndex
	if err := l3EncryptSend(d, cmd); err != nil {
		return err
	}
	resp, err := l3DecryptReceive(d)
	if err != nil {
		return err
	}
	return l3Check(resp)
}

// IConfigRead reads a 32-bit value from the I-Config address.
// Requires an active L3 session.
func (d *Device) IConfigRead(address uint16) (uint32, error) {
	if d.session.status != sessionOn {
		return 0, ErrNoSession
	}
	// Payload: cmd_id(1) || address(2 LE) = 3 bytes
	cmd := make([]byte, 3)
	cmd[0] = l3CmdIConfigRead
	binary.LittleEndian.PutUint16(cmd[1:], address)
	if err := l3EncryptSend(d, cmd); err != nil {
		return 0, err
	}
	resp, err := l3DecryptReceive(d)
	if err != nil {
		return 0, err
	}
	if err := l3Check(resp); err != nil {
		return 0, err
	}
	// Response: result(1) || padding(3) || value(4 LE)
	if len(resp) < 8 {
		return 0, ErrFail
	}
	return binary.LittleEndian.Uint32(resp[4:8]), nil
}

// MCTRInit initialises a monotonic counter slot to the given value.
// Requires an active L3 session.
func (d *Device) MCTRInit(slot byte, value uint32) error {
	if d.session.status != sessionOn {
		return ErrNoSession
	}
	// Payload: cmd_id(1) || index(2 LE) || padding(1) || value(4 LE) = 8 bytes
	cmd := make([]byte, 8)
	cmd[0] = l3CmdMctrInit
	binary.LittleEndian.PutUint16(cmd[1:], uint16(slot))
	cmd[3] = 0x00
	binary.LittleEndian.PutUint32(cmd[4:], value)
	if err := l3EncryptSend(d, cmd); err != nil {
		return err
	}
	resp, err := l3DecryptReceive(d)
	if err != nil {
		return err
	}
	return l3Check(resp)
}

// MacAndDestroy computes a MAC over dataIn using the key in slot, then
// destroys the key. Returns the 32-byte MAC.
// Requires an active L3 session.
func (d *Device) MacAndDestroy(slot uint16, dataIn []byte) ([]byte, error) {
	if d.session.status != sessionOn {
		return nil, ErrNoSession
	}
	// Payload: cmd_id(1) || slot(2 LE) || padding(1) || data(32) = 36 bytes
	cmd := make([]byte, 36)
	cmd[0] = l3CmdMacAndDestroy
	binary.LittleEndian.PutUint16(cmd[1:], slot)
	cmd[3] = 0x00
	copy(cmd[4:], dataIn)
	if err := l3EncryptSend(d, cmd); err != nil {
		return nil, err
	}
	resp, err := l3DecryptReceive(d)
	if err != nil {
		return nil, err
	}
	if err := l3Check(resp); err != nil {
		return nil, err
	}
	// Response: result(1) || padding(3) || mac(32)
	if len(resp) < 4+32 {
		return nil, ErrFail
	}
	mac := make([]byte, 32)
	copy(mac, resp[4:4+32])
	return mac, nil
}

// GetInfoChipID reads the chip ID via L2 GET_INFO. No session required.
// Mirrors Rust InfoReq::ChipId = 0x01.
func (d *Device) GetInfoChipID() ([]byte, error) {
	return d.GetInfo(0x01, 0x00)
}

// GetInfoRiscvFWVer reads the RISC-V firmware version. No session required.
// Mirrors Rust InfoReq::_RiscvFwVersion = 0x02.
func (d *Device) GetInfoRiscvFWVer() ([]byte, error) {
	return d.GetInfo(0x02, 0x00)
}

// GetInfoSpectFWVer reads the SPECT firmware version. No session required.
// Mirrors Rust InfoReq::_SpectFwVersion = 0x04.
func (d *Device) GetInfoSpectFWVer() ([]byte, error) {
	return d.GetInfo(0x04, 0x00)
}

// GetInfoFWBank reads firmware bank header for the given bankID. No session required.
// Mirrors Rust InfoReq::_FwBank = 0xb0.
func (d *Device) GetInfoFWBank(bankID byte) ([]byte, error) {
	return d.GetInfo(0xb0, bankID)
}

// extractChipPublicKey parses the cert store raw data, extracts the device
// certificate (cert 0), and returns the 32-byte X25519 public key (stpub).
//
// Cert store format:
//
//	byte 0:     version (must be 1)
//	byte 1:     num_certs (must be 4)
//	bytes 2-9:  4 × 2-byte big-endian certificate lengths
//	bytes 10+:  certificate data (contiguous)
func extractChipPublicKey(certStore []byte) ([]byte, error) {
	if len(certStore) < 10 {
		return nil, ErrFail
	}
	if certStore[0] != 1 || certStore[1] != 4 {
		return nil, ErrFail
	}
	// Device cert is cert 0; its length is at bytes 2-3 (BE).
	certLen := int(certStore[2])<<8 | int(certStore[3])
	headerSize := 2 + 4*2 // 10 bytes
	if len(certStore) < headerSize+certLen {
		return nil, ErrFail
	}
	deviceCert := certStore[headerSize : headerSize+certLen]
	return asn1der.ExtractSubjectPublicKey(deviceCert)
}

// GetInfoCertStore reads the certificate store via L2 GET_INFO multi-block reads.
// No L3 session is required.
// Returns the concatenated certificate store data (up to 30 blocks of 128 bytes).
func (d *Device) GetInfoCertStore() ([]byte, error) {
	const certBlocks = 30
	var result []byte
	for i := byte(0); i < certBlocks; i++ {
		data, err := d.GetInfo(0x00, i)
		if err != nil {
			return nil, err
		}
		result = append(result, data...)
	}
	return result, nil
}

// GetLogReq sends an L2 GET_LOG request and returns the raw response.
// No L3 session is required.
func (d *Device) GetLogReq() ([]byte, error) {
	return l2SendRecv(d, l2ReqGetLog, nil)
}

// FirmwareUpdate is not yet implemented.
// It returns ErrNotImplemented unconditionally.
func (d *Device) FirmwareUpdate() error {
	return ErrNotImplemented
}
