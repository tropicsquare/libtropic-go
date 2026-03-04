package tropic01

// l2GetResponseReqID is the GET_RESPONSE request identifier written to buf[0]
// before each poll, mirroring L2_CMD_ID_GET_RESPONSE in the Rust crate.
const l2GetResponseReqID = 0xAA

// l2CmdReqLen is written to buf[1] in l1Read, mirroring L2_CMD_REQ_LEN = 128
// in the Rust crate. It tells the chip the maximum response length the host
// can accept.
const l2CmdReqLen = 128

// l1Write sends d.l2buf[0:length] to the chip via SPI, retrying until the chip
// reports READY. Mirrors lt_l1_write in the Rust crate which loops up to
// L1_READ_MAX_TRIES times, waiting 25 ms between attempts.
func l1Write(d *Device, length int) error {
	// Save the outgoing frame since Transfer overwrites buf[0] with chip status.
	var saved [l1LenMax]byte
	copy(saved[:length], d.l2buf[:length])

	for range l1MaxRetries {
		// Restore the original frame (chip status overwrites buf[0] each transfer).
		copy(d.l2buf[:length], saved[:length])

		if err := d.t.CSNLow(); err != nil {
			return err
		}
		if err := d.t.Transfer(d.l2buf[:length]); err != nil {
			_ = d.t.CSNHigh()
			return err
		}
		if err := d.t.CSNHigh(); err != nil {
			return err
		}

		chipStatus := d.l2buf[0]

		if chipStatus&l1StatusAlarm != 0 {
			return ErrL1SPI
		}

		if chipStatus&l1StatusReady != 0 {
			return nil
		}

		// Not ready yet — wait before retrying.
		if err := d.t.Delay(l1RetryDelay); err != nil {
			return err
		}
	}

	// Rust returns Ok(()) even after exhausting retries; we do the same.
	return nil
}

// l1Read polls the chip until READY, then reads the full response frame into
// d.l2buf. Mirrors lt_l1_read in the Rust and C implementations.
//
// Each iteration performs a single full-buffer SPI transfer:
//
//	CSNLow → Transfer(l2buf[:]) → CSNHigh
//
// After the transfer:
//   - l2buf[0] = CHIP_STATUS (overwritten during SPI exchange)
//   - l2buf[1] = STATUS
//   - l2buf[2] = LEN
//   - l2buf[3..] = DATA + CRC
//
// Using a single transfer (instead of multiple small ones) ensures
// compatibility with transport backends that deassert CS between exchanges,
// such as USB serial dongles.
func l1Read(d *Device) error {
	for range l1MaxRetries {
		// Clear the buffer and set the GET_RESPONSE request ID and length.
		clear(d.l2buf[:])
		d.l2buf[0] = l2GetResponseReqID
		d.l2buf[1] = l2CmdReqLen

		// Single full-buffer transfer.
		if err := d.t.CSNLow(); err != nil {
			return err
		}
		if err := d.t.Transfer(d.l2buf[:]); err != nil {
			_ = d.t.CSNHigh()
			return ErrL1SPI
		}
		if err := d.t.CSNHigh(); err != nil {
			return err
		}

		chipStatus := d.l2buf[0]

		// ALARM bit is fatal.
		if chipStatus&l1StatusAlarm != 0 {
			d.logger.Debug("l1: chip alarm mode", "chip_status", chipStatus)
			return ErrL1SPI
		}

		// READY bit set and STATUS is not 0xFF: response is available.
		if chipStatus&l1StatusReady != 0 && d.l2buf[1] != 0xff {
			return nil
		}

		// Not ready yet — wait before retrying.
		if err := d.t.Delay(l1RetryDelay); err != nil {
			return err
		}
	}

	return ErrL1Timeout
}
