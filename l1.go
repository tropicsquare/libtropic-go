package libtropic

// l2GetResponseReqID is the GET_RESPONSE request identifier written to buff[0]
// before each poll, mirroring TR01_L1_GET_RESPONSE_REQ_ID in the C library.
const l2GetResponseReqID = 0x01

// l1Write sends d.l2buf[0:length] to the chip via a single SPI transaction.
// Mirrors lt_l1_write in lt_l1.c:
//
//	CSNLow → Transfer(buf[0:length]) → CSNHigh
func l1Write(d *Device, length int) error {
	if err := d.t.CSNLow(); err != nil {
		return err
	}
	if err := d.t.Transfer(d.l2buf[:length]); err != nil {
		_ = d.t.CSNHigh()
		return err
	}
	return d.t.CSNHigh()
}

// l1Read polls the chip until READY, then reads the full response frame into
// d.l2buf. Mirrors lt_l1_read in lt_l1.c.
//
// Protocol (per C source):
//  1. Set buff[0] = GET_RESPONSE_REQ_ID.
//  2. CSNLow.
//  3. Transfer 1 byte (offset 0) → chip_status in buff[0].
//  4. If ALARM bit set: CSNHigh, return ErrL1SPI (chip alarm mode).
//  5. If READY bit set (CSN still low):
//     a. Transfer 2 bytes (offset 1) → STATUS in buff[1], LEN in buff[2].
//     b. If STATUS == 0xFF: CSNHigh, delay, continue (no response yet).
//     c. Otherwise: read buff[2]+2 bytes at offset 3 (data + CRC), CSNHigh, return nil.
//  6. If not READY: CSNHigh, delay, continue.
//  7. After l1MaxRetries exhausted: return ErrL1Timeout.
func l1Read(d *Device) error {
	for range l1MaxRetries {
		// Set GET_RESPONSE_REQ_ID in the first byte before each poll.
		d.l2buf[0] = l2GetResponseReqID

		// Assert CSN.
		if err := d.t.CSNLow(); err != nil {
			return err
		}

		// Transfer 1 byte to read CHIP_STATUS into buff[0].
		if err := d.t.Transfer(d.l2buf[:1]); err != nil {
			_ = d.t.CSNHigh()
			return ErrL1SPI
		}

		chipStatus := d.l2buf[0]

		// ALARM bit is fatal — deassert CSN and return error.
		if chipStatus&l1StatusAlarm != 0 {
			_ = d.t.CSNHigh()
			d.logger.Debug("l1: chip alarm mode", "chip_status", chipStatus)
			return ErrL1SPI
		}

		// READY bit: continue reading within the same CSN transaction.
		if chipStatus&l1StatusReady != 0 {
			// Read STATUS (buff[1]) and LEN (buff[2]) — 2 bytes at offset 1.
			if err := d.t.Transfer(d.l2buf[1:3]); err != nil {
				_ = d.t.CSNHigh()
				return ErrL1SPI
			}

			// If STATUS == 0xFF the chip has no response prepared yet; retry.
			// This mirrors the `if (s2->buff[1] == 0xff)` check in lt_l1.c.
			if d.l2buf[1] == 0xff {
				if err := d.t.CSNHigh(); err != nil {
					return err
				}
				if err := d.t.Delay(l1RetryDelay); err != nil {
					return err
				}
				continue
			}

			// Compute remaining bytes: buff[2] (data len) + 2 (CRC).
			dataAndCRC := int(d.l2buf[l2RespLenOffset]) + 2
			total := 3 + dataAndCRC // header (3) + data + CRC
			if total > len(d.l2buf) {
				_ = d.t.CSNHigh()
				return ErrL2ResTooLong
			}

			// Read remaining bytes starting at offset 3.
			if err := d.t.Transfer(d.l2buf[3:total]); err != nil {
				_ = d.t.CSNHigh()
				return ErrL1SPI
			}

			return d.t.CSNHigh()
		}

		// Not READY (and not ALARM): deassert CSN and wait before retrying.
		if err := d.t.CSNHigh(); err != nil {
			return err
		}
		if err := d.t.Delay(l1RetryDelay); err != nil {
			return err
		}
	}

	return ErrL1Timeout
}
