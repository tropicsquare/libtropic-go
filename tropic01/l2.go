package tropic01

// l2FrameCheck validates an L2 response frame stored in frame[].
//
// Frame layout (mirrors lt_l2_frame_check.c):
//
//	frame[0]           = CHIP_STATUS (from L1, not used here)
//	frame[1]           = STATUS
//	frame[2]           = LEN (number of DATA bytes)
//	frame[3..2+LEN]    = DATA
//	frame[3+LEN]       = CRC high byte
//	frame[4+LEN]       = CRC low byte
//
// CRC is computed over frame[1..2+LEN] (STATUS + LEN + DATA), i.e.
// (LEN + 2) bytes starting at offset 1.  This mirrors the C expression:
//
//	crc16(frame + 1, len + 2)
//
// For STATUS codes that indicate valid frames (REQUEST_OK, RESULT_OK) the CRC
// is verified; all other status codes map directly to their error values.
func l2FrameCheck(frame []byte) error {
	status := frame[l2RespStatusOffset]
	length := frame[l2RespLenOffset]

	switch status {
	case l2StatusRequestOK, l2StatusResultOK:
		// Reconstruct the expected CRC from the frame.
		// C: frame_crc = frame[len+4] | frame[len+3] << 8
		// i.e. frame[3+len] is hi, frame[4+len] is lo (big-endian).
		hiIdx := int(length) + 3
		loIdx := int(length) + 4
		frameCRC := uint16(frame[hiIdx])<<8 | uint16(frame[loIdx])

		// CRC covers STATUS + LEN + DATA: (length + 2) bytes at offset 1.
		computed := crc16(frame[1 : 3+int(length)])
		if frameCRC != computed {
			return ErrL2CRCIn
		}
		return nil

	case l2StatusRequestCont:
		return ErrL2ReqCont
	case l2StatusResultCont:
		return ErrL2ResCont
	case l2StatusHSKErr:
		return ErrL2HSKErr
	case l2StatusNoSession:
		return ErrL2NoSession
	case l2StatusTagErr:
		return ErrL2TagErr
	case l2StatusCRCErr:
		return ErrL2CRCErr
	case l2StatusGenErr:
		return ErrL2GenErr
	case l2StatusNoResp:
		return ErrL2NoResp
	case l2StatusUnknownErr:
		return ErrL2UnknownReq
	case l2StatusRespDisabled:
		return ErrL2RespDisabled
	default:
		return ErrL2StatusUnknown
	}
}

// l2Send builds an L2 request frame in d.l2buf and sends it via l1Write.
//
// Frame layout (mirrors add_crc + lt_l2_send in lt_crc16.c / libtropic_l2.c):
//
//	d.l2buf[0]               = REQ_ID
//	d.l2buf[1]               = REQ_LEN (= len(payload))
//	d.l2buf[2..1+len]        = payload
//	d.l2buf[2+len]           = CRC high byte
//	d.l2buf[3+len]           = CRC low byte
//
// CRC is computed over REQ_ID + REQ_LEN + DATA (the first 2+len bytes).
// Total frame length written to l1Write: len(payload) + 4.
func l2Send(d *Device, reqID byte, payload []byte) error {
	if len(payload) > l2MaxDataSize {
		return ErrL2ReqTooLong
	}

	plen := len(payload)

	// Build header.
	d.l2buf[l2ReqIDOffset] = reqID
	d.l2buf[l2ReqLenOffset] = byte(plen)

	// Copy payload into DATA section.
	copy(d.l2buf[l2ReqDataOffset:], payload)

	// Compute and append CRC over REQ_ID + REQ_LEN + DATA.
	// crcLen = plen + 2 (the two header bytes).
	crcLen := plen + 2
	c := crc16(d.l2buf[:crcLen])
	d.l2buf[crcLen] = byte(c >> 8)   // CRC high byte
	d.l2buf[crcLen+1] = byte(c)      // CRC low byte

	// Total frame length: header(2) + data(plen) + crc(2) = plen + 4.
	return l1Write(d, plen+4)
}

// l2Receive reads one L2 response frame from the chip, validates it via
// l2FrameCheck, and returns a copy of the DATA payload.
//
// The returned slice is freshly allocated; it does not alias d.l2buf.
func l2Receive(d *Device) ([]byte, error) {
	if err := l1Read(d); err != nil {
		return nil, err
	}

	if err := l2FrameCheck(d.l2buf[:]); err != nil {
		return nil, err
	}

	// Extract the DATA section: d.l2buf[3..3+LEN-1].
	length := int(d.l2buf[l2RespLenOffset])
	result := make([]byte, length)
	copy(result, d.l2buf[l2RespDataOffset:l2RespDataOffset+length])
	return result, nil
}

// l2SendRecv is a convenience wrapper that sends a request and receives the
// corresponding response in a single call.
func l2SendRecv(d *Device, reqID byte, payload []byte) ([]byte, error) {
	if err := l2Send(d, reqID, payload); err != nil {
		return nil, err
	}
	return l2Receive(d)
}
