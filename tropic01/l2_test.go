package tropic01

import (
	"testing"
)

func TestL2FrameCheck(t *testing.T) {
	tests := []struct {
		name    string
		frame   func() []byte
		wantErr error
	}{
		{
			"result OK with valid CRC",
			func() []byte {
				// Frame: CHIP_STATUS(1) STATUS(1) LEN(1) DATA(n) CRC_HI(1) CRC_LO(1)
				// CRC covers STATUS + LEN + DATA (bytes starting at offset 1)
				status := byte(l2StatusResultOK) // 0x02
				length := byte(1)
				data := byte(0xAB)
				crcInput := []byte{status, length, data}
				c := crc16(crcInput)
				return []byte{0x00, status, length, data, byte(c >> 8), byte(c)}
			},
			nil,
		},
		{
			"result OK with bad CRC",
			func() []byte {
				return []byte{0x00, l2StatusResultOK, 0x01, 0xAB, 0xFF, 0xFF}
			},
			ErrL2CRCIn,
		},
		{
			"no session status",
			func() []byte {
				return []byte{0x00, l2StatusNoSession, 0x00, 0x00, 0x00}
			},
			ErrL2NoSession,
		},
		{
			"request OK with valid CRC",
			func() []byte {
				status := byte(l2StatusRequestOK)
				length := byte(2)
				data := []byte{0x11, 0x22}
				crcInput := append([]byte{status, length}, data...)
				c := crc16(crcInput)
				frame := []byte{0x00, status, length}
				frame = append(frame, data...)
				frame = append(frame, byte(c>>8), byte(c))
				return frame
			},
			nil,
		},
		{
			"request OK with bad CRC",
			func() []byte {
				return []byte{0x00, l2StatusRequestOK, 0x01, 0xAB, 0x00, 0x00}
			},
			ErrL2CRCIn,
		},
		{
			"request cont status",
			func() []byte {
				return []byte{0x00, l2StatusRequestCont, 0x00, 0x00, 0x00}
			},
			ErrL2ReqCont,
		},
		{
			"result cont status",
			func() []byte {
				return []byte{0x00, l2StatusResultCont, 0x00, 0x00, 0x00}
			},
			ErrL2ResCont,
		},
		{
			"handshake error status",
			func() []byte {
				return []byte{0x00, l2StatusHSKErr, 0x00, 0x00, 0x00}
			},
			ErrL2HSKErr,
		},
		{
			"tag error status",
			func() []byte {
				return []byte{0x00, l2StatusTagErr, 0x00, 0x00, 0x00}
			},
			ErrL2TagErr,
		},
		{
			"CRC error status",
			func() []byte {
				return []byte{0x00, l2StatusCRCErr, 0x00, 0x00, 0x00}
			},
			ErrL2CRCErr,
		},
		{
			"general error status",
			func() []byte {
				return []byte{0x00, l2StatusGenErr, 0x00, 0x00, 0x00}
			},
			ErrL2GenErr,
		},
		{
			"no response status",
			func() []byte {
				return []byte{0x00, l2StatusNoResp, 0x00, 0x00, 0x00}
			},
			ErrL2NoResp,
		},
		{
			"unknown error status",
			func() []byte {
				return []byte{0x00, l2StatusUnknownErr, 0x00, 0x00, 0x00}
			},
			ErrL2UnknownReq,
		},
		{
			"response disabled status",
			func() []byte {
				return []byte{0x00, l2StatusRespDisabled, 0x00, 0x00, 0x00}
			},
			ErrL2RespDisabled,
		},
		{
			"unknown status byte",
			func() []byte {
				return []byte{0x00, 0xFE, 0x00, 0x00, 0x00}
			},
			ErrL2StatusUnknown,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := l2FrameCheck(tc.frame())
			if err != tc.wantErr {
				t.Errorf("l2FrameCheck() = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestL2SendPayloadTooLong(t *testing.T) {
	// l2Send must reject payloads exceeding l2MaxDataSize.
	payload := make([]byte, l2MaxDataSize+1)
	d := &Device{}
	err := l2Send(d, l2ReqGetInfo, payload)
	if err != ErrL2ReqTooLong {
		t.Errorf("l2Send with oversized payload: got %v, want %v", err, ErrL2ReqTooLong)
	}
}

func TestL2SendRecv(t *testing.T) {
	// Build a valid response frame for STATUS=ResultOK, DATA=[0xDE, 0xAD].
	data := []byte{0xDE, 0xAD}
	status := byte(l2StatusResultOK)
	length := byte(len(data))
	crcInput := append([]byte{status, length}, data...)
	c := crc16(crcInput)
	respFrame := []byte{0x00, status, length}
	respFrame = append(respFrame, data...)
	respFrame = append(respFrame, byte(c>>8), byte(c))

	// Use a scripted transport: respond with the valid frame.
	tr := newScriptedTransport(t, respFrame)
	d := NewDevice(tr)

	payload := []byte{0x01, 0x02}
	got, err := l2SendRecv(d, l2ReqGetInfo, payload)
	if err != nil {
		t.Fatalf("l2SendRecv: unexpected error %v", err)
	}
	if len(got) != len(data) {
		t.Fatalf("l2SendRecv: got %d bytes, want %d", len(got), len(data))
	}
	for i, b := range data {
		if got[i] != b {
			t.Errorf("l2SendRecv: byte[%d] = 0x%02x, want 0x%02x", i, got[i], b)
		}
	}
}

// scriptedTransport implements Transport for unit-testing l2 functions.
// It counts SPI transactions: the first CSNLow/Transfer/CSNHigh triplet is the
// l1Write (send), the subsequent triplets are the l1Read (receive) polling phases.
type scriptedTransport struct {
	t         *testing.T
	response  []byte // full response frame: chip_status + status + len + data + crc
	callCount int    // counts Transfer calls
}

func newScriptedTransport(t *testing.T, response []byte) *scriptedTransport {
	return &scriptedTransport{t: t, response: response}
}

func (s *scriptedTransport) Init() error                  { return nil }
func (s *scriptedTransport) Deinit() error                { return nil }
func (s *scriptedTransport) Delay(_ uint32) error         { return nil }
func (s *scriptedTransport) RandomBytes(buf []byte) error { return nil }
func (s *scriptedTransport) CSNLow() error                { return nil }
func (s *scriptedTransport) CSNHigh() error               { return nil }

func (s *scriptedTransport) Transfer(buf []byte) error {
	s.callCount++
	// Call 1: l1Write — outgoing frame. l1Write retries until READY,
	//         so we must return chip status = READY so it succeeds immediately.
	// Call 2: l1Read — single full-buffer transfer returning the complete
	//         response: chip_status + STATUS + LEN + DATA + CRC.
	switch s.callCount {
	case 1:
		// outgoing write — report chip READY so l1Write stops retrying
		buf[0] = l1StatusReady
	case 2:
		// Full response: chip_status(READY) + response frame
		buf[0] = l1StatusReady
		copy(buf[1:], s.response[1:])
	default:
		s.t.Errorf("scriptedTransport: unexpected Transfer call #%d", s.callCount)
	}
	return nil
}
