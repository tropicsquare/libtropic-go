package sim_test

import (
	"testing"

	"go-libtropic/hal/sim"
)

func TestQueuedTransfer(t *testing.T) {
	s := sim.NewQueued()
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}

	// Enqueue a 4-byte response
	s.EnqueueResponse([]byte{0xDE, 0xAD, 0xBE, 0xEF})

	buf := make([]byte, 4)
	if err := s.CSNLow(); err != nil {
		t.Fatal(err)
	}
	if err := s.Transfer(buf); err != nil {
		t.Fatal(err)
	}
	if err := s.CSNHigh(); err != nil {
		t.Fatal(err)
	}

	want := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	for i, b := range want {
		if buf[i] != b {
			t.Errorf("buf[%d] = 0x%02x, want 0x%02x", i, buf[i], b)
		}
	}
}

func TestQueuedTransferEmptyQueue(t *testing.T) {
	s := sim.NewQueued()
	_ = s.Init()
	buf := make([]byte, 4)
	_ = s.CSNLow()
	if err := s.Transfer(buf); err == nil {
		t.Error("expected error on empty queue, got nil")
	}
}

func TestStatefulGetInfo(t *testing.T) {
	s := sim.NewStateful()
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}

	// Verify it satisfies the Transport interface
	var _ interface {
		Init() error
		Deinit() error
		CSNLow() error
		CSNHigh() error
		Transfer([]byte) error
		Delay(uint32) error
		RandomBytes([]byte) error
	} = s

	// The stateful sim should respond to any request with RESULT_OK.
	// We use the device-level helpers to issue a GetInfo-style request.
	// Build a minimal GET_INFO request manually and push it through.
	// For now just verify Init/Deinit round-trip and no panics.
	if err := s.Deinit(); err != nil {
		t.Fatal(err)
	}
}

func TestStatefulResultOK(t *testing.T) {
	s := sim.NewStateful()
	_ = s.Init()

	// Simulate what l1Write + l1Read do:
	// 1. l1Write: CSNLow → Transfer(request) → CSNHigh
	// 2. l1Read poll: CSNLow → Transfer(1 byte poll) → CSNHigh
	//    Should get CHIP_STATUS with READY bit set
	// 3. l1ReadFrame: CSNLow stays, Transfer(3 header bytes) + Transfer(full frame)

	// l1Write step
	req := make([]byte, 4) // minimal frame
	req[0] = 0x01          // GET_INFO req ID
	req[1] = 0x01          // 1 byte data
	req[2] = 0x00          // data
	// CRC skipped for this low-level test
	_ = s.CSNLow()
	_ = s.Transfer(req)
	_ = s.CSNHigh()

	// l1Read poll step: Transfer 1 byte, expect READY bit set
	poll := make([]byte, 1)
	_ = s.CSNLow()
	if err := s.Transfer(poll); err != nil {
		t.Fatalf("poll Transfer: %v", err)
	}
	if poll[0]&0x01 == 0 {
		t.Errorf("poll response chip_status=0x%02x, want READY bit (0x01) set", poll[0])
	}
	// Continue reading (CSN stays low in l1ReadFrame)
	header := make([]byte, 2) // STATUS + LEN
	if err := s.Transfer(header); err != nil {
		t.Fatalf("header Transfer: %v", err)
	}
	if header[0] != 0x02 { // l2StatusResultOK
		t.Errorf("status=0x%02x, want 0x02 (RESULT_OK)", header[0])
	}
	dataLen := int(header[1])
	remaining := make([]byte, dataLen+2) // data + CRC
	_ = s.Transfer(remaining)
	_ = s.CSNHigh()
}
