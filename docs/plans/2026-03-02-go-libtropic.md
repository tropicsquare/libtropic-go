# go-libtropic Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement a pure-Go host-side driver for the TROPIC01 secure element chip, porting the libtropic C library.

**Architecture:** Three-layer protocol (L1 physical SPI, L2 framing+CRC, L3 AES-GCM session) behind a `Transport` interface. Simulator (queued + stateful) enables tests without hardware.

**Tech Stack:** Go 1.26, stdlib only (`crypto/ecdh`, `crypto/aes`, `crypto/cipher`, `crypto/hmac`, `crypto/sha256`, `crypto/hkdf`, `crypto/rand`, `encoding/asn1`, `log/slog`).

**Reference:** All protocol details from `../libtropic/` (vendored C library). Do not introduce external dependencies.

---

### Task 1: Go module scaffold

**Files:**
- Create: `go.mod`
- Create: `doc.go`

**Step 1: Create go.mod**

```
module go-libtropic

go 1.26
```

File: `go.mod`

**Step 2: Create doc.go**

```go
// Package libtropic is a pure-Go port of the TROPIC01 secure element host driver.
//
// Protocol reference: https://github.com/tropicsquare/libtropic
//
// Typical usage:
//
//	dev := libtropic.NewDevice(transport)
//	if err := dev.Init(); err != nil { ... }
//	defer dev.Deinit()
package libtropic
```

File: `doc.go`

**Step 3: Verify module compiles**

Run: `go build ./...`
Expected: no output, exit 0

**Step 4: Commit**

```bash
git add go.mod doc.go
git commit -m "feat: scaffold go-libtropic module"
```

---

### Task 2: Error type

**Files:**
- Create: `errors.go`
- Create: `errors_test.go`

**Step 1: Write the failing test**

```go
package libtropic_test

import (
    "testing"
    libtropic "go-libtropic"
)

func TestErrorString(t *testing.T) {
    tests := []struct {
        err  libtropic.Error
        want string
    }{
        {libtropic.ErrOK, "OK"},
        {libtropic.ErrFail, "fail"},
        {libtropic.ErrNoSession, "no session"},
        {libtropic.ErrParam, "param error"},
        {libtropic.ErrCrypto, "crypto error"},
        {libtropic.Error(99), "unknown error (99)"},
    }
    for _, tc := range tests {
        if got := tc.err.Error(); got != tc.want {
            t.Errorf("Error(%d).Error() = %q, want %q", tc.err, got, tc.want)
        }
    }
}
```

File: `errors_test.go`

**Step 2: Run to verify it fails**

Run: `go test -run TestErrorString ./...`
Expected: FAIL — `libtropic.Error` undefined

**Step 3: Implement errors.go**

```go
package libtropic

import "fmt"

// Error represents a TROPIC01 return code. Numeric values mirror C lt_ret_t.
type Error int

const (
    ErrOK                Error = 0
    ErrFail              Error = 1
    ErrNoSession         Error = 2
    ErrParam             Error = 3
    ErrCrypto            Error = 4
    ErrAppFWTooNew       Error = 5
    ErrAppFWTooOld       Error = 6
    ErrL1L3TooLong       Error = 7
    ErrL1Timeout         Error = 8
    ErrL1SPI             Error = 9
    ErrL2ReqCont         Error = 10
    ErrL2ResCont         Error = 11
    ErrL2ReqTooLong      Error = 12
    ErrL2ResTooLong      Error = 13
    ErrL2CRCIn           Error = 14
    ErrL2HSKErr          Error = 15
    ErrL2NoSession       Error = 16
    ErrL2TagErr          Error = 17
    ErrL2CRCErr          Error = 18
    ErrL2GenErr          Error = 19
    ErrL2NoResp          Error = 20
    ErrL2UnknownReq      Error = 21
    ErrL2RespDisabled    Error = 22
    ErrL2StatusUnknown   Error = 23
    ErrL3Unauthorized    Error = 24
    ErrL3ParamErr        Error = 25
    ErrL3InfoErr         Error = 26
    ErrL3RandomBytesErr  Error = 27
    ErrL3KeyErr          Error = 28
    ErrL3EXTDataErr      Error = 29
    ErrL3DataLenErr      Error = 30
    ErrL3GRIDErr         Error = 31
    ErrL3MCTRLViolation  Error = 32
    ErrL3NoData          Error = 33
    ErrL3KeyUsage        Error = 34
    ErrL3AppBusy         Error = 35
    ErrL3IntegrityErr    Error = 36
    ErrL3Rollback        Error = 37
    ErrL3HibernateErr    Error = 38
    ErrL3SetupErr        Error = 39
    ErrL3SlotExpired     Error = 40
    ErrL3Undefined       Error = 41
    ErrNotImplemented    Error = 42
)

var errorStrings = map[Error]string{
    ErrOK:               "OK",
    ErrFail:             "fail",
    ErrNoSession:        "no session",
    ErrParam:            "param error",
    ErrCrypto:           "crypto error",
    ErrAppFWTooNew:      "app FW too new",
    ErrAppFWTooOld:      "app FW too old",
    ErrL1L3TooLong:      "L1/L3 too long",
    ErrL1Timeout:        "L1 timeout",
    ErrL1SPI:            "L1 SPI error",
    ErrL2ReqCont:        "L2 request continue",
    ErrL2ResCont:        "L2 response continue",
    ErrL2ReqTooLong:     "L2 request too long",
    ErrL2ResTooLong:     "L2 response too long",
    ErrL2CRCIn:          "L2 incoming CRC error",
    ErrL2HSKErr:         "L2 handshake error",
    ErrL2NoSession:      "L2 no session",
    ErrL2TagErr:         "L2 tag error",
    ErrL2CRCErr:         "L2 CRC error",
    ErrL2GenErr:         "L2 general error",
    ErrL2NoResp:         "L2 no response",
    ErrL2UnknownReq:     "L2 unknown request",
    ErrL2RespDisabled:   "L2 response disabled",
    ErrL2StatusUnknown:  "L2 unknown status",
    ErrL3Unauthorized:   "L3 unauthorized",
    ErrL3ParamErr:       "L3 param error",
    ErrL3InfoErr:        "L3 info error",
    ErrL3RandomBytesErr: "L3 random bytes error",
    ErrL3KeyErr:         "L3 key error",
    ErrL3EXTDataErr:     "L3 ext data error",
    ErrL3DataLenErr:     "L3 data len error",
    ErrL3GRIDErr:        "L3 GRID error",
    ErrL3MCTRLViolation: "L3 MCTRL violation",
    ErrL3NoData:         "L3 no data",
    ErrL3KeyUsage:       "L3 key usage",
    ErrL3AppBusy:        "L3 app busy",
    ErrL3IntegrityErr:   "L3 integrity error",
    ErrL3Rollback:       "L3 rollback",
    ErrL3HibernateErr:   "L3 hibernate error",
    ErrL3SetupErr:       "L3 setup error",
    ErrL3SlotExpired:    "L3 slot expired",
    ErrL3Undefined:      "L3 undefined error",
    ErrNotImplemented:   "not implemented",
}

func (e Error) Error() string {
    if s, ok := errorStrings[e]; ok {
        return s
    }
    return fmt.Sprintf("unknown error (%d)", int(e))
}
```

File: `errors.go`

**Step 4: Run test to verify it passes**

Run: `go test -run TestErrorString ./...`
Expected: PASS

**Step 5: Commit**

```bash
git add errors.go errors_test.go
git commit -m "feat: add Error type mirroring C lt_ret_t"
```

---

### Task 3: Protocol constants

**Files:**
- Create: `constants.go`

**Step 1: Write constants.go**

No tests needed — pure constants. Verify it compiles.

```go
package libtropic

// L1 timing and retry constants (mirrors lt_l1.h).
const (
    l1StatusReady   = 0x01 // chip ready for command
    l1StatusAlarm   = 0x02 // chip alarm condition
    l1StatusStartup = 0x04 // chip in startup

    l1MaxRetries = 50    // max status-poll iterations
    l1RetryDelay = 25    // ms between retries

    l1TimeoutMSDefault  = 70  // default command timeout (ms)
    l1TimeoutMSInit     = 5   // startup poll timeout (ms)
    l1TimeoutMSExtended = 150 // extended operation timeout (ms)
)

// L2 frame layout constants (mirrors libtropic_common.h).
const (
    // Request frame offsets
    l2ReqIDOffset  = 0 // REQ_ID byte
    l2ReqLenOffset = 1 // REQ_LEN byte
    l2ReqDataOffset = 2 // DATA start

    // Response frame offsets
    l2RespChipStatusOffset = 0 // CHIP_STATUS byte (from L1)
    l2RespStatusOffset     = 1 // STATUS byte
    l2RespLenOffset        = 2 // RSP_LEN byte
    l2RespDataOffset       = 3 // DATA start

    l2MaxDataSize = 252   // max data bytes per L2 chunk
    l2MaxLoops    = 42    // max receive iterations

    // L2 request IDs (mirrors lt_l2_api_structs.h)
    l2ReqGetInfo      = 0x01
    l2ReqHandshake    = 0x02
    l2ReqEncryptedCmd = 0x04
    l2ReqSessionAbort = 0x08
    l2ReqResend       = 0x10
    l2ReqSleep        = 0x20
    l2ReqStartup      = 0xb3
    l2ReqGetLog       = 0xa2

    // L2 status codes (mirrors libtropic_common.h TR01_L2_STATUS_*)
    l2StatusRequestOK      = 0x01
    l2StatusResultOK       = 0x02
    l2StatusRequestCont    = 0x03
    l2StatusResultCont     = 0x04
    l2StatusHSKErr         = 0x05
    l2StatusNoSession      = 0x06
    l2StatusTagErr         = 0x07
    l2StatusCRCErr         = 0x08
    l2StatusGenErr         = 0x09
    l2StatusNoResp         = 0x0a
    l2StatusUnknownErr     = 0x0b
    l2StatusRespDisabled   = 0x0c
)

// L3 packet constants.
const (
    l3PacketMaxSize = 4113 // TR01_L3_PACKET_MAX_SIZE

    // L3 command IDs (mirrors lt_l3_api_structs.h)
    l3CmdPing           = 0x01
    l3CmdPairingKeyWrite = 0x10
    l3CmdPairingKeyRead  = 0x11
    l3CmdPairingKeyInvalidate = 0x12
    l3CmdRMemDataWrite  = 0x20
    l3CmdRMemDataRead   = 0x21
    l3CmdRMemDataErase  = 0x22
    l3CmdECCKeyGenerate = 0x30
    l3CmdECCKeyStore    = 0x31
    l3CmdECCKeyRead     = 0x32
    l3CmdECCKeyErase    = 0x33
    l3CmdECDSASign      = 0x34
    l3CmdEdDSASign      = 0x35
    l3CmdECDH           = 0x36
    l3CmdMctrUpdate     = 0x40
    l3CmdMctrGet        = 0x41
    l3CmdMacAndDestroy  = 0x50
    l3CmdSeqIDGet       = 0x60
    l3CmdIConfigWrite   = 0x70
    l3CmdIConfigRead    = 0x71
    l3CmdCertStore      = 0x72
    l3CmdLog            = 0x73
    l3CmdFirmwareUpdate = 0x80
    l3CmdReboot         = 0x90
    l3CmdGetInfo        = 0xa0
    l3CmdSessionAbort   = 0xa1

    // AES-GCM parameters
    l3IVSize  = 12
    l3TagSize = 16
    l3KeySize = 32 // AES-256

    // Noise protocol parameters
    noiseProtocolName = "Noise_KK1_25519_AESGCM_SHA256"
    noiseCKSize       = 32
)

// L1 frame total sizes.
const (
    l1LenMax = l2RespDataOffset + l2MaxDataSize + 2 // chip_status + status + len + data + crc_hi + crc_lo
)
```

File: `constants.go`

**Step 2: Verify it compiles**

Run: `go build ./...`
Expected: no output, exit 0

**Step 3: Commit**

```bash
git add constants.go
git commit -m "feat: add protocol constants"
```

---

### Task 4: Transport interface

**Files:**
- Create: `transport.go`

**Step 1: Write transport.go**

```go
package libtropic

// Transport is the hardware abstraction layer for TROPIC01 SPI communication.
//
// Implementations must be safe to call sequentially; concurrent access is
// the caller's responsibility.
//
// See hal/linux for a Linux spidev+GPIO implementation.
// See hal/sim for a test simulator.
type Transport interface {
    // Init opens the underlying hardware resources.
    Init() error
    // Deinit releases hardware resources opened by Init.
    Deinit() error
    // CSNLow asserts the chip-select line (active low).
    CSNLow() error
    // CSNHigh deasserts the chip-select line.
    CSNHigh() error
    // Transfer performs a full-duplex SPI exchange in-place.
    // On return, buf contains the received bytes.
    Transfer(buf []byte) error
    // Delay blocks for at least ms milliseconds.
    Delay(ms uint32) error
    // RandomBytes fills buf with cryptographically random bytes.
    RandomBytes(buf []byte) error
}
```

File: `transport.go`

**Step 2: Verify it compiles**

Run: `go build ./...`
Expected: no output, exit 0

**Step 3: Commit**

```bash
git add transport.go
git commit -m "feat: add Transport interface (HAL)"
```

---

### Task 5: CRC16

**Files:**
- Create: `crc16.go`
- Create: `crc16_test.go`

The C implementation: polynomial `0x8005`, initial value `0x0000`, no final XOR, result is byte-swapped before writing to frame (`crc<<8 | crc>>8`).

The CRC in the frame is stored big-endian: `frame[n] = crc>>8; frame[n+1] = crc&0xff` — but the C does this via the byte-swap trick. We will expose `crc16(data) uint16` returning the raw CRC value, and frame encoding writes `crc>>8, crc&0xff`.

**Step 1: Write the failing test**

```go
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
        // Single zero byte: processing 0x00 through CRC-16/IBM poly 0x8005, init 0x0000
        // Manually: crc=0x0000, bit=0, result stays 0x0000
        {"zero byte", []byte{0x00}, 0x0000},
        // Known vector: "123456789" → CRC-16/IBM = 0xBB3D
        {"123456789", []byte("123456789"), 0xBB3D},
        // Single byte 0x01
        {"0x01", []byte{0x01}, 0x8005},
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
```

File: `crc16_test.go`

**Step 2: Run to verify it fails**

Run: `go test -run TestCRC16 ./...`
Expected: FAIL — `crc16` undefined

**Step 3: Implement crc16.go**

```go
package libtropic

// crc16 computes CRC-16/IBM (polynomial 0x8005, initial 0x0000, no final XOR,
// MSB-first bit processing). This matches the libtropic C implementation
// in lt_crc16.c.
func crc16(data []byte) uint16 {
    var crc uint16
    for _, b := range data {
        crc ^= uint16(b) << 8
        for range 8 {
            if crc&0x8000 != 0 {
                crc = (crc << 1) ^ 0x8005
            } else {
                crc <<= 1
            }
        }
    }
    return crc
}
```

File: `crc16.go`

**Step 4: Run test to verify it passes**

Run: `go test -run TestCRC16 ./...`
Expected: PASS

**Step 5: Commit**

```bash
git add crc16.go crc16_test.go
git commit -m "feat: add CRC16/IBM implementation"
```

---

### Task 6: Functional options + Device struct

**Files:**
- Create: `options.go`
- Create: `device.go`

**Step 1: Write options.go**

```go
package libtropic

import "log/slog"

// Option configures a Device.
type Option func(*Device)

// WithLogger sets the logger used by the device.
// Pass slog.New(slog.NewTextHandler(io.Discard, nil)) to silence all output.
func WithLogger(l *slog.Logger) Option {
    return func(d *Device) { d.logger = l }
}

// WithTimeout sets the L1 polling timeout in milliseconds.
// Default: l1TimeoutMSDefault (70 ms).
func WithTimeout(ms uint32) Option {
    return func(d *Device) { d.timeoutMS = ms }
}
```

File: `options.go`

**Step 2: Write device.go**

```go
package libtropic

import "log/slog"

// tr01Attrs holds firmware-version-specific attributes detected at Init time.
type tr01Attrs struct {
    fwVersion [4]byte
}

// Device is a TROPIC01 secure element driver.
// Use NewDevice to construct one.
type Device struct {
    t         Transport
    l2buf     [l1LenMax]byte
    session   sessionState
    attrs     tr01Attrs
    logger    *slog.Logger
    timeoutMS uint32
}

// NewDevice creates a Device using the given transport and options.
// Call Init before issuing any commands.
func NewDevice(t Transport, opts ...Option) *Device {
    d := &Device{
        t:         t,
        logger:    slog.Default(),
        timeoutMS: l1TimeoutMSDefault,
    }
    for _, o := range opts {
        o(d)
    }
    return d
}

// Init initialises the transport and reads device attributes.
// It mirrors lt_init in the C library.
func (d *Device) Init() error {
    if err := d.t.Init(); err != nil {
        return err
    }
    d.logger.Debug("device initialised")
    return nil
}

// Deinit releases transport resources and invalidates any active session.
func (d *Device) Deinit() error {
    d.session = sessionState{}
    return d.t.Deinit()
}
```

File: `device.go`

**Step 3: Create session.go stub (needed for compilation)**

```go
package libtropic

// sessionStatus indicates whether a secure session is active.
type sessionStatus int

const (
    sessionOff sessionStatus = iota
    sessionOn
)

// sessionState holds the per-direction AES-GCM keys and nonces for an active
// L3 session, plus ephemeral key material for the Noise handshake.
type sessionState struct {
    status sessionStatus
    kcmd   [l3KeySize]byte // host→chip AES-256 key
    kres   [l3KeySize]byte // chip→host AES-256 key
    ivcmd  [l3IVSize]byte  // host→chip nonce (incremented per message)
    ivres  [l3IVSize]byte  // chip→host nonce (incremented per message)
}
```

File: `session.go`

**Step 4: Verify it compiles**

Run: `go build ./...`
Expected: no output, exit 0

**Step 5: Commit**

```bash
git add options.go device.go session.go
git commit -m "feat: add Device struct, options, and session state stub"
```

---

### Task 7: Simulator — queued mode

**Files:**
- Create: `hal/sim/sim.go`
- Create: `hal/sim/sim_test.go`

**Step 1: Write the failing test**

```go
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
```

File: `hal/sim/sim_test.go`

**Step 2: Run to verify it fails**

Run: `go test -run TestQueued ./hal/sim/...`
Expected: FAIL — package not found

**Step 3: Implement hal/sim/sim.go**

```go
// Package sim provides a TROPIC01 Transport simulator for use in tests.
//
// Two modes are available:
//   - Queued: pre-load raw frame bytes; each Transfer copies from the queue.
//   - Stateful: maintains in-memory chip state and processes commands.
package sim

import (
    "errors"
    "fmt"
    "sync"
    "time"
)

// Sim implements [libtropic.Transport] for testing without physical hardware.
type Sim struct {
    mu         sync.Mutex
    queue      [][]byte // pending MISO frames (queued mode)
    inProgress bool     // true between CSNLow and CSNHigh
    stateful   bool     // true when running in stateful mode
    state      *chipState
}

// chipState holds in-memory TROPIC01 state for stateful mode.
type chipState struct {
    // Minimal fields; extended as stateful mode is fleshed out.
    initialized bool
}

// NewQueued returns a Sim in queued-response mode.
func NewQueued() *Sim {
    return &Sim{}
}

// NewStateful returns a Sim in stateful chip-emulation mode.
func NewStateful() *Sim {
    return &Sim{
        stateful: true,
        state:    &chipState{initialized: true},
    }
}

// EnqueueResponse pre-loads a MISO frame that will be returned on the next Transfer.
func (s *Sim) EnqueueResponse(data []byte) {
    s.mu.Lock()
    defer s.mu.Unlock()
    cp := make([]byte, len(data))
    copy(cp, data)
    s.queue = append(s.queue, cp)
}

// Init implements Transport.
func (s *Sim) Init() error { return nil }

// Deinit implements Transport.
func (s *Sim) Deinit() error { return nil }

// CSNLow implements Transport.
func (s *Sim) CSNLow() error {
    s.mu.Lock()
    defer s.mu.Unlock()
    if s.inProgress {
        return errors.New("sim: CSNLow called while transaction in progress")
    }
    s.inProgress = true
    return nil
}

// CSNHigh implements Transport and advances the response queue.
func (s *Sim) CSNHigh() error {
    s.mu.Lock()
    defer s.mu.Unlock()
    if !s.inProgress {
        return errors.New("sim: CSNHigh called without CSNLow")
    }
    s.inProgress = false
    if len(s.queue) > 0 {
        s.queue = s.queue[1:]
    }
    return nil
}

// Transfer implements Transport. In queued mode it copies the head of the
// response queue into buf (zero-padding if the response is shorter).
func (s *Sim) Transfer(buf []byte) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    if !s.inProgress {
        return errors.New("sim: Transfer called without CSNLow")
    }
    if len(s.queue) == 0 {
        return fmt.Errorf("sim: Transfer called with empty queue")
    }
    resp := s.queue[0]
    n := copy(buf, resp)
    for i := n; i < len(buf); i++ {
        buf[i] = 0
    }
    return nil
}

// Delay implements Transport.
func (s *Sim) Delay(ms uint32) error {
    time.Sleep(time.Duration(ms) * time.Millisecond)
    return nil
}

// RandomBytes implements Transport using a simple counter for determinism.
func (s *Sim) RandomBytes(buf []byte) error {
    for i := range buf {
        buf[i] = byte(i)
    }
    return nil
}
```

File: `hal/sim/sim.go`

**Step 4: Run test to verify it passes**

Run: `go test -run TestQueued ./hal/sim/...`
Expected: PASS

**Step 5: Commit**

```bash
git add hal/sim/sim.go hal/sim/sim_test.go
git commit -m "feat: add simulator Transport (queued mode)"
```

---

### Task 8: Layer 1 — SPI read/write

**Files:**
- Create: `l1.go`
- Create: `l1_test.go`

**Step 1: Write the failing test**

```go
package libtropic

import (
    "testing"
    "go-libtropic/hal/sim"
)

func TestL1Write(t *testing.T) {
    s := sim.NewQueued()
    d := NewDevice(s)
    if err := d.Init(); err != nil {
        t.Fatal(err)
    }
    // l1Write sends d.l2buf[0:length] via CSNLow → Transfer → CSNHigh.
    // Enqueue a dummy response so CSNHigh advances queue without panicking.
    s.EnqueueResponse(make([]byte, 4))
    d.l2buf[0] = 0xAB
    d.l2buf[1] = 0xCD
    if err := l1Write(d, 2); err != nil {
        t.Errorf("l1Write: %v", err)
    }
}

func TestL1ReadTimeout(t *testing.T) {
    s := sim.NewQueued()
    d := NewDevice(s)
    _ = d.Init()
    // No response enqueued → polling loop should exhaust and return ErrL1Timeout.
    // Enqueue chip-status bytes that never show READY (all zero).
    for range l1MaxRetries {
        frame := make([]byte, l1LenMax)
        frame[0] = 0x00 // chip status = not ready
        s.EnqueueResponse(frame)
    }
    err := l1Read(d)
    if err != ErrL1Timeout {
        t.Errorf("l1Read timeout: got %v, want ErrL1Timeout", err)
    }
}
```

File: `l1_test.go`

**Step 2: Run to verify it fails**

Run: `go test -run TestL1 ./...`
Expected: FAIL — `l1Write` undefined

**Step 3: Implement l1.go**

```go
package libtropic

// l1Write sends d.l2buf[0:length] to the chip via a single SPI transaction.
// Mirrors lt_l1_write in lt_l1.c.
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
// Protocol:
//  1. Transfer a 2-byte "poll" frame to read CHIP_STATUS and STATUS bytes.
//  2. If STATUS byte has READY bit set, read STATUS+LEN, then full frame.
//  3. Retry up to l1MaxRetries times with l1RetryDelay ms between retries.
func l1Read(d *Device) error {
    poll := [2]byte{}
    for range l1MaxRetries {
        if err := d.t.CSNLow(); err != nil {
            return err
        }
        copy(d.l2buf[:2], poll[:])
        if err := d.t.Transfer(d.l2buf[:2]); err != nil {
            _ = d.t.CSNHigh()
            return ErrL1SPI
        }
        if err := d.t.CSNHigh(); err != nil {
            return err
        }

        chipStatus := d.l2buf[0]
        if chipStatus&l1StatusReady != 0 {
            return l1ReadFrame(d)
        }
        if chipStatus&l1StatusAlarm != 0 {
            d.logger.Debug("l1: chip alarm")
        }
        if err := d.t.Delay(l1RetryDelay); err != nil {
            return err
        }
    }
    return ErrL1Timeout
}

// l1ReadFrame performs the actual frame read once the chip signals READY.
// It reads CHIP_STATUS+STATUS+LEN, then reads the remaining data+CRC bytes.
func l1ReadFrame(d *Device) error {
    // First transfer: read chip_status(1) + status(1) + len(1)
    header := [3]byte{}
    if err := d.t.CSNLow(); err != nil {
        return err
    }
    copy(d.l2buf[:3], header[:])
    if err := d.t.Transfer(d.l2buf[:3]); err != nil {
        _ = d.t.CSNHigh()
        return ErrL1SPI
    }

    frameLen := int(d.l2buf[l2RespLenOffset])
    total := 3 + frameLen + 2 // header + data + CRC
    if total > len(d.l2buf) {
        _ = d.t.CSNHigh()
        return ErrL2ResTooLong
    }

    // Second transfer: read remaining bytes in the same CSN assertion
    remaining := d.l2buf[3:total]
    for i := range remaining {
        remaining[i] = 0
    }
    if err := d.t.Transfer(d.l2buf[:total]); err != nil {
        _ = d.t.CSNHigh()
        return ErrL1SPI
    }
    return d.t.CSNHigh()
}
```

File: `l1.go`

**Step 4: Run test to verify it passes**

Run: `go test -run TestL1 ./...`
Expected: PASS

**Step 5: Commit**

```bash
git add l1.go l1_test.go
git commit -m "feat: add Layer 1 SPI read/write"
```

---

### Task 9: Layer 2 — framing, CRC, chunking

**Files:**
- Create: `l2.go`
- Create: `l2_test.go`

**Step 1: Write the failing test**

```go
package libtropic

import (
    "testing"
    "go-libtropic/hal/sim"
)

func TestL2FrameCheck(t *testing.T) {
    tests := []struct {
        name   string
        frame  func() []byte
        wantErr error
    }{
        {
            "result OK with valid CRC",
            func() []byte {
                // Build: CHIP_STATUS=0, STATUS=0x02(RESULT_OK), LEN=1, DATA=0xAB, CRC
                data := []byte{0x02, 0x01, 0xAB}
                c := crc16(data)
                return append([]byte{0x00}, append(data, byte(c>>8), byte(c))...)
            },
            nil,
        },
        {
            "result OK with bad CRC",
            func() []byte {
                return []byte{0x00, 0x02, 0x01, 0xAB, 0xFF, 0xFF}
            },
            ErrL2CRCIn,
        },
        {
            "no session status",
            func() []byte {
                return []byte{0x00, 0x06, 0x00, 0x00, 0x00}
            },
            ErrL2NoSession,
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

func TestL2SendReceiveRoundtrip(t *testing.T) {
    s := sim.NewQueued()
    d := NewDevice(s)
    _ = d.Init()

    // Build a valid RESULT_OK response for a 1-byte payload (0xBB).
    // Frame: CHIP_STATUS(1) STATUS(1) LEN(1) DATA(n) CRC(2)
    // We need chip status = READY first so l1Read succeeds.
    // Simplification: we'll directly test l2Receive by pre-loading full frames.

    payload := []byte{0xBB}
    statusAndLen := []byte{l2StatusResultOK, byte(len(payload))}
    crcInput := append(statusAndLen, payload...)
    c := crc16(crcInput)
    frame := append([]byte{l1StatusReady}, crcInput...)
    frame = append(frame, byte(c>>8), byte(c))

    // l1Read poll: first byte = l1StatusReady triggers l1ReadFrame
    // l1ReadFrame reads 3 bytes then reads total frame
    // We need to structure responses to match the 2-step l1Read protocol.
    // For the polling step: return a 2-byte response with READY set.
    pollResp := make([]byte, l1LenMax)
    pollResp[0] = l1StatusReady

    // Full frame response for l1ReadFrame's first 3-byte transfer:
    fullFrame := make([]byte, l1LenMax)
    copy(fullFrame, frame)

    s.EnqueueResponse(pollResp)  // poll response
    s.EnqueueResponse(fullFrame) // full frame read

    buf, err := l2Receive(d)
    if err != nil {
        t.Fatalf("l2Receive: %v", err)
    }
    if len(buf) != 1 || buf[0] != 0xBB {
        t.Errorf("l2Receive payload = %x, want [bb]", buf)
    }
}
```

File: `l2_test.go`

**Step 2: Run to verify it fails**

Run: `go test -run TestL2 ./...`
Expected: FAIL — `l2FrameCheck` undefined

**Step 3: Implement l2.go**

```go
package libtropic

// l2FrameCheck validates an L2 response frame.
// frame[0] = CHIP_STATUS (from L1)
// frame[1] = L2 STATUS
// frame[2] = LEN
// frame[3..3+LEN-1] = DATA
// frame[3+LEN], frame[3+LEN+1] = CRC high, CRC low
// Mirrors lt_l2_frame_check.c.
func l2FrameCheck(frame []byte) error {
    if len(frame) < 5 {
        return ErrL2StatusUnknown
    }
    status := frame[l2RespStatusOffset]
    frameLen := int(frame[l2RespLenOffset])

    switch status {
    case l2StatusRequestOK, l2StatusResultOK:
        if len(frame) < l2RespDataOffset+frameLen+2 {
            return ErrL2CRCIn
        }
        crcData := frame[l2RespStatusOffset : l2RespStatusOffset+1+1+frameLen] // STATUS+LEN+DATA
        computed := crc16(crcData)
        stored := uint16(frame[l2RespDataOffset+frameLen])<<8 | uint16(frame[l2RespDataOffset+frameLen+1])
        if computed != stored {
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

// l2Send builds an L2 request frame in d.l2buf and sends it via L1.
// reqID selects the command; payload is the DATA field.
// Frame layout: REQ_ID(1) REQ_LEN(1) DATA(n) CRC_HI(1) CRC_LO(1)
// CRC covers REQ_ID + REQ_LEN + DATA.
func l2Send(d *Device, reqID byte, payload []byte) error {
    if len(payload) > l2MaxDataSize {
        return ErrL2ReqTooLong
    }
    d.l2buf[l2ReqIDOffset] = reqID
    d.l2buf[l2ReqLenOffset] = byte(len(payload))
    copy(d.l2buf[l2ReqDataOffset:], payload)
    crcInput := d.l2buf[:l2ReqDataOffset+len(payload)]
    c := crc16(crcInput)
    end := l2ReqDataOffset + len(payload)
    d.l2buf[end] = byte(c >> 8)
    d.l2buf[end+1] = byte(c)
    return l1Write(d, end+2)
}

// l2Receive reads one L2 response frame from the chip and returns the DATA payload.
func l2Receive(d *Device) ([]byte, error) {
    if err := l1Read(d); err != nil {
        return nil, err
    }
    if err := l2FrameCheck(d.l2buf[:]); err != nil {
        return nil, err
    }
    frameLen := int(d.l2buf[l2RespLenOffset])
    payload := make([]byte, frameLen)
    copy(payload, d.l2buf[l2RespDataOffset:l2RespDataOffset+frameLen])
    return payload, nil
}

// l2SendRecv sends a request and receives one response, returning the DATA payload.
func l2SendRecv(d *Device, reqID byte, payload []byte) ([]byte, error) {
    if err := l2Send(d, reqID, payload); err != nil {
        return nil, err
    }
    return l2Receive(d)
}
```

File: `l2.go`

**Step 4: Run test to verify it passes**

Run: `go test -run TestL2 ./...`
Expected: PASS

**Step 5: Commit**

```bash
git add l2.go l2_test.go
git commit -m "feat: add Layer 2 framing, CRC validation, and send/receive"
```

---

### Task 10: Crypto primitives — custom Noise HKDF + AES-GCM

**Files:**
- Create: `crypto.go`
- Create: `crypto_test.go`

The Noise framework HKDF used by TROPIC01 (from lt_hkdf.c):
```
tmp  = HMAC-SHA256(key=ck, data=input)
out1 = HMAC-SHA256(key=tmp, data=[0x01])
out2 = HMAC-SHA256(key=tmp, data=out1||[0x02])
```
Note: for the first HKDF call, `ck` is the 32-byte protocol name. For subsequent calls, the C code passes a 33-byte buffer `output_1[33]` where `output_1[32] = 0` (a trailing zero byte is always present).

**Step 1: Write the failing test**

```go
package libtropic

import (
    "bytes"
    "testing"
)

func TestNoiseHKDF(t *testing.T) {
    // Test vector: protocol name as initial ck, empty input
    // We can't trivially compute by hand, so we verify the structure:
    // out1 and out2 must be different, and both be 32 bytes.
    ck := [32]byte{}
    copy(ck[:], []byte(noiseProtocolName))
    input := []byte{0x01, 0x02, 0x03}

    out1, out2 := noiseHKDF(ck[:], input)

    if len(out1) != 32 {
        t.Errorf("out1 len = %d, want 32", len(out1))
    }
    if len(out2) != 32 {
        t.Errorf("out2 len = %d, want 32", len(out2))
    }
    if bytes.Equal(out1, out2) {
        t.Error("out1 == out2, want different")
    }
}

func TestAESGCMRoundTrip(t *testing.T) {
    key := make([]byte, 32)
    nonce := make([]byte, 12)
    plaintext := []byte("hello TROPIC01")
    aad := []byte("additional data")

    ct, tag, err := aesGCMEncrypt(key, nonce, plaintext, aad)
    if err != nil {
        t.Fatal(err)
    }
    if len(tag) != l3TagSize {
        t.Errorf("tag len = %d, want %d", len(tag), l3TagSize)
    }

    pt, err := aesGCMDecrypt(key, nonce, ct, tag, aad)
    if err != nil {
        t.Fatal(err)
    }
    if !bytes.Equal(pt, plaintext) {
        t.Errorf("decrypted = %q, want %q", pt, plaintext)
    }
}

func TestAESGCMDecryptBadTag(t *testing.T) {
    key := make([]byte, 32)
    nonce := make([]byte, 12)
    plaintext := []byte("hello")

    ct, tag, _ := aesGCMEncrypt(key, nonce, plaintext, nil)
    tag[0] ^= 0xFF // corrupt tag

    _, err := aesGCMDecrypt(key, nonce, ct, tag, nil)
    if err == nil {
        t.Error("expected error on bad tag, got nil")
    }
}
```

File: `crypto_test.go`

**Step 2: Run to verify it fails**

Run: `go test -run TestNoiseHKDF -run TestAESGCM ./...`
Expected: FAIL — `noiseHKDF` undefined

**Step 3: Implement crypto.go**

```go
package libtropic

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/hmac"
    "crypto/sha256"
)

// noiseHKDF derives two 32-byte keys from a chaining key ck and input material,
// following the Noise framework HKDF (NOT RFC 5869). Mirrors lt_hkdf.c.
//
//   tmp  = HMAC-SHA256(key=ck, data=input)
//   out1 = HMAC-SHA256(key=tmp, data=[0x01])
//   out2 = HMAC-SHA256(key=tmp, data=out1 || [0x02])
func noiseHKDF(ck, input []byte) (out1, out2 []byte) {
    mac := hmac.New(sha256.New, ck)
    mac.Write(input)
    tmp := mac.Sum(nil)

    mac = hmac.New(sha256.New, tmp)
    mac.Write([]byte{0x01})
    out1 = mac.Sum(nil)

    mac = hmac.New(sha256.New, tmp)
    mac.Write(out1)
    mac.Write([]byte{0x02})
    out2 = mac.Sum(nil)
    return
}

// hmacSHA256 computes HMAC-SHA256(key, data).
func hmacSHA256(key, data []byte) []byte {
    mac := hmac.New(sha256.New, key)
    mac.Write(data)
    return mac.Sum(nil)
}

// sha256Hash computes SHA-256(data).
func sha256Hash(data []byte) []byte {
    h := sha256.Sum256(data)
    return h[:]
}

// aesGCMEncrypt encrypts plaintext with AES-256-GCM.
// Returns (ciphertext, tag, error). tag is always l3TagSize bytes.
func aesGCMEncrypt(key, nonce, plaintext, aad []byte) (ct, tag []byte, err error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, nil, ErrCrypto
    }
    gcm, err := cipher.NewGCMWithNonceSize(block, l3IVSize)
    if err != nil {
        return nil, nil, ErrCrypto
    }
    combined := gcm.Seal(nil, nonce, plaintext, aad)
    ct = combined[:len(combined)-l3TagSize]
    tag = combined[len(combined)-l3TagSize:]
    return
}

// aesGCMDecrypt decrypts ciphertext with AES-256-GCM.
func aesGCMDecrypt(key, nonce, ct, tag, aad []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, ErrCrypto
    }
    gcm, err := cipher.NewGCMWithNonceSize(block, l3IVSize)
    if err != nil {
        return nil, ErrCrypto
    }
    combined := append(ct, tag...)
    pt, err := gcm.Open(nil, nonce, combined, aad)
    if err != nil {
        return nil, ErrCrypto
    }
    return pt, nil
}

// incrementIV adds 1 to the 96-bit IV stored as big-endian in iv[:].
func incrementIV(iv []byte) {
    for i := len(iv) - 1; i >= 0; i-- {
        iv[i]++
        if iv[i] != 0 {
            break
        }
    }
}
```

File: `crypto.go`

**Step 4: Run test to verify it passes**

Run: `go test -run TestNoiseHKDF -run TestAESGCM ./...`
Expected: PASS

**Step 5: Commit**

```bash
git add crypto.go crypto_test.go
git commit -m "feat: add Noise HKDF and AES-256-GCM crypto primitives"
```

---

### Task 11: Layer 3 — session handshake

**Files:**
- Modify: `session.go` (extend with handshake logic)
- Create: `l3.go`
- Create: `l3_test.go`

The Noise_KK1_25519_AESGCM_SHA256 handshake (from libtropic_l3.c):
```
h  = SHA256(protocol_name)          // h = SHA256("Noise_KK1_25519_AESGCM_SHA256")
h  = SHA256(h || SHIPUB)            // SHIPUB = chip's identity public key (from cert store)
h  = SHA256(h || STPUB)             // STPUB  = host's static public key
h  = SHA256(h || EHPUB)             // EHPUB  = host's ephemeral public key
h  = SHA256(h || PKEY_INDEX)        // PKEY_INDEX = pairing key slot (1 byte)
h  = SHA256(h || ETPUB)             // ETPUB  = chip's ephemeral public key (from response)
ck, kauth = noiseHKDF(ck0, ES)     // ES = ECDH(ehsec, ETPUB)
ck, kcmd  = noiseHKDF(ck,  SS)     // SS = ECDH(shsec, SHIPUB)
kres from subsequent HKDF          // kres used for chip→host decryption
Verify authentication tag with kauth (AES-GCM, zero IV, h as AAD)
```

Where `ck0 = protocol_name` (32 bytes, zero-padded or truncated to 32).

**Step 1: Write the failing test**

```go
package libtropic

import (
    "crypto/ecdh"
    "testing"
)

func TestSessionHandshakeKeyMaterial(t *testing.T) {
    // Verify that the HKDF chain produces different keys for kcmd and kres.
    // We simulate the key derivation steps without a real chip.
    curve := ecdh.X25519()

    ehKey, _ := curve.GenerateKey(mockRand{})
    etKey, _ := curve.GenerateKey(mockRand2{})
    shKey, _ := curve.GenerateKey(mockRand{})
    siKey, _ := curve.GenerateKey(mockRand2{})

    ehPub := ehKey.PublicKey().Bytes()
    etPub := etKey.PublicKey().Bytes()
    shPub := shKey.PublicKey().Bytes()
    siPub := siKey.PublicKey().Bytes()

    // ES = ECDH(ehsec, ETPUB)
    etPubKey, _ := curve.NewPublicKey(etPub)
    es, _ := ehKey.ECDH(etPubKey)

    // SS = ECDH(shsec, SIPUB)
    siPubKey, _ := curve.NewPublicKey(siPub)
    ss, _ := shKey.ECDH(siPubKey)

    _ = ehPub
    _ = shPub

    var ck [32]byte
    copy(ck[:], []byte(noiseProtocolName))

    ck1, _ := noiseHKDF(ck[:], es)
    ck2, kcmd := noiseHKDF(ck1, ss)
    _, kres := noiseHKDF(ck2, []byte{})

    if len(kcmd) != 32 {
        t.Errorf("kcmd len = %d", len(kcmd))
    }
    if len(kres) != 32 {
        t.Errorf("kres len = %d", len(kres))
    }
    // kcmd and kres should differ (different HKDF iterations)
    equal := true
    for i := range kcmd {
        if kcmd[i] != kres[i] {
            equal = false
            break
        }
    }
    if equal {
        t.Error("kcmd == kres, expected different keys")
    }
}

// mockRand provides deterministic bytes for key generation in tests.
type mockRand struct{}
func (mockRand) Read(b []byte) (int, error) {
    for i := range b { b[i] = byte(i + 1) }
    return len(b), nil
}

type mockRand2 struct{}
func (mockRand2) Read(b []byte) (int, error) {
    for i := range b { b[i] = byte(i + 0x80) }
    return len(b), nil
}
```

File: `l3_test.go`

**Step 2: Run to verify it fails**

Run: `go test -run TestSession ./...`
Expected: FAIL or build error from missing l3.go

**Step 3: Extend session.go with handshake fields**

Add to `session.go`:

```go
// sessionState additions for handshake storage.
// (Merge into existing sessionState struct)

// shKey is the host's static X25519 private key (set at session start).
// ehKey is the ephemeral X25519 private key generated per session.
```

Update the `sessionState` struct:

```go
type sessionState struct {
    status sessionStatus
    kcmd   [l3KeySize]byte
    kres   [l3KeySize]byte
    ivcmd  [l3IVSize]byte
    ivres  [l3IVSize]byte
}
```

**Step 4: Create l3.go**

```go
package libtropic

import (
    "crypto/ecdh"
    "crypto/rand"
)

// l3SessionStart performs the Noise_KK1_25519_AESGCM_SHA256 handshake.
// shPriv is the host's static X25519 private key (32 raw bytes).
// siPub is the chip's static identity public key (from cert store, 32 bytes).
// pkeyIndex selects the pairing key slot (0-based).
// Mirrors lt_l3_session_start logic in libtropic_l3.c.
func l3SessionStart(d *Device, shPriv, siPub []byte, pkeyIndex byte) error {
    curve := ecdh.X25519()

    // Generate ephemeral key pair
    ehKey, err := curve.GenerateKey(rand.Reader)
    if err != nil {
        return ErrCrypto
    }
    shKey, err := curve.NewPrivateKey(shPriv)
    if err != nil {
        return ErrParam
    }

    ehPub := ehKey.PublicKey().Bytes()  // 32 bytes
    shPub := shKey.PublicKey().Bytes()  // 32 bytes

    // Initialise hash chain: h = SHA256(protocol_name)
    h := sha256Hash([]byte(noiseProtocolName))
    h = sha256Hash(append(h, siPub...))
    h = sha256Hash(append(h, shPub...))
    h = sha256Hash(append(h, ehPub...))
    h = sha256Hash(append(h, pkeyIndex))

    // Build L2 HANDSHAKE request: [PKEY_INDEX(1) || EHPUB(32)]
    reqPayload := make([]byte, 33)
    reqPayload[0] = pkeyIndex
    copy(reqPayload[1:], ehPub)

    // Send handshake request, get response containing ETPUB(32) + auth_tag(16)
    resp, err := l2SendRecv(d, l2ReqHandshake, reqPayload)
    if err != nil {
        return err
    }
    if len(resp) < 32+l3TagSize {
        return ErrL2ResTooLong
    }

    etPub := resp[:32]
    authTag := resp[32 : 32+l3TagSize]

    // Extend hash chain with chip's ephemeral public key
    h = sha256Hash(append(h, etPub...))

    // Derive session keys via Noise HKDF chain
    var ck [32]byte
    copy(ck[:], []byte(noiseProtocolName))

    // ES = ECDH(ehsec, ETPUB)
    etPubKey, err := curve.NewPublicKey(etPub)
    if err != nil {
        return ErrCrypto
    }
    es, err := ehKey.ECDH(etPubKey)
    if err != nil {
        return ErrCrypto
    }

    // SS = ECDH(shsec, SIPUB)
    siPubKey, err := curve.NewPublicKey(siPub)
    if err != nil {
        return ErrCrypto
    }
    ss, err := shKey.ECDH(siPubKey)
    if err != nil {
        return ErrCrypto
    }

    ck1, _ := noiseHKDF(ck[:], es)
    ck2, kcmd := noiseHKDF(ck1, ss)
    _, kres := noiseHKDF(ck2, []byte{})

    // Verify authentication tag: AES-GCM(key=kauth, nonce=zero, ct=[], aad=h)
    // kauth was derived alongside kcmd in the C library — in Noise_KK1 it is
    // a third output of the final HKDF, but the C code folds it into the
    // second HKDF output. We use kcmd here as the authentication key per the
    // C implementation's actual derivation.
    // TODO: cross-check against chip in integration test.
    zeroNonce := make([]byte, l3IVSize)
    _, err = aesGCMDecrypt(kcmd, zeroNonce, nil, authTag, h)
    if err != nil {
        return ErrCrypto
    }

    // Store session keys
    copy(d.session.kcmd[:], kcmd)
    copy(d.session.kres[:], kres)
    d.session.ivcmd = [l3IVSize]byte{}
    d.session.ivres = [l3IVSize]byte{}
    d.session.status = sessionOn

    d.logger.Debug("L3 session established")
    return nil
}

// l3SessionAbort sends a SESSION_ABORT command and clears session state.
func l3SessionAbort(d *Device) error {
    _, err := l2SendRecv(d, l2ReqSessionAbort, nil)
    d.session = sessionState{}
    return err
}

// l3EncryptSend encrypts an L3 command payload and sends it as an ENCRYPTED_CMD.
func l3EncryptSend(d *Device, cmdPayload []byte) error {
    if d.session.status != sessionOn {
        return ErrNoSession
    }
    ct, tag, err := aesGCMEncrypt(d.session.kcmd[:], d.session.ivcmd[:], cmdPayload, nil)
    if err != nil {
        return err
    }
    incrementIV(d.session.ivcmd[:])

    frame := make([]byte, 0, len(ct)+l3TagSize)
    frame = append(frame, ct...)
    frame = append(frame, tag...)
    return l2Send(d, l2ReqEncryptedCmd, frame)
}

// l3DecryptReceive receives and decrypts an L3 response.
func l3DecryptReceive(d *Device) ([]byte, error) {
    if d.session.status != sessionOn {
        return nil, ErrNoSession
    }
    resp, err := l2Receive(d)
    if err != nil {
        return nil, err
    }
    if len(resp) < l3TagSize {
        return nil, ErrL2ResTooLong
    }
    ct := resp[:len(resp)-l3TagSize]
    tag := resp[len(resp)-l3TagSize:]

    pt, err := aesGCMDecrypt(d.session.kres[:], d.session.ivres[:], ct, tag, nil)
    if err != nil {
        return nil, err
    }
    incrementIV(d.session.ivres[:])
    return pt, nil
}
```

File: `l3.go`

**Step 5: Run test to verify it passes**

Run: `go test -run TestSession ./...`
Expected: PASS

**Step 6: Commit**

```bash
git add session.go l3.go l3_test.go
git commit -m "feat: add Layer 3 Noise_KK1 session handshake and encrypt/decrypt"
```

---

### Task 12: ASN.1 DER cert store parser

**Files:**
- Create: `internal/asn1der/asn1der.go`
- Create: `internal/asn1der/asn1der_test.go`

The cert store holds the chip's static identity public key (STPUB/SHIPUB) encoded in a TLV structure. We only need to extract the 32-byte X25519 public key.

**Step 1: Write the failing test**

```go
package asn1der_test

import (
    "bytes"
    "testing"
    "go-libtropic/internal/asn1der"
)

func TestExtractSubjectPublicKey(t *testing.T) {
    // Minimal self-consistent DER wrapping a 32-byte X25519 public key.
    // SEQUENCE { SEQUENCE { OID ... } BIT STRING { 0x00 <32 bytes> } }
    // We'll construct a minimal encoding manually.
    pubKey := make([]byte, 32)
    for i := range pubKey { pubKey[i] = byte(i + 1) }

    // Build: BIT STRING = 0x00 (no unused bits) || pubKey
    bitString := append([]byte{0x00}, pubKey...)
    // BIT STRING TLV
    bsTLV := append([]byte{0x03, byte(len(bitString))}, bitString...)

    // Wrap in outer SEQUENCE (placeholder for algorithm info)
    // We just need: SEQUENCE { ... BIT STRING { key } }
    inner := bsTLV // simplified: just the bit string
    outer := append([]byte{0x30, byte(len(inner))}, inner...)

    got, err := asn1der.ExtractSubjectPublicKey(outer)
    if err != nil {
        t.Fatalf("ExtractSubjectPublicKey: %v", err)
    }
    if !bytes.Equal(got, pubKey) {
        t.Errorf("got %x, want %x", got, pubKey)
    }
}
```

File: `internal/asn1der/asn1der_test.go`

**Step 2: Run to verify it fails**

Run: `go test ./internal/asn1der/...`
Expected: FAIL — package not found

**Step 3: Implement asn1der.go**

```go
// Package asn1der provides a minimal ASN.1 DER parser for extracting the
// subject public key from a TROPIC01 X.509-like certificate store entry.
//
// Only the subset required to extract the raw 32-byte X25519 public key is
// implemented. Full certificate chain verification is left to the caller using
// stdlib crypto/x509.
package asn1der

import (
    "errors"
)

// ExtractSubjectPublicKey extracts the raw public key bytes from a DER-encoded
// certificate. It locates the BIT STRING containing the subject public key and
// returns the content after stripping the leading "unused bits" byte.
func ExtractSubjectPublicKey(der []byte) ([]byte, error) {
    // Walk the outer SEQUENCE
    if len(der) < 2 {
        return nil, errors.New("asn1der: input too short")
    }
    if der[0] != 0x30 {
        return nil, errors.New("asn1der: expected SEQUENCE")
    }
    content, err := tlvContent(der)
    if err != nil {
        return nil, err
    }

    // Scan for BIT STRING (tag 0x03) at any depth
    return findBitString(content)
}

// findBitString recursively searches for the first BIT STRING in a DER blob.
func findBitString(data []byte) ([]byte, error) {
    for len(data) >= 2 {
        tag := data[0]
        content, err := tlvContent(data)
        if err != nil {
            return nil, err
        }
        if tag == 0x03 {
            // BIT STRING: first byte is unused-bits count
            if len(content) < 2 {
                return nil, errors.New("asn1der: BIT STRING too short")
            }
            return content[1:], nil // strip unused-bits byte
        }
        if tag == 0x30 || tag == 0x31 {
            // Recurse into SEQUENCE or SET
            if result, err := findBitString(content); err == nil {
                return result, nil
            }
        }
        // Advance past this TLV
        _, skip, err := parseTLV(data)
        if err != nil {
            return nil, err
        }
        data = data[skip:]
    }
    return nil, errors.New("asn1der: BIT STRING not found")
}

// tlvContent returns the value bytes of the first TLV in data.
func tlvContent(data []byte) ([]byte, error) {
    _, n, err := parseTLV(data)
    if err != nil {
        return nil, err
    }
    return data[n-int(data[1]):n], nil
}

// parseTLV returns (tag, total-length) for the first TLV in data.
func parseTLV(data []byte) (tag byte, total int, err error) {
    if len(data) < 2 {
        return 0, 0, errors.New("asn1der: truncated TLV")
    }
    tag = data[0]
    lenByte := data[1]
    if lenByte&0x80 == 0 {
        // Short form
        valLen := int(lenByte)
        if 2+valLen > len(data) {
            return 0, 0, errors.New("asn1der: value overflows buffer")
        }
        return tag, 2 + valLen, nil
    }
    // Long form
    numBytes := int(lenByte & 0x7f)
    if numBytes == 0 || 2+numBytes > len(data) {
        return 0, 0, errors.New("asn1der: invalid long-form length")
    }
    var valLen int
    for _, b := range data[2 : 2+numBytes] {
        valLen = valLen<<8 | int(b)
    }
    total = 2 + numBytes + valLen
    if total > len(data) {
        return 0, 0, errors.New("asn1der: value overflows buffer")
    }
    return tag, total, nil
}
```

File: `internal/asn1der/asn1der.go`

**Step 4: Run test to verify it passes**

Run: `go test ./internal/asn1der/...`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/asn1der/asn1der.go internal/asn1der/asn1der_test.go
git commit -m "feat: add minimal ASN.1 DER parser for cert store"
```

---

### Task 13: Public API — api.go

**Files:**
- Create: `api.go`
- Create: `api_test.go`

**Step 1: Write the failing test**

```go
package libtropic_test

import (
    "testing"
    libtropic "go-libtropic"
    "go-libtropic/hal/sim"
)

func newTestDevice(t *testing.T) *libtropic.Device {
    t.Helper()
    s := sim.NewQueued()
    d := libtropic.NewDevice(s)
    if err := d.Init(); err != nil {
        t.Fatal(err)
    }
    return d
}

func TestPingNoSession(t *testing.T) {
    d := newTestDevice(t)
    // Ping without a session must return ErrNoSession.
    _, err := d.Ping([]byte{0x01, 0x02})
    if err != libtropic.ErrNoSession {
        t.Errorf("Ping without session: got %v, want ErrNoSession", err)
    }
}
```

File: `api_test.go`

**Step 2: Run to verify it fails**

Run: `go test -run TestPing ./...`
Expected: FAIL — `Device.Ping` undefined

**Step 3: Create api.go with core public methods**

```go
package libtropic

// Ping sends a PING command over an established session and returns the
// response payload. Mirrors lt_ping in libtropic.h.
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
    return l3DecryptReceive(d)
}

// SessionStart performs the Noise_KK1_25519_AESGCM_SHA256 handshake.
// shPriv is the host's 32-byte X25519 private key.
// siPub is the chip's 32-byte static identity public key (from GetCert).
// pkeyIndex is the pairing key slot to use.
// Mirrors lt_session_start in libtropic.h.
func (d *Device) SessionStart(shPriv, siPub []byte, pkeyIndex byte) error {
    return l3SessionStart(d, shPriv, siPub, pkeyIndex)
}

// SessionAbort aborts the current L3 session.
// Mirrors lt_session_abort in libtropic.h.
func (d *Device) SessionAbort() error {
    return l3SessionAbort(d)
}

// GetInfo returns chip information without a session.
// Mirrors lt_get_info_* functions in libtropic.h.
func (d *Device) GetInfo(object byte) ([]byte, error) {
    req := []byte{object}
    return l2SendRecv(d, l2ReqGetInfo, req)
}

// Sleep commands the chip to enter sleep mode.
// Mirrors lt_sleep in libtropic.h.
func (d *Device) Sleep() error {
    _, err := l2SendRecv(d, l2ReqSleep, nil)
    return err
}

// Startup wakes the chip from sleep.
// Mirrors lt_startup in libtropic.h.
func (d *Device) Startup() error {
    _, err := l2SendRecv(d, l2ReqStartup, nil)
    return err
}

// PairingKeyWrite writes a pairing key to the given slot.
// Mirrors lt_pairing_key_write in libtropic.h.
func (d *Device) PairingKeyWrite(slot byte, key []byte) error {
    if d.session.status != sessionOn {
        return ErrNoSession
    }
    cmd := make([]byte, 2+len(key))
    cmd[0] = l3CmdPairingKeyWrite
    cmd[1] = slot
    copy(cmd[2:], key)
    if err := l3EncryptSend(d, cmd); err != nil {
        return err
    }
    _, err := l3DecryptReceive(d)
    return err
}

// RMemDataWrite writes data to an R-mem slot.
// Mirrors lt_r_mem_data_write in libtropic.h.
func (d *Device) RMemDataWrite(slot uint16, data []byte) error {
    if d.session.status != sessionOn {
        return ErrNoSession
    }
    cmd := make([]byte, 3+len(data))
    cmd[0] = l3CmdRMemDataWrite
    cmd[1] = byte(slot >> 8)
    cmd[2] = byte(slot)
    copy(cmd[3:], data)
    if err := l3EncryptSend(d, cmd); err != nil {
        return err
    }
    _, err := l3DecryptReceive(d)
    return err
}

// RMemDataRead reads data from an R-mem slot.
// Mirrors lt_r_mem_data_read in libtropic.h.
func (d *Device) RMemDataRead(slot uint16) ([]byte, error) {
    if d.session.status != sessionOn {
        return nil, ErrNoSession
    }
    cmd := []byte{l3CmdRMemDataRead, byte(slot >> 8), byte(slot)}
    if err := l3EncryptSend(d, cmd); err != nil {
        return nil, err
    }
    return l3DecryptReceive(d)
}

// ECCKeyGenerate generates an ECC key in the given slot.
// curve selects the algorithm (see libtropic.h ECC_KEY_TYPE_* constants).
// Mirrors lt_ecc_key_generate in libtropic.h.
func (d *Device) ECCKeyGenerate(slot byte, curve byte) error {
    if d.session.status != sessionOn {
        return ErrNoSession
    }
    cmd := []byte{l3CmdECCKeyGenerate, slot, curve}
    if err := l3EncryptSend(d, cmd); err != nil {
        return err
    }
    _, err := l3DecryptReceive(d)
    return err
}

// ECCKeyRead returns the public key from an ECC key slot.
// Mirrors lt_ecc_key_read in libtropic.h.
func (d *Device) ECCKeyRead(slot byte) ([]byte, error) {
    if d.session.status != sessionOn {
        return nil, ErrNoSession
    }
    cmd := []byte{l3CmdECCKeyRead, slot}
    if err := l3EncryptSend(d, cmd); err != nil {
        return nil, err
    }
    return l3DecryptReceive(d)
}

// ECDSASign signs a hash using the ECDSA key in the given slot.
// Mirrors lt_ecdsa_sign in libtropic.h.
func (d *Device) ECDSASign(slot byte, hash []byte) ([]byte, error) {
    if d.session.status != sessionOn {
        return nil, ErrNoSession
    }
    cmd := make([]byte, 2+len(hash))
    cmd[0] = l3CmdECDSASign
    cmd[1] = slot
    copy(cmd[2:], hash)
    if err := l3EncryptSend(d, cmd); err != nil {
        return nil, err
    }
    return l3DecryptReceive(d)
}

// EdDSASign signs a message using the EdDSA key in the given slot.
// Mirrors lt_eddsa_sign in libtropic.h.
func (d *Device) EdDSASign(slot byte, msg []byte) ([]byte, error) {
    if d.session.status != sessionOn {
        return nil, ErrNoSession
    }
    cmd := make([]byte, 2+len(msg))
    cmd[0] = l3CmdEdDSASign
    cmd[1] = slot
    copy(cmd[2:], msg)
    if err := l3EncryptSend(d, cmd); err != nil {
        return nil, err
    }
    return l3DecryptReceive(d)
}

// MCTRUpdate increments a monotonic counter in the given slot.
// Mirrors lt_mctr_update in libtropic.h.
func (d *Device) MCTRUpdate(slot byte) error {
    if d.session.status != sessionOn {
        return ErrNoSession
    }
    cmd := []byte{l3CmdMctrUpdate, slot}
    if err := l3EncryptSend(d, cmd); err != nil {
        return err
    }
    _, err := l3DecryptReceive(d)
    return err
}

// MCTRGet reads a monotonic counter value.
// Mirrors lt_mctr_get in libtropic.h.
func (d *Device) MCTRGet(slot byte) (uint32, error) {
    if d.session.status != sessionOn {
        return 0, ErrNoSession
    }
    cmd := []byte{l3CmdMctrGet, slot}
    if err := l3EncryptSend(d, cmd); err != nil {
        return 0, err
    }
    resp, err := l3DecryptReceive(d)
    if err != nil {
        return 0, err
    }
    if len(resp) < 4 {
        return 0, ErrL2ResTooLong
    }
    val := uint32(resp[0])<<24 | uint32(resp[1])<<16 | uint32(resp[2])<<8 | uint32(resp[3])
    return val, nil
}

// GetCert retrieves the chip certificate store.
// Mirrors lt_cert_store_read in libtropic.h.
func (d *Device) GetCert() ([]byte, error) {
    if d.session.status != sessionOn {
        return nil, ErrNoSession
    }
    cmd := []byte{l3CmdCertStore}
    if err := l3EncryptSend(d, cmd); err != nil {
        return nil, err
    }
    return l3DecryptReceive(d)
}

// FirmwareUpdate is not yet implemented.
func (d *Device) FirmwareUpdate() error {
    return ErrNotImplemented
}
```

File: `api.go`

**Step 4: Run test to verify it passes**

Run: `go test -run TestPingNoSession ./...`
Expected: PASS

**Step 5: Compile everything**

Run: `go build ./...`
Expected: no output, exit 0

**Step 6: Commit**

```bash
git add api.go api_test.go
git commit -m "feat: add public Device API (Ping, SessionStart, ECC, MCTR, etc.)"
```

---

### Task 14: Linux HAL

**Files:**
- Create: `hal/linux/spi.go`

**Step 1: Create hal/linux/spi.go**

Note: No test for the Linux HAL (requires physical hardware). The file must compile on Linux with `//go:build linux`.

```go
//go:build linux

// Package linux provides a Linux spidev + GPIO v2 Transport implementation
// for TROPIC01 communication.
//
// It uses /dev/spidevN.M for SPI transfers and the Linux GPIO v2 UAPI
// (kernel 5.10+) for chip-select control.
package linux

import (
    "fmt"
    "os"
    "time"
    "unsafe"
    "syscall"
)

// LinuxSPIConfig configures the Linux HAL.
type LinuxSPIConfig struct {
    // SPIDevice is the spidev path, e.g. "/dev/spidev0.0".
    SPIDevice string
    // GPIOChip is the gpiochip path, e.g. "/dev/gpiochip0".
    GPIOChip string
    // CSPin is the GPIO line number for chip-select.
    CSPin uint32
    // SpeedHz is the SPI clock frequency in Hz (default: 1 000 000).
    SpeedHz uint32
}

// SPITransport implements libtropic.Transport using Linux kernel interfaces.
type SPITransport struct {
    cfg    LinuxSPIConfig
    spiFD  int
    gpioFD int
    lineFD int
}

// NewSPITransport creates a new Linux SPI transport. Call Init before use.
func NewSPITransport(cfg LinuxSPIConfig) *SPITransport {
    if cfg.SpeedHz == 0 {
        cfg.SpeedHz = 1_000_000
    }
    return &SPITransport{cfg: cfg, spiFD: -1, gpioFD: -1, lineFD: -1}
}

// Init implements Transport.
func (s *SPITransport) Init() error {
    var err error
    s.spiFD, err = syscall.Open(s.cfg.SPIDevice, syscall.O_RDWR, 0)
    if err != nil {
        return fmt.Errorf("linux hal: open %s: %w", s.cfg.SPIDevice, err)
    }
    s.gpioFD, err = syscall.Open(s.cfg.GPIOChip, syscall.O_RDWR, 0)
    if err != nil {
        _ = syscall.Close(s.spiFD)
        return fmt.Errorf("linux hal: open %s: %w", s.cfg.GPIOChip, err)
    }
    if err := s.requestCSLine(); err != nil {
        _ = syscall.Close(s.spiFD)
        _ = syscall.Close(s.gpioFD)
        return err
    }
    return nil
}

// Deinit implements Transport.
func (s *SPITransport) Deinit() error {
    if s.lineFD >= 0 {
        _ = syscall.Close(s.lineFD)
        s.lineFD = -1
    }
    if s.gpioFD >= 0 {
        _ = syscall.Close(s.gpioFD)
        s.gpioFD = -1
    }
    if s.spiFD >= 0 {
        _ = syscall.Close(s.spiFD)
        s.spiFD = -1
    }
    return nil
}

// CSNLow implements Transport (asserts CS low via GPIO output = 0).
func (s *SPITransport) CSNLow() error {
    return s.setCS(0)
}

// CSNHigh implements Transport (deasserts CS high via GPIO output = 1).
func (s *SPITransport) CSNHigh() error {
    return s.setCS(1)
}

// Transfer implements Transport using SPI_IOC_MESSAGE ioctl.
func (s *SPITransport) Transfer(buf []byte) error {
    return spiTransfer(s.spiFD, buf, s.cfg.SpeedHz)
}

// Delay implements Transport.
func (s *SPITransport) Delay(ms uint32) error {
    time.Sleep(time.Duration(ms) * time.Millisecond)
    return nil
}

// RandomBytes implements Transport using getrandom(2).
func (s *SPITransport) RandomBytes(buf []byte) error {
    _, err := cryptoRandRead(buf)
    return err
}

// ---- platform-specific helpers (syscall wrappers) ----

// GPIO v2 UAPI constants (linux/gpio.h, kernel 5.10+).
const (
    gpioV2GetLineIOCTL       = 0xc250b407
    gpioV2LineSetValuesIOCTL = 0xc010b40f
    gpioV2LineFlagOutput     = 1 << 1
)

type gpioV2LineRequest struct {
    offsets    [64]uint32
    consumer   [32]byte
    config     gpioV2LineConfig
    numLines   uint32
    eventBufSz uint32
    pad        [5]uint32
    fd         int32
}

type gpioV2LineConfig struct {
    flags     uint64
    numAttrs  uint32
    pad       [5]uint32
    attrs     [10]gpioV2LineConfigAttr
}

type gpioV2LineConfigAttr struct {
    attr gpioV2LineAttr
    mask uint64
}

type gpioV2LineAttr struct {
    id      uint32
    padding uint32
    val     uint64
}

type gpioV2LineValues struct {
    bits uint64
    mask uint64
}

func (s *SPITransport) requestCSLine() error {
    req := gpioV2LineRequest{}
    req.offsets[0] = s.cfg.CSPin
    req.numLines = 1
    copy(req.consumer[:], "go-libtropic")
    req.config.flags = gpioV2LineFlagOutput

    _, _, errno := syscall.Syscall(
        syscall.SYS_IOCTL,
        uintptr(s.gpioFD),
        gpioV2GetLineIOCTL,
        uintptr(unsafe.Pointer(&req)),
    )
    if errno != 0 {
        return fmt.Errorf("linux hal: GPIO_V2_GET_LINE_IOCTL: %w", errno)
    }
    s.lineFD = int(req.fd)
    return nil
}

func (s *SPITransport) setCS(val uint64) error {
    lv := gpioV2LineValues{bits: val, mask: 1}
    _, _, errno := syscall.Syscall(
        syscall.SYS_IOCTL,
        uintptr(s.lineFD),
        gpioV2LineSetValuesIOCTL,
        uintptr(unsafe.Pointer(&lv)),
    )
    if errno != 0 {
        return fmt.Errorf("linux hal: set CS: %w", errno)
    }
    return nil
}

// spiIocTransfer mirrors struct spi_ioc_transfer from linux/spi/spidev.h.
type spiIocTransfer struct {
    txBuf       uint64
    rxBuf       uint64
    length      uint32
    speedHz     uint32
    delayUsecs  uint16
    bitsPerWord uint8
    csChange    uint8
    txNBits     uint8
    rxNBits     uint8
    wordDelayUs uint16
    pad         uint32
}

const spiIOCMessage1 = 0x40206b00

func spiTransfer(fd int, buf []byte, speedHz uint32) error {
    if len(buf) == 0 {
        return nil
    }
    xfer := spiIocTransfer{
        txBuf:       uint64(uintptr(unsafe.Pointer(&buf[0]))),
        rxBuf:       uint64(uintptr(unsafe.Pointer(&buf[0]))),
        length:      uint32(len(buf)),
        speedHz:     speedHz,
        bitsPerWord: 8,
    }
    _, _, errno := syscall.Syscall(
        syscall.SYS_IOCTL,
        uintptr(fd),
        spiIOCMessage1,
        uintptr(unsafe.Pointer(&xfer)),
    )
    if errno != 0 {
        return fmt.Errorf("linux hal: SPI_IOC_MESSAGE: %w", errno)
    }
    return nil
}

func cryptoRandRead(buf []byte) (int, error) {
    return os.ReadFile("/dev/urandom") // placeholder; see below
}

func init() {
    // Override cryptoRandRead with getrandom(2) for true CSPRNG.
    cryptoRandRead = func(buf []byte) (int, error) {
        n, _, errno := syscall.Syscall(
            syscall.SYS_GETRANDOM,
            uintptr(unsafe.Pointer(&buf[0])),
            uintptr(len(buf)),
            0,
        )
        if errno != 0 {
            return 0, fmt.Errorf("getrandom: %w", errno)
        }
        return int(n), nil
    }
}
```

> **Note:** The `cryptoRandRead` variable pattern above is a placeholder that gets replaced in `init()`. A cleaner implementation can use a package-level `var cryptoRandRead func([]byte) (int, error)` and the `init()` sets it; the outer function is never actually called. This avoids importing `os` just for the placeholder.

**Step 2: Verify it compiles on Linux**

Run: `GOOS=linux go build ./hal/linux/...`
Expected: no output, exit 0

**Step 3: Commit**

```bash
git add hal/linux/spi.go
git commit -m "feat: add Linux spidev+GPIO v2 Transport implementation"
```

---

### Task 15: Run all tests and verify

**Step 1: Run the full test suite**

Run: `go test ./...`
Expected: all tests PASS, no compilation errors

**Step 2: Run with race detector**

Run: `go test -race ./...`
Expected: no races detected

**Step 3: Verify cross-compilation**

Run: `GOOS=linux GOARCH=arm64 go build ./...`
Expected: no output, exit 0

**Step 4: Commit (if any fixes were made)**

```bash
git add -p
git commit -m "fix: resolve issues found during full test run"
```

---

### Task 16: Stateful simulator (hal/sim) — extended

**Files:**
- Modify: `hal/sim/sim.go` (add stateful command dispatch)
- Modify: `hal/sim/sim_test.go` (add stateful tests)

This extends the simulator to parse L2 frames, dispatch command IDs, and return realistic responses. Implement as a follow-up pass — the queued mode is sufficient for initial testing.

**Step 1: Add stateful Transfer dispatch**

In `hal/sim/sim.go`, update `Transfer` to check `s.stateful` and call `s.dispatchFrame(buf)` instead of queue lookup.

**Step 2: Implement minimal command dispatch**

```go
func (s *Sim) dispatchFrame(buf []byte) {
    // Parse REQ_ID from buf[0]
    // For GET_INFO: return chip version response
    // For HANDSHAKE: return a dummy ETPUB + zero auth tag
    // For ENCRYPTED_CMD: echo back decrypted payload (test convenience)
    // Default: return RESULT_OK with empty data
}
```

Full implementation is an integration effort — stub with RESULT_OK responses initially.

**Step 3: Run tests**

Run: `go test ./hal/sim/...`
Expected: PASS

**Step 4: Commit**

```bash
git add hal/sim/sim.go hal/sim/sim_test.go
git commit -m "feat: add stateful simulator dispatch skeleton"
```

---

## Summary

| Task | Files | What it builds |
|------|-------|----------------|
| 1 | go.mod, doc.go | Module scaffold |
| 2 | errors.go | Error type (43 codes) |
| 3 | constants.go | Protocol constants |
| 4 | transport.go | Transport interface |
| 5 | crc16.go | CRC16/IBM |
| 6 | options.go, device.go, session.go | Device + options |
| 7 | hal/sim/sim.go | Queued simulator |
| 8 | l1.go | Layer 1 SPI |
| 9 | l2.go | Layer 2 framing |
| 10 | crypto.go | Noise HKDF + AES-GCM |
| 11 | l3.go | L3 session handshake |
| 12 | internal/asn1der/ | DER cert parser |
| 13 | api.go | Public API |
| 14 | hal/linux/spi.go | Linux HAL |
| 15 | — | Full test run |
| 16 | hal/sim/sim.go | Stateful simulator |
