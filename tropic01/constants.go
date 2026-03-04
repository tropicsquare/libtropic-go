package tropic01

// L1 timing and retry constants (mirrors lt_l1.h).
const (
	l1StatusReady   = 0x01 // chip ready for command
	l1StatusAlarm   = 0x02 // chip alarm condition
	l1StatusStartup = 0x04 // chip in startup

	l1MaxRetries = 50 // max status-poll iterations
	l1RetryDelay = 25 // ms between retries

	l1TimeoutMSDefault  = 70  // default command timeout (ms)
	l1TimeoutMSInit     = 5   // startup poll timeout (ms)
	l1TimeoutMSExtended = 150 // extended operation timeout (ms)
)

// L2 frame layout constants (mirrors libtropic_common.h).
const (
	// Request frame offsets
	l2ReqIDOffset   = 0 // REQ_ID byte
	l2ReqLenOffset  = 1 // REQ_LEN byte
	l2ReqDataOffset = 2 // DATA start

	// Response frame offsets
	l2RespChipStatusOffset = 0 // CHIP_STATUS byte (from L1)
	l2RespStatusOffset     = 1 // STATUS byte
	l2RespLenOffset        = 2 // RSP_LEN byte
	l2RespDataOffset       = 3 // DATA start

	l2MaxDataSize = 252 // max data bytes per L2 chunk
	l2MaxLoops    = 42  // max receive iterations

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
	l2StatusRequestOK    = 0x01
	l2StatusResultOK     = 0x02
	l2StatusRequestCont  = 0x03
	l2StatusResultCont   = 0x04
	l2StatusHSKErr       = 0x05
	l2StatusNoSession    = 0x06
	l2StatusTagErr       = 0x07
	l2StatusCRCErr       = 0x08
	l2StatusGenErr       = 0x09
	l2StatusNoResp       = 0x0a
	l2StatusUnknownErr   = 0x0b
	l2StatusRespDisabled = 0x0c
)

// L3 packet constants.
const (
	l3PacketMaxSize = 4113 // TR01_L3_PACKET_MAX_SIZE

	// L3 command IDs (mirrors lt_l3_api_structs.h)
	l3CmdPing                 = 0x01
	l3CmdPairingKeyWrite      = 0x10
	l3CmdPairingKeyRead       = 0x11
	l3CmdPairingKeyInvalidate = 0x12
	l3CmdRConfigWrite         = 0x20
	l3CmdRConfigRead          = 0x21
	l3CmdRConfigErase         = 0x22
	l3CmdIConfigWrite         = 0x30
	l3CmdIConfigRead          = 0x31
	l3CmdRMemDataWrite        = 0x40
	l3CmdRMemDataRead         = 0x41
	l3CmdRMemDataErase        = 0x42
	l3CmdRandomValueGet       = 0x50
	l3CmdECCKeyGenerate       = 0x60
	l3CmdECCKeyStore          = 0x61
	l3CmdECCKeyRead           = 0x62
	l3CmdECCKeyErase          = 0x63
	l3CmdECDSASign            = 0x70
	l3CmdEdDSASign            = 0x71
	l3CmdMctrInit             = 0x80
	l3CmdMctrUpdate           = 0x81
	l3CmdMctrGet              = 0x82
	l3CmdMacAndDestroy        = 0x90

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

// Public protocol constants matching Rust tropic01 exports.
const (
	ECCSlotMax           = 31
	RMemDataSlotMax      = 511
	PairingKeySlotMax    = 3
	MacAndDestroySlotMax = 127
	MCounterValueMax     = 0xFFFFFFFE

	EccCurveP256    byte = 0x01
	EccCurveEd25519 byte = 0x02

	SleepReqSleep     byte = 0x00
	SleepReqDeepSleep byte = 0x01

	StartupReqReboot            byte = 0x00
	StartupReqMaintenanceReboot byte = 0x01

	BankIDRiscvFw1 byte = 0x00
	BankIDRiscvFw2 byte = 0x01
	BankIDSpectFw1 byte = 0x02
	BankIDSpectFw2 byte = 0x03
)
