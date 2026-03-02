package libtropic

import "fmt"

// Error represents a TROPIC01 return code. Numeric values mirror C lt_ret_t.
type Error int

const (
	ErrOK               Error = 0
	ErrFail             Error = 1
	ErrNoSession        Error = 2
	ErrParam            Error = 3
	ErrCrypto           Error = 4
	ErrAppFWTooNew      Error = 5
	ErrAppFWTooOld      Error = 6
	ErrL1L3TooLong      Error = 7
	ErrL1Timeout        Error = 8
	ErrL1SPI            Error = 9
	ErrL2ReqCont        Error = 10
	ErrL2ResCont        Error = 11
	ErrL2ReqTooLong     Error = 12
	ErrL2ResTooLong     Error = 13
	ErrL2CRCIn          Error = 14
	ErrL2HSKErr         Error = 15
	ErrL2NoSession      Error = 16
	ErrL2TagErr         Error = 17
	ErrL2CRCErr         Error = 18
	ErrL2GenErr         Error = 19
	ErrL2NoResp         Error = 20
	ErrL2UnknownReq     Error = 21
	ErrL2RespDisabled   Error = 22
	ErrL2StatusUnknown  Error = 23
	ErrL3Unauthorized   Error = 24
	ErrL3ParamErr       Error = 25
	ErrL3InfoErr        Error = 26
	ErrL3RandomBytesErr Error = 27
	ErrL3KeyErr         Error = 28
	ErrL3EXTDataErr     Error = 29
	ErrL3DataLenErr     Error = 30
	ErrL3GRIDErr        Error = 31
	ErrL3MCTRLViolation Error = 32
	ErrL3NoData         Error = 33
	ErrL3KeyUsage       Error = 34
	ErrL3AppBusy        Error = 35
	ErrL3IntegrityErr   Error = 36
	ErrL3Rollback       Error = 37
	ErrL3HibernateErr   Error = 38
	ErrL3SetupErr       Error = 39
	ErrL3SlotExpired    Error = 40
	ErrL3Undefined      Error = 41
	ErrNotImplemented   Error = 42
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
