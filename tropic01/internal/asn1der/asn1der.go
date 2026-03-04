// Package asn1der provides a minimal ASN.1 DER parser for extracting the
// subject public key from a TROPIC01 certificate store entry.
//
// Only the subset required to extract the raw 32-byte X25519 public key is
// implemented. Full certificate chain verification is left to the caller
// using stdlib crypto/x509.
package asn1der

import "errors"

// ExtractSubjectPublicKey extracts the raw public key bytes from a DER-encoded
// certificate. It searches for the first BIT STRING and returns its content
// after stripping the leading unused-bits byte.
func ExtractSubjectPublicKey(der []byte) ([]byte, error) {
	if len(der) < 2 {
		return nil, errors.New("asn1der: input too short")
	}
	if der[0] != 0x30 {
		return nil, errors.New("asn1der: expected SEQUENCE at top level")
	}
	content, err := tlvContent(der)
	if err != nil {
		return nil, err
	}
	return findBitString(content)
}

// findBitString recursively searches for the first BIT STRING (tag 0x03)
// in a DER-encoded blob, descending into SEQUENCE and SET containers.
func findBitString(data []byte) ([]byte, error) {
	for len(data) >= 2 {
		tag := data[0]
		content, err := tlvContent(data)
		if err != nil {
			return nil, err
		}
		if tag == 0x03 {
			if len(content) < 2 {
				return nil, errors.New("asn1der: BIT STRING too short")
			}
			return content[1:], nil // strip unused-bits byte
		}
		if tag == 0x30 || tag == 0x31 {
			if result, err := findBitString(content); err == nil {
				return result, nil
			}
		}
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
	_, total, err := parseTLV(data)
	if err != nil {
		return nil, err
	}
	// value starts after tag(1) + length field
	lenByte := data[1]
	headerLen := 2
	if lenByte&0x80 != 0 {
		headerLen = 2 + int(lenByte&0x7f)
	}
	return data[headerLen:total], nil
}

// parseTLV returns (tag, total-TLV-length) for the first TLV in data.
// total includes the tag and length bytes themselves.
func parseTLV(data []byte) (tag byte, total int, err error) {
	if len(data) < 2 {
		return 0, 0, errors.New("asn1der: truncated TLV")
	}
	tag = data[0]
	lenByte := data[1]
	if lenByte&0x80 == 0 {
		valLen := int(lenByte)
		if 2+valLen > len(data) {
			return 0, 0, errors.New("asn1der: value overflows buffer")
		}
		return tag, 2 + valLen, nil
	}
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
