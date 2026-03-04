package tropic01

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
