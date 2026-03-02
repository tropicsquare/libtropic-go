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
