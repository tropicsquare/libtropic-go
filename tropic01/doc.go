// Package tropic01 is a pure-Go port of the TROPIC01 secure element host driver.
//
// Protocol reference: https://github.com/tropicsquare/libtropic
//
// Typical usage:
//
//	dev := tropic01.NewDevice(transport)
//	if err := dev.Init(); err != nil { ... }
//	defer dev.Deinit()
package tropic01
