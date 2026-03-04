package tropic01_test

import (
	"testing"

	tropic01 "libtropic-go/tropic01"
)

func TestErrorString(t *testing.T) {
	tests := []struct {
		err  tropic01.Error
		want string
	}{
		{tropic01.ErrOK, "OK"},
		{tropic01.ErrFail, "fail"},
		{tropic01.ErrNoSession, "no session"},
		{tropic01.ErrParam, "param error"},
		{tropic01.ErrCrypto, "crypto error"},
		{tropic01.Error(99), "unknown error (99)"},
	}
	for _, tc := range tests {
		if got := tc.err.Error(); got != tc.want {
			t.Errorf("Error(%d).Error() = %q, want %q", tc.err, got, tc.want)
		}
	}
}
