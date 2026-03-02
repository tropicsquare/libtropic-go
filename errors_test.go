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
