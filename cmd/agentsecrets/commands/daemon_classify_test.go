package commands

import (
	"errors"
	"fmt"
	"testing"

	"github.com/The-17/agentsecrets/pkg/keychainauth"
)

func TestClassifyInitErrorUsesTypedErrors(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want recoveryKind
	}{
		{name: "protocol", err: &keychainauth.DaemonProtocolError{Status: "v9"}, want: recoverProtocol},
		{name: "wrapped protocol", err: fmt.Errorf("init: %w", &keychainauth.DaemonProtocolError{Status: "v9"}), want: recoverProtocol},
		{name: "dropped connection", err: &keychainauth.DaemonConnectionError{}, want: recoverRegister},
		{name: "wrapped dropped connection", err: fmt.Errorf("init: %w", &keychainauth.DaemonConnectionError{}), want: recoverRegister},
		{name: "plain broken pipe is not classified as registration", err: errors.New("broken pipe"), want: recoverNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyInitError(tc.err); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
