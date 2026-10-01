package crypto11

import (
	"errors"
	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSealErrorCause(t *testing.T) {
	cause := pkcs11.Error(pkcs11.CKR_DEVICE_ERROR)
	marked := &SealError{Err: cause}
	var native pkcs11.Error
	require.True(t, errors.As(marked, &native))
	require.Equal(t, cause, native)
	require.ErrorIs(t, marked, cause)
}

func TestSealNonceMisuse(t *testing.T) {
	// A malformed nonce must panic before touching even an uninitialized key.
	g := genericAead{nonceSize: 12}
	require.PanicsWithValue(t, "crypto11: incorrect nonce length given to GCM", func() {
		g.Seal(nil, make([]byte, 11), nil, nil)
	})
}
