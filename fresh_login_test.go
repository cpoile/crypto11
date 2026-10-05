//go:build crypto11_testshim

package crypto11

import (
	"fmt"
	"github.com/eclipse-keypont/crypto11/internal/testshim"
	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestFreshLoginOwnership(t *testing.T) {
	cfg := nativeConfig(t)
	cfg.RequireFreshLogin = true
	first, err := Configure(cfg)
	require.NoError(t, err)
	defer first.Close()
	key, err := first.GenerateSecretKey(randomBytes(), 256, CipherAES)
	require.NoError(t, err)
	defer key.Delete()
	aead, err := key.NewGCM()
	require.NoError(t, err)
	wrong := *cfg
	wrong.Pin = "wrong-candidate-pin"
	live, refs := testshim.Counter(testshim.Live), references(cfg.Path)
	logouts := testshim.Counter(testshim.LogoutAttempts)
	failed, err := Configure(&wrong)
	require.Nil(t, failed)
	nativeCode(t, err, pkcs11.CKR_USER_ALREADY_LOGGED_IN)
	require.Equal(t, live, testshim.Counter(testshim.Live))
	require.Equal(t, refs, references(cfg.Path))
	require.Equal(t, logouts, testshim.Counter(testshim.LogoutAttempts))
	// The compatible default still shares the application's existing login.
	wrong.RequireFreshLogin = false
	compatible, err := Configure(&wrong)
	require.NoError(t, err)
	require.Error(t, compatible.LogoutAndClose())
	require.Equal(t, logouts, testshim.Counter(testshim.LogoutAttempts))
	require.NoError(t, compatible.Close())
	nonce := make([]byte, aead.NonceSize())
	encrypted := aead.Seal(nil, nonce, []byte("healthy"), nil)
	plain, err := aead.Open(nil, nonce, encrypted, nil)
	require.NoError(t, err)
	require.Equal(t, "healthy", string(plain))
}

func TestFreshLoginTemporaryCleanup(t *testing.T) {
	for _, failure := range []uint{0, pkcs11.CKR_DEVICE_ERROR, pkcs11.CKR_USER_NOT_LOGGED_IN} {
		t.Run(fmt.Sprintf("logout_%x", failure), func(t *testing.T) {
			cfg := nativeConfig(t)
			cfg.RequireFreshLogin = true
			siblingCfg := *cfg
			siblingCfg.TokenLabel = "token2"
			sibling, err := Configure(&siblingCfg)
			require.NoError(t, err)
			defer sibling.Close()
			baseline := testshim.Counter(testshim.Live)
			temporary, err := Configure(cfg)
			require.NoError(t, err)
			attempts := testshim.Counter(testshim.LogoutAttempts)
			testshim.Fault(testshim.Logout, failure)
			err = temporary.LogoutAndClose()
			if failure == 0 {
				require.NoError(t, err)
			} else {
				nativeCode(t, err, failure)
			}
			require.Equal(t, attempts+1, testshim.Counter(testshim.LogoutAttempts))
			require.Equal(t, baseline, testshim.Counter(testshim.Live))
			require.Equal(t, 1, references(cfg.Path))
			require.Error(t, temporary.LogoutAndClose())
			testshim.Fault(testshim.NoFault, 0)
			_, err = sibling.FindAllKeys()
			require.NoError(t, err)
			reopened, err := Configure(cfg)
			require.NoError(t, err)
			require.NoError(t, reopened.LogoutAndClose())
		})
	}
}

func TestFreshLoginFailedClose(t *testing.T) {
	cfg := nativeConfig(t)
	cfg.RequireFreshLogin = true
	siblingCfg := *cfg
	siblingCfg.TokenLabel = "token2"
	sibling, err := Configure(&siblingCfg)
	require.NoError(t, err)
	defer sibling.Close()
	temporary, err := Configure(cfg)
	require.NoError(t, err)
	testshim.Fault(testshim.CloseSession, pkcs11.CKR_DEVICE_ERROR)
	// Successful explicit logout permits fresh authentication even if CloseSession fails.
	require.NoError(t, temporary.LogoutAndClose())
	testshim.Fault(testshim.NoFault, 0)
	wrong := *cfg
	wrong.Pin = "wrong-candidate-pin"
	failed, err := Configure(&wrong)
	require.Nil(t, failed)
	nativeCode(t, err, pkcs11.CKR_PIN_INCORRECT)
	next, err := Configure(cfg)
	require.NoError(t, err)
	require.NoError(t, next.LogoutAndClose())
	_, err = sibling.FindAllKeys()
	require.NoError(t, err)
}

func TestFreshLoginRequiresLoginSupport(t *testing.T) {
	c, err := Configure(&Config{RequireFreshLogin: true, LoginNotSupported: true})
	require.Nil(t, c)
	require.Error(t, err)
}

func TestFreshLoginConcurrentCandidates(t *testing.T) {
	cfg := nativeConfig(t)
	cfg.RequireFreshLogin = true
	cfg.MaxSessions = 2
	type result struct {
		c   *Context
		err error
	}
	results := make(chan result, 8)
	start := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			local := *cfg
			<-start
			c, err := Configure(&local)
			results <- result{c, err}
		}()
	}
	close(start)
	var winner *Context
	successes := 0
	for i := 0; i < 8; i++ {
		r := <-results
		if r.err == nil {
			winner = r.c
			successes++
		} else {
			nativeCode(t, r.err, pkcs11.CKR_USER_ALREADY_LOGGED_IN)
		}
	}
	require.Equal(t, 1, successes)
	require.NoError(t, winner.LogoutAndClose())
	next, err := Configure(cfg)
	require.NoError(t, err)
	require.NoError(t, next.LogoutAndClose())
}
