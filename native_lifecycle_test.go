//go:build crypto11_testshim

package crypto11

import (
	"errors"
	"github.com/eclipse-keypont/crypto11/internal/testshim"
	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func nativeConfig(t *testing.T) *Config {
	t.Helper()
	path := os.Getenv("CRYPTO11_TEST_SHIM")
	require.NotEmpty(t, path, "mandatory forwarding module unavailable")
	require.True(t, testshim.Open(path), "cannot load mandatory forwarding module")
	testshim.Fault(testshim.NoFault, 0)
	t.Cleanup(func() { testshim.Fault(testshim.NoFault, 0) })
	cfg, err := getConfig("config")
	require.NoError(t, err)
	cfg.Path = path
	return cfg
}
func references(path string) int {
	moduleReferencesMutex.Lock()
	defer moduleReferencesMutex.Unlock()
	return moduleReferences[path].refCount
}
func nativeCode(t *testing.T, err error, code uint) {
	t.Helper()
	var native pkcs11.Error
	require.True(t, errors.As(err, &native), "missing native error cause")
	require.Equal(t, pkcs11.Error(code), native)
}

func TestInvalidPinDoesntDestroyLibrary(t *testing.T) {
	cfg := nativeConfig(t)
	healthy, err := Configure(cfg)
	require.NoError(t, err)
	defer func() {
		if healthy != nil {
			_ = healthy.Close()
		}
	}()
	key, err := healthy.GenerateSecretKey(randomBytes(), 256, CipherAES)
	require.NoError(t, err)
	aead, err := key.NewGCM()
	require.NoError(t, err)
	finalizes := testshim.Counter(testshim.Finalized)
	refs := references(cfg.Path)
	wrong := *cfg
	wrong.TokenLabel = "token2"
	wrong.Pin = "this_should_be_wrong_pin"
	for i := 0; i < 8; i++ {
		baseline := testshim.Counter(testshim.Live)
		opens, closes := testshim.Counter(testshim.Opened), testshim.Counter(testshim.Closed)
		failed, err := Configure(&wrong)
		require.Nil(t, failed)
		nativeCode(t, err, pkcs11.CKR_PIN_INCORRECT)
		require.Equal(t, opens+1, testshim.Counter(testshim.Opened))
		require.Equal(t, closes+1, testshim.Counter(testshim.Closed))
		require.Equal(t, baseline, testshim.Counter(testshim.Live), "failed login leaked a native handle")
		require.Equal(t, refs, references(cfg.Path), "failed login leaked module reference")
		require.Equal(t, finalizes, testshim.Counter(testshim.Finalized), "healthy owner's module was finalized")
		nonce := randomBytes()[:aead.NonceSize()]
		ciphertext := aead.Seal(nil, nonce, []byte("healthy"), nil)
		plain, err := aead.Open(nil, nonce, ciphertext, nil)
		require.NoError(t, err)
		require.Equal(t, []byte("healthy"), plain)
	}
	require.NoError(t, key.Delete())
	require.NoError(t, healthy.Close())
	healthy = nil
	require.Zero(t, references(cfg.Path))
	require.Zero(t, testshim.Counter(testshim.Live))
	require.Equal(t, finalizes+1, testshim.Counter(testshim.Finalized))
	reopened, err := Configure(cfg)
	require.NoError(t, err)
	require.NoError(t, reopened.Close())
	require.Equal(t, finalizes+2, testshim.Counter(testshim.Finalized))
	require.Zero(t, testshim.Counter(testshim.InvalidCloses), "unowned/double session close")
}

func TestNativeFailureOwnership(t *testing.T) {
	cfg := nativeConfig(t)
	testshim.Fault(testshim.Initialize, pkcs11.CKR_DEVICE_ERROR)
	failed, err := Configure(cfg)
	require.Nil(t, failed)
	nativeCode(t, err, pkcs11.CKR_DEVICE_ERROR)
	require.Zero(t, references(cfg.Path))
	require.Zero(t, testshim.Counter(testshim.Live))
	testshim.Fault(testshim.NoFault, 0)
	healthy, err := Configure(cfg)
	require.NoError(t, err)
	defer func() {
		if healthy != nil {
			_ = healthy.Close()
		}
	}()
	baseline, refs := testshim.Counter(testshim.Live), references(cfg.Path)
	attempts, finals := testshim.Counter(testshim.CloseAttempts), testshim.Counter(testshim.Finalized)
	missing := *cfg
	missing.TokenLabel = "missing-token"
	failed, err = Configure(&missing)
	require.Nil(t, failed)
	require.Error(t, err)
	require.Equal(t, refs, references(cfg.Path))
	require.Equal(t, baseline, testshim.Counter(testshim.Live))
	require.Equal(t, attempts, testshim.Counter(testshim.CloseAttempts))
	testshim.Fault(testshim.OpenSession, pkcs11.CKR_SESSION_COUNT)
	failed, err = Configure(cfg)
	require.Nil(t, failed)
	nativeCode(t, err, pkcs11.CKR_SESSION_COUNT)
	require.Equal(t, refs, references(cfg.Path))
	require.Equal(t, attempts, testshim.Counter(testshim.CloseAttempts))
	testshim.Fault(testshim.CloseSession, pkcs11.CKR_DEVICE_ERROR)
	wrong := *cfg
	wrong.TokenLabel = "token2"
	wrong.Pin = "incorrect-pin"
	failed, err = Configure(&wrong)
	require.Nil(t, failed)
	nativeCode(t, err, pkcs11.CKR_PIN_INCORRECT)
	require.Equal(t, attempts+1, testshim.Counter(testshim.CloseAttempts), "cleanup must be attempted once")
	require.Equal(t, baseline+1, testshim.Counter(testshim.Live), "failed close must not claim reclamation")
	require.Equal(t, refs, references(cfg.Path))
	require.Equal(t, finals, testshim.Counter(testshim.Finalized))
	testshim.Fault(testshim.NoFault, 0)
	_, err = healthy.FindAllKeys()
	require.NoError(t, err)
	require.NoError(t, healthy.Close())
	healthy = nil
	require.Zero(t, references(cfg.Path))
	require.Zero(t, testshim.Counter(testshim.Live))
	require.Equal(t, finals+1, testshim.Counter(testshim.Finalized))
}

func TestNativeAEADErrors(t *testing.T) {
	for _, test := range []struct {
		name    string
		faultID testshim.FaultID
		seal    bool
	}{
		{"EncryptInit", testshim.EncryptInit, true},
		{"Encrypt", testshim.Encrypt, true},
		{"DecryptInit", testshim.DecryptInit, false},
		{"Decrypt", testshim.Decrypt, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := nativeConfig(t)
			ctx, err := Configure(cfg)
			require.NoError(t, err)
			defer ctx.Close()
			key, err := ctx.GenerateSecretKey(randomBytes(), 256, CipherAES)
			require.NoError(t, err)
			defer key.Delete()
			aead, err := key.NewGCM()
			require.NoError(t, err)
			nonce := make([]byte, aead.NonceSize())
			require.PanicsWithValue(t, "crypto11: incorrect nonce length given to GCM", func() {
				aead.Seal(nil, nonce[:len(nonce)-1], nil, nil)
			})
			require.PanicsWithValue(t, "crypto11: incorrect nonce length given to GCM", func() {
				aead.Open(nil, nonce[:len(nonce)-1], nil, nil)
			})
			sentinel := errors.New("unrelated panic")
			other := aead.(genericAead)
			other.makeMech = func([]byte, []byte, bool) ([]*pkcs11.Mechanism, *pkcs11.GCMParams, error) { panic(sentinel) }
			require.PanicsWithValue(t, sentinel, func() { other.Seal(nil, nonce, nil, nil) })
			ciphertext := aead.Seal(nil, nonce, []byte("fixture"), nil)
			testshim.Fault(test.faultID, pkcs11.CKR_DEVICE_ERROR)
			if test.seal {
				func() {
					defer func() {
						failure, ok := recover().(*SealError)
						require.True(t, ok, "Seal must mark returned operation failure")
						nativeCode(t, failure, pkcs11.CKR_DEVICE_ERROR)
					}()
					aead.Seal(nil, nonce, []byte("fixture"), nil)
					t.Fatal("native Seal unexpectedly succeeded")
				}()
			} else {
				result, err := aead.Open(nil, nonce, ciphertext, nil)
				require.Nil(t, result)
				nativeCode(t, err, pkcs11.CKR_DEVICE_ERROR)
			}
			testshim.Fault(testshim.NoFault, 0)
		})
	}
}
