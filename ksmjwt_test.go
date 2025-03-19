package kmsjwt_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/spacelift-io/kmsjwt/v7"
)

func TestWithLocalStack(t *testing.T) {
	const in = "sign me, please"
	ctx := context.Background()
	client := newKMSClient(t, ctx)
	keyID := client.CreateKey(t, ctx)

	t.Run("sign and verify", func(t *testing.T) {
		signer, err := kmsjwt.New(ctx, client.KMS, keyID)
		require.NoError(t, err, "new")

		signature, err := signer.Sign(in, ctx)
		require.NoError(t, err, "sign")

		err = signer.Verify(in, signature, ctx)
		assert.NoError(t, err, "verify")
	})

	t.Run("RFC compliance", func(t *testing.T) {
		signer, err := kmsjwt.New(ctx, client.KMS, keyID)
		require.NoError(t, err, "new")

		signature, err := signer.Sign(in, ctx)
		require.NoError(t, err, "sign")

		builtinSigner := jwt.GetSigningMethod(signer.Alg())
		require.NotNil(t, builtinSigner, "unknown algorithm")

		publicKey := client.GetPublicKey(t, ctx, keyID)
		err = builtinSigner.Verify(in, signature, publicKey)
		assert.NoError(t, err, "verify")
	})
}

func TestNew(t *testing.T) {
	const keyID = "dummy"

	t.Run("happy", func(t *testing.T) {
		_, _ = newSignerAndStub(t)
	})

	t.Run("error preserved in chain from KMS", func(t *testing.T) {
		ctx := context.Background()
		want := errors.New("something went wrong")

		_, err := kmsjwt.New(ctx, KMSStub{Err: want}, keyID)
		assert.ErrorIs(t, err, want)
	})

	t.Run("wrong key type", func(t *testing.T) {
		ctx := context.Background()
		publicKey := encodedED25519PublicKey(t)

		_, err := kmsjwt.New(ctx, KMSStub{PublicKey: publicKey}, keyID)
		assert.ErrorContains(t, err, "cannot assert")
	})

	t.Run("key not parsable", func(t *testing.T) {
		ctx := context.Background()
		publicKey := []byte("something unexpected")

		_, err := kmsjwt.New(ctx, KMSStub{PublicKey: publicKey}, keyID)
		assert.ErrorContains(t, err, "could not parse")
	})
}

func newSignerAndStub(t *testing.T) (kmsjwt.KMSJWT, *KMSStub) {
	t.Helper()
	const keyID = "dummy"
	ctx := context.Background()
	stub := &KMSStub{PublicKey: encodedRSAPublicKey(t)}
	signer, err := kmsjwt.New(ctx, stub, keyID)
	require.NoError(t, err, "creating signer")
	return signer, stub
}

func TestKMSJWT_Alg(t *testing.T) {
	// Valid values: https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
	const want = "PS512"
	signer, _ := newSignerAndStub(t)
	assert.Equal(t, want, signer.Alg(), "algorithm changed, that's MAJOR change")
}

func TestKMSJWT_Sign(t *testing.T) {
	const signMe = "sign me, please"

	t.Run("invalid key type", func(t *testing.T) {
		signer, _ := newSignerAndStub(t)

		_, err := signer.Sign(signMe, "foo")
		assert.ErrorIs(t, err, jwt.ErrInvalidKeyType)
	})

	t.Run("error preserved in chain", func(t *testing.T) {
		ctx := context.Background()
		signer, stub := newSignerAndStub(t)
		stub.Err = errors.New("something went wrong")

		_, err := signer.Sign(signMe, ctx)
		assert.ErrorIs(t, err, stub.Err)
	})
}

func TestKMSJWT_Verify(t *testing.T) {
	const signMe = "sign me, please"

	t.Run("invalid key type", func(t *testing.T) {
		signer, _ := newSignerAndStub(t)
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err, "generating key")
		signature, err := signer.Sign(signMe, key)
		require.NoError(t, err, "signing")

		err = signer.Verify(signMe, signature, "foo")
		assert.ErrorIs(t, err, jwt.ErrInvalidKey)
	})
}

func TestKMSJWT_BuiltinFallback(t *testing.T) {
	const signMe = "sign me, please"

	signer, _ := newSignerAndStub(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "generating key")

	signature, err := signer.Sign(signMe, key)
	fmt.Println(signature)
	require.NoError(t, err, "signing")

	err = signer.Verify(signMe, signature, &key.PublicKey)
	require.NoError(t, err, "verifying")
}
