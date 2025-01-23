package kmsjwt_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/spacelift-io/kmsjwt/v7"
)

func TestWithLocalStack(t *testing.T) {
	const in = "sign me, please"
	ctx := context.Background()
	client := newClient(t, ctx)
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

func newClient(t *testing.T, ctx context.Context) Client {
	t.Helper()

	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("eu-west-1"),
		config.WithBaseEndpoint("http://localhost:4566"),
		config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider("dummy", "dummy", "dummy"),
		),
	)
	require.NoError(t, err, "load AWS config")

	return Client{KMS: kms.NewFromConfig(cfg)}
}

type Client struct {
	KMS *kms.Client
}

func (c Client) CreateKey(t *testing.T, ctx context.Context) (id string) {
	t.Helper()
	result, err := c.KMS.CreateKey(ctx, &kms.CreateKeyInput{
		KeySpec:  types.KeySpecRsa4096,
		KeyUsage: types.KeyUsageTypeSignVerify,
	})
	require.NoError(t, err, "creating KMS key")
	return *result.KeyMetadata.KeyId
}

func (c Client) GetPublicKey(t *testing.T, ctx context.Context, id string) *rsa.PublicKey {
	t.Helper()
	response, err := c.KMS.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: &id,
	})
	require.NoError(t, err, "get KMS public key")

	key, err := x509.ParsePKIXPublicKey(response.PublicKey)
	require.NoError(t, err, "parsing fetched pubic key")

	return key.(*rsa.PublicKey)
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

func encodedRSAPublicKey(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "generating RSA key")
	return encode(t, &key.PublicKey)
}

func encode(t *testing.T, publicKey any) []byte {
	t.Helper()
	encoded, err := x509.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, err, "encoding public key")
	return encoded
}

func encodedED25519PublicKey(t *testing.T) []byte {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err, "generating ed25519 key")
	return encode(t, publicKey)
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

		err := signer.Verify(signMe, "invalid signature", "foo")
		assert.ErrorIs(t, err, jwt.ErrInvalidKeyType)
	})
}
