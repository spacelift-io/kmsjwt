package kmsjwt_test

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
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
	publicKey := client.GetPublicKey(t, ctx, keyID)

	t.Run("new", func(t *testing.T) {
		signer := kmsjwt.New(client.KMS, keyID)

		signature, err := signer.Sign(in, ctx)
		require.NoError(t, err, "sign")

		err = signer.Verify(in, signature, ctx)
		assert.NoError(t, err, "verify")
	})

	t.Run("new with public key", func(t *testing.T) {
		signer := kmsjwt.NewWithPublicKey(client.KMS, keyID, publicKey)

		signature, err := signer.Sign(in, ctx)
		require.NoError(t, err, "sign")

		err = signer.Verify(in, signature, ctx)
		assert.NoError(t, err, "verify")
	})

	t.Run("RFC compliance", func(t *testing.T) {
		signer := kmsjwt.New(client.KMS, keyID)

		signature, err := signer.Sign(in, ctx)
		require.NoError(t, err, "sign")

		builtinSigner := jwt.GetSigningMethod(signer.Alg())
		require.NotNil(t, builtinSigner, "unknown algorithm")

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
