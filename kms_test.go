package kmsjwt_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stretchr/testify/require"
)

type KMSStub struct {
	Err       error
	PublicKey []byte
}

func (k KMSStub) GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	return &kms.GetPublicKeyOutput{PublicKey: k.PublicKey}, k.Err
}

func (k KMSStub) Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error) {
	// The message is already hashed, so we cannot produce a valid signature here.
	return &kms.SignOutput{Signature: []byte("invalid")}, k.Err
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

func newKMSClient(t *testing.T, ctx context.Context) Client {
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
