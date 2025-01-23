package kmsjwt

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
)

var (
	signingMethod = jwt.SigningMethodRS512
	_             = jwt.SigningMethod(KMSJWT{})
)

// KMSJWT is a JWT signing method implementation using an asymmetric AWS KMS key.
// The signing is done by KMS service, so there is a network call on every sign action.
// The verification is done on the client side with the exported public key.
// The public key is retrieved from KMS on initialization.
type KMSJWT struct {
	client    KMS
	keyID     string
	publicKey *rsa.PublicKey
}

// New retrieves the public key from KMS and returns a signer.
func New(ctx context.Context, client KMS, keyID string) (*KMSJWT, error) {
	publicKey, err := getPublicKey(ctx, client, keyID)
	return &KMSJWT{client: client, keyID: keyID, publicKey: publicKey}, err
}

func getPublicKey(ctx context.Context, client KMS, keyID string) (*rsa.PublicKey, error) {
	response, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: &keyID})
	if err != nil {
		return nil, errors.Wrap(err, "could not retrieve public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(response.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse public key")
	}

	result, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.Errorf("public key type assertion: cannot assert %T as %T", publicKey, result)
	}

	return result, nil
}

func (k KMSJWT) Alg() string {
	return signingMethod.Alg()
}

func (k KMSJWT) Sign(signingString string, key interface{}) (string, error) {
	ctx, ok := key.(context.Context)
	if !ok {
		return "", jwt.ErrInvalidKeyType
	}

	hash := signingMethod.Hash.New()
	hash.Write([]byte(signingString))

	out, err := k.client.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(k.keyID),
		Message:          hash.Sum(nil),
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
	})

	if errors.Is(err, context.Canceled) {
		return "", err
	} else if err != nil {
		return "", errors.Wrap(err, "signing with KMS")
	}

	return base64.RawURLEncoding.EncodeToString(out.Signature), nil
}

func (k KMSJWT) Verify(signingString, stringSignature string, key interface{}) error {
	// We don't use context, but let's keep it so:
	// - The interface remains symmetric with Sign.
	// - It can be reintroduced later if needed without breaking the interface.
	_, ok := key.(context.Context)
	if !ok {
		return jwt.ErrInvalidKeyType
	}

	return signingMethod.Verify(signingString, stringSignature, k.publicKey)
}
