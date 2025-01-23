package kmsjwt

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/golang-jwt/jwt/v4"
)

var (
	signingMethod = jwt.SigningMethodPS512
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
	if err != nil {
		return nil, fmt.Errorf("kmsjwt new: %w", err)
	}
	return &KMSJWT{client: client, keyID: keyID, publicKey: publicKey}, err
}

func getPublicKey(ctx context.Context, client KMS, keyID string) (*rsa.PublicKey, error) {
	response, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: &keyID})
	if err != nil {
		return nil, fmt.Errorf("could not retrieve public key: %w", err)
	}

	publicKey, err := x509.ParsePKIXPublicKey(response.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("could not parse public key: %w", err)
	}

	result, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key: cannot assert %T as %T", publicKey, result)
	}

	return result, nil
}

// Alg returns the signing algorithm as defined in https://datatracker.ietf.org/doc/html/rfc7518#section-3.1.
func (k KMSJWT) Alg() string {
	return signingMethod.Alg()
}

// Sign signs the signingString with AWS KMS using the key ID stored on the object.
// The key parameter expects a context.Context that is used for the network call to KMS.
func (k KMSJWT) Sign(signingString string, key interface{}) (string, error) {
	ctx, ok := key.(context.Context)
	if !ok {
		return "", fmt.Errorf("kmsjwt sign: %w", jwt.ErrInvalidKeyType)
	}

	hash := signingMethod.Hash.New()
	_, _ = hash.Write([]byte(signingString))

	out, err := k.client.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(k.keyID),
		Message:          hash.Sum(nil),
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPssSha512,
	})
	if err != nil {
		return "", fmt.Errorf("kmsjwt signing with KMS: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(out.Signature), nil
}

// Verify verifies that the signature is valid for the signingString.
// The verification is done on the client side using the rsa.PublicKey stored on the object.
// For the key parameter a context.Context is expected.
func (k KMSJWT) Verify(signingString, stringSignature string, key interface{}) error {
	// We don't use context, but let's keep it so:
	// - The interface remains symmetric with Sign.
	// - It can be reintroduced later if needed without breaking the interface.
	_, ok := key.(context.Context)
	if !ok {
		return fmt.Errorf("kmsjwt verify: %w", jwt.ErrInvalidKeyType)
	}

	return signingMethod.Verify(signingString, stringSignature, k.publicKey)
}
