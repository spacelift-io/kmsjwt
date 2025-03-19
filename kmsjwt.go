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

// KMSJWT implements jwt.SigningMethod using an asymmetric AWS KMS key.
// Signing is performed by the KMS service, requiring a network call for each signing operation.
// Verification is handled on the client side, using the public key, which is retrieved from KMS during initialization.
// If the library is registered with jwt.RegisterSigningMethod, it overrides the built-in method.
// This override is not an issue, as the library behaves like the built-in method unless the key type is context.Context.
type KMSJWT struct {
	client    KMS
	keyID     string
	publicKey *rsa.PublicKey
}

// New retrieves the public key from KMS and returns a signer.
func New(ctx context.Context, client KMS, keyID string) (KMSJWT, error) {
	publicKey, err := getPublicKey(ctx, client, keyID)
	if err != nil {
		return KMSJWT{}, fmt.Errorf("kmsjwt new: %w", err)
	}
	return KMSJWT{client: client, keyID: keyID, publicKey: publicKey}, err
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

// Sign signs the signingString using AWS KMS with the key ID stored in the object.
// The key parameter expected to be a context.Context, that is used for the network call to KMS.
// If the key is not of type context.Context, the method falls back to the algorithm provided by jwt.
func (k KMSJWT) Sign(signingString string, key interface{}) (string, error) {
	ctx, ok := key.(context.Context)
	if ok {
		return k.signWithKMS(ctx, signingString)
	}
	return signingMethod.Sign(signingString, key)
}

func (k KMSJWT) signWithKMS(ctx context.Context, signingString string) (string, error) {
	hash := signingMethod.Hash.New()
	_, err := hash.Write([]byte(signingString))
	if err != nil {
		return "", fmt.Errorf("kmsjwt writing hash: %w", err)
	}

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

// Verify checks whether the signature is valid for the given signingString.
// Verification is performed on the client side.
// If the key is of type context.Context, the key stored in the struct is used for verification.
// Otherwise, the provided key is used.
func (k KMSJWT) Verify(signingString, stringSignature string, key interface{}) error {
	// We use context, so the interface remains symmetric with Sign.
	_, ok := key.(context.Context)
	if ok {
		key = k.publicKey
	}
	return signingMethod.Verify(signingString, stringSignature, key)
}
