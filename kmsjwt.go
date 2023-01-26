package kmsjwt

import (
	"context"
	"crypto/rsa"
	"encoding/base64"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
)

// KMSJWT is a JWT signing method implementation using RSA512 with the private
// key stored in AWS KMS. The public key is retrieved from KMS on
// initialization.
type KMSJWT struct {
	api       KMS
	keyID     string
	publicKey *rsa.PublicKey
}

// New provides a KMS-based implementation of JWT signing method.
func New(ctx context.Context, api KMS, keyID string) (*KMSJWT, error) {
	out, err := api.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		return nil, errors.Wrap(err, "could not retrieve public key")
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(out.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse public key")
	}

	return &KMSJWT{api, keyID, publicKey}, nil
}

// NewWithPublicKey provides a KMS-based implementation of JWT signing method
// with a pre-loaded public key.
func NewWithPublicKey(api KMS, keyID string, publicKey *rsa.PublicKey) *KMSJWT {
	return &KMSJWT{api, keyID, publicKey}
}

func (k *KMSJWT) Alg() string {
	return jwt.SigningMethodRS512.Alg()
}

func (k *KMSJWT) Sign(signingString string, key interface{}) (string, error) {
	ctx, ok := key.(context.Context)
	if !ok {
		return "", jwt.ErrInvalidKeyType
	}

	hash := jwt.SigningMethodPS512.Hash.New()
	hash.Write([]byte(signingString))

	out, err := k.api.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(k.keyID),
		Message:          hash.Sum(nil),
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
	})

	if err != nil && errors.Is(err, context.Canceled) {
		return "", err
	} else if err != nil {
		return "", jwt.ErrInvalidKey
	}

	return base64.RawURLEncoding.EncodeToString(out.Signature), nil
}

func (k *KMSJWT) Verify(signingString, stringSignature string, _ interface{}) error {
	return jwt.SigningMethodRS512.Verify(signingString, stringSignature, k.publicKey)
}
