package kmsjwt

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
)

var signingMethod = jwt.SigningMethodRS512

// KMSJWT is a JWT signing method implementation using RSA512 with the private
// key stored in AWS KMS. The public key is retrieved from KMS on
// initialization.
type KMSJWT struct {
	api   KMS
	keyID string

	lock      sync.Mutex
	publicKey *rsa.PublicKey
}

// New provides a KMS-based implementation of JWT signing method.
func New(api KMS, keyID string) *KMSJWT {
	return &KMSJWT{api: api, keyID: keyID}
}

// NewWithPublicKey provides a KMS-based implementation of JWT signing method
// with a pre-loaded public key.
func NewWithPublicKey(api KMS, keyID string, publicKey *rsa.PublicKey) *KMSJWT {
	return &KMSJWT{api: api, keyID: keyID, publicKey: publicKey}
}

func (k *KMSJWT) Alg() string {
	return signingMethod.Alg()
}

func (k *KMSJWT) Sign(signingString string, key interface{}) (string, error) {
	ctx, ok := key.(context.Context)
	if !ok {
		return "", jwt.ErrInvalidKeyType
	}

	hash := signingMethod.Hash.New()
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

func (k *KMSJWT) Verify(signingString, stringSignature string, key interface{}) error {
	ctx, ok := key.(context.Context)
	if !ok {
		return jwt.ErrInvalidKeyType
	}

	publicKey, err := k.getPublicKey(ctx)
	if err != nil {
		return err
	}

	return signingMethod.Verify(signingString, stringSignature, publicKey)
}

func (k *KMSJWT) getPublicKey(ctx context.Context) (*rsa.PublicKey, error) {
	k.lock.Lock()
	defer k.lock.Unlock()

	if k.publicKey != nil {
		return k.publicKey, nil
	}

	response, err := k.api.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: &k.keyID})
	if err != nil {
		return nil, errors.Wrap(err, "could not retrieve public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(response.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse public key")
	}

	var ok bool
	k.publicKey, ok = publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.Errorf("public key type assertion: cannot assert %T as %T", publicKey, k.publicKey)
	}

	return k.publicKey, nil
}
