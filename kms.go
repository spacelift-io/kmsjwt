package kmsjwt

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// KMS defines a small part of the AWS KMS interface, that is required by the signer to work.
type KMS interface {
	GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error)
}
