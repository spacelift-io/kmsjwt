package kmsjwt

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// KMS implements a small subset of the KMS API.
type KMS interface {
	GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error)
}
