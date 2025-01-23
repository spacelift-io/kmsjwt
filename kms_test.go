package kmsjwt_test

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/kms"
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
