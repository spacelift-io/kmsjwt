package internal

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/stretchr/testify/mock"
)

type MockKMS struct {
	mock.Mock
}

func (m *MockKMS) GetPublicKey(ctx context.Context, input *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	args := m.Called(ctx, input, optFns)
	return args.Get(0).(*kms.GetPublicKeyOutput), args.Error(1)
}

func (m *MockKMS) Sign(ctx context.Context, input *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
	args := m.Called(ctx, input, optFns)
	return args.Get(0).(*kms.SignOutput), args.Error(1)
}
