package kmsjwt_test

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/franela/goblin"
	"github.com/golang-jwt/jwt/v4"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/spacelift-io/kmsjwt/v6"
	"github.com/spacelift-io/kmsjwt/v6/internal"
)

func TestKMSJWT(t *testing.T) {
	g := goblin.Goblin(t)
	RegisterFailHandler(func(m string, _ ...int) { g.Fail(m) })

	g.Describe("KMSJWT", func() {
		const kmsKeyID = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
		const signingString = "bacon"

		var noOpts []func(*kms.Options)

		var api *internal.MockKMS
		var ctx context.Context
		var err error
		var expectedSignature string
		var signature string
		var sut *kmsjwt.KMSJWT

		g.BeforeEach(func() {
			api = &internal.MockKMS{}
			ctx = context.Background()
			signature = ""

			sut = kmsjwt.New(api, kmsKeyID)

			data, err := os.ReadFile("testdata/rsa.private")
			require.NoError(t, err)

			privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(data)
			require.NoError(t, err)

			expectedSignature, err = jwt.SigningMethodRS512.Sign(signingString, privateKey)
			require.NoError(t, err)
		})

		g.Describe("Alg", func() {
			g.It("should return the correct algorithm", func() {
				Expect(sut.Alg()).To(Equal("RS512"))
			})
		})

		g.Describe("Sign", func() {
			var apiCall *mock.Call
			var input *kms.SignInput

			g.BeforeEach(func() {
				input = nil

				apiCall = api.On("Sign", ctx, mock.MatchedBy(func(i any) bool {
					input = i.(*kms.SignInput)
					return true
				}), noOpts)
			})

			g.JustBeforeEach(func() { signature, err = sut.Sign(signingString, ctx) })

			g.Describe("when the API call fails", func() {
				g.Describe("with context cancellation", func() {
					g.BeforeEach(func() { apiCall.Return((*kms.SignOutput)(nil), context.Canceled) })

					g.It("sends the right request", func() {
						Expect(input).ToNot(BeNil())
						Expect(*input.KeyId).To(Equal(kmsKeyID))
						Expect(hex.EncodeToString(input.Message)).To(Equal("7f7284ac92b0151c6ab58adc9e6673f63d420cf7bc5f829cb03e17b73daef49dccfdc2b29142f2bfd609ebdcc9abf7f3a63c2fe02f8b5e62b9a664c9f6152848"))
						Expect(input.MessageType).To(Equal(types.MessageTypeDigest))
						Expect(input.SigningAlgorithm).To(Equal(types.SigningAlgorithmSpecRsassaPkcs1V15Sha512))
					})

					g.It("should return the raw error", func() {
						Expect(signature).To(BeEmpty())
						Expect(err).To(MatchError("context canceled"))
					})
				})

				g.Describe("with a generic error", func() {
					g.BeforeEach(func() { apiCall.Return((*kms.SignOutput)(nil), errors.New("bacon")) })

					g.It("should return an invalid key error", func() {
						Expect(signature).To(BeEmpty())
						Expect(err).To(MatchError("key is invalid"))
					})
				})
			})

			g.Describe("when the API call succeeds", func() {
				g.BeforeEach(func() {
					sigBytes, err := base64.RawURLEncoding.DecodeString(expectedSignature)
					require.NoError(t, err)

					apiCall.Return(&kms.SignOutput{Signature: sigBytes}, nil)
				})

				g.It("returns the signature", func() {
					Expect(err).To(Succeed())
					Expect(signature).To(Equal(expectedSignature))
				})
			})
		})

		g.Describe("Verify", func() {
			var publicKeyBytes []byte
			var publicKey *rsa.PublicKey

			g.BeforeEach(func() {
				var pemEncodedBytes []byte
				pemEncodedBytes, err = os.ReadFile("testdata/rsa.public")
				require.NoError(t, err)

				// KMS API returns DER encoded bytes.
				var decoded *pem.Block
				decoded, _ = pem.Decode(pemEncodedBytes)
				publicKeyBytes = decoded.Bytes

				publicKey, err = jwt.ParseRSAPublicKeyFromPEM(pemEncodedBytes)
				require.NoError(t, err)

				signature = expectedSignature
			})

			g.JustBeforeEach(func() { err = sut.Verify(signingString, signature, ctx) })

			g.Describe("with public key not yet loaded", func() {
				var apiCall *mock.Call

				g.BeforeEach(func() {
					apiCall = api.On("GetPublicKey", ctx, mock.MatchedBy(func(i any) bool {
						return *i.(*kms.GetPublicKeyInput).KeyId == kmsKeyID
					}), noOpts)
				})

				g.Describe("when the API call fails", func() {
					g.BeforeEach(func() { apiCall.Return((*kms.GetPublicKeyOutput)(nil), errors.New("bacon")) })

					g.It("returns an error", func() {
						Expect(err).To(MatchError("could not retrieve public key: bacon"))
					})
				})

				g.Describe("when the API call returns garbage", func() {
					g.BeforeEach(func() {
						apiCall.Return(&kms.GetPublicKeyOutput{PublicKey: []byte("bacon")}, nil)
					})

					g.It("returns an error", func() {
						Expect(err).To(MatchError(ContainSubstring("could not parse public key")))
					})
				})

				g.Describe("when the API call succeeds", func() {
					g.BeforeEach(func() {
						apiCall.Return(&kms.GetPublicKeyOutput{PublicKey: publicKeyBytes}, nil)
					})

					g.It("returns no error", func() {
						Expect(err).To(Succeed())
					})
				})
			})

			g.Describe("with public key already loaded", func() {
				g.BeforeEach(func() {
					sut = kmsjwt.NewWithPublicKey(api, kmsKeyID, publicKey)
				})

				g.Describe("with invalid signature", func() {
					g.BeforeEach(func() { signature = base64.RawStdEncoding.EncodeToString([]byte("bacon")) })

					g.It("should return an error", func() {
						Expect(err).To(MatchError("crypto/rsa: verification error"))
					})
				})

				g.Describe("with a valid signature", func() {
					g.It("should succeed", func() { Expect(err).To(Succeed()) })
				})
			})
		})
	})
}
