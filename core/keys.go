package core

import (
	"context"
	"encoding/asn1"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	kmsCustomerMasterKeySpec = "ECC_SECG_P256K1"
	localKMSRegion           = "us-east-1"
	localKMSKeyId            = "localKMSSecretKeyId"
	localKMSSecretKey        = "localKMSSecretKey"
)

// KMSAPI defines the operations used by KMSClient to make mocking easier.
type KMSAPI interface {
	CreateKey(ctx context.Context, params *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error)
	DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
}

// KMSClient is a struct wrapper around the AWS KMS client.
type KMSClient struct {
	client     KMSAPI
	cfg        aws.Config
	kmsKeyTags []types.Tag
}

// NewKMSClient creates a new KMSClient wrapping the specified KMSAPI implementation.
func NewKMSClient(api KMSAPI) *KMSClient {
	return &KMSClient{client: api}
}

func (k *KMSClient) CreateKey(ctx context.Context, params *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
	return k.client.CreateKey(ctx, params, optFns...)
}

func (k *KMSClient) DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	return k.client.DescribeKey(ctx, params, optFns...)
}

func (k *KMSClient) GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	return k.client.GetPublicKey(ctx, params, optFns...)
}

func (k *KMSClient) Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
	return k.client.Sign(ctx, params, optFns...)
}

func InitKMSWithProfile(ctx context.Context, awsSignInRegion string, awsSignInProfile string, tagsMap map[string]string) (*KMSClient, error) {
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(awsSignInRegion),
		config.WithSharedConfigProfile(awsSignInProfile),
	)
	if err != nil {
		log.Printf("[ERROR] Failed to create KMS Config with error:%s", err)
		return nil, err
	}

	return InitKMS(ctx, cfg, tagsMap), nil
}

// InitKMSWithStaticCredentials initializes a KMS client using static explicit AWS credentials.
func InitKMSWithStaticCredentials(ctx context.Context, awsSignInRegion string, accessKey string, secretAccessKey string, kmsUrl string, tagsMap map[string]string) (*KMSClient, error) {
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(awsSignInRegion),
		config.WithCredentialsProvider(credentials.StaticCredentialsProvider{
			Value: aws.Credentials{
				AccessKeyID:     accessKey,
				SecretAccessKey: secretAccessKey,
			},
		}),
	)
	if err != nil {
		log.Printf("[ERROR] Failed to create KMS Config with error: %v", err)
		return nil, err
	}

	return InitKMS(ctx, cfg, tagsMap), nil
}

func InitLocalKMS(ctx context.Context, kmsUrl string, tagsMap map[string]string) (*KMSClient, error) {
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(localKMSRegion),
		config.WithCredentialsProvider(credentials.StaticCredentialsProvider{
			Value: aws.Credentials{
				AccessKeyID:     localKMSKeyId,
				SecretAccessKey: localKMSSecretKey,
			},
		}),
		config.WithEndpointResolverWithOptions(aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{URL: kmsUrl}, nil
		})),
	)
	if err != nil {
		log.Printf("[ERROR] Failed to create KMS Config with error: %v", err)
		return nil, err
	}

	return InitKMS(ctx, cfg, tagsMap), nil
}

func InitKMS(ctx context.Context, cfg aws.Config, tagsMap map[string]string) *KMSClient {
	var keyTags []types.Tag

	for keyTag, keyValue := range tagsMap {
		keyTags = append(keyTags, types.Tag{
			TagKey:   aws.String(keyTag),
			TagValue: aws.String(keyValue),
		})
	}

	kmsClient := kms.NewFromConfig(cfg)
	return &KMSClient{client: kmsClient, cfg: cfg, kmsKeyTags: keyTags}
}

func (k *KMSClient) RegisterKey(ctx context.Context, walletDescription string) (string, string, error) {
	input := &kms.CreateKeyInput{
		Description:           aws.String(walletDescription),
		CustomerMasterKeySpec: kmsCustomerMasterKeySpec,
		KeyUsage:              "SIGN_VERIFY",
		Tags:                  k.kmsKeyTags,
	}

	result, err := k.CreateKey(ctx, input)

	if err != nil {
		log.Printf("[ERROR] Failed to create key for wallet: %s with error: %v", walletDescription, err)
		return "", "", err
	}

	keyId := *result.KeyMetadata.KeyId

	publicKeyInput := &kms.GetPublicKeyInput{
		KeyId: aws.String(keyId),
	}
	publicKeyResult, publicKeyErr := k.GetPublicKey(ctx, publicKeyInput)
	if publicKeyErr != nil {
		log.Printf("[ERROR] Failed to get public key for key: %s with error: %v", keyId, publicKeyErr)
		return "", "", publicKeyErr
	}

	var asn1pubk asn1EcPublicKey
	_, err = asn1.Unmarshal(publicKeyResult.PublicKey, &asn1pubk)
	if err != nil {
		log.Printf("[ERROR] Failed to unmarshal public key for key: %s with error: %v", keyId, err)
		return "", "", err
	}

	pubkey, err := crypto.UnmarshalPubkey(asn1pubk.PublicKey.Bytes)
	if err != nil {
		log.Printf("[ERROR] Failed to unmarshal ecdsa key for key: %s with error: %v", keyId, err)
		return "", "", err
	}

	keyAddr := crypto.PubkeyToAddress(*pubkey)

	return keyId, keyAddr.Hex(), nil
}

func (k *KMSClient) ValidateKey(ctx context.Context, keyId string) bool {
	// Validate if we have a key registered for a given wallet
	input := &kms.DescribeKeyInput{
		KeyId: &keyId,
	}
	_, err := k.DescribeKey(ctx, input)
	if err != nil {
		log.Printf("[ERROR] Failed to describe key for key: %s with error: %v", keyId, err)
		log.Printf("[WARN] Returning Key Not Found - flag False for key: %s", keyId)
		return false
	}

	return true
}

func (k *KMSClient) GetAddressFromKeyId(ctx context.Context, keyId string) (string, error) {
	publicKeyInput := &kms.GetPublicKeyInput{
		KeyId: aws.String(keyId),
	}
	publicKeyResult, publicKeyErr := k.GetPublicKey(ctx, publicKeyInput)
	if publicKeyErr != nil {
		log.Printf("[ERROR] Failed to get public key for key: %s with error: %v", keyId, publicKeyErr)
		return "", publicKeyErr
	}

	var asn1pubk asn1EcPublicKey
	_, err := asn1.Unmarshal(publicKeyResult.PublicKey, &asn1pubk)
	if err != nil {
		log.Printf("[ERROR] Failed to unmarshal public key for key: %s with error: %v", keyId, err)
		return "", err
	}

	pubkey, err := crypto.UnmarshalPubkey(asn1pubk.PublicKey.Bytes)
	if err != nil {
		log.Printf("[ERROR] Failed to unmarshal ecdsa key for key: %s with error: %v", keyId, err)
		return "", err
	}

	keyAddr := crypto.PubkeyToAddress(*pubkey)

	return keyAddr.Hex(), nil
}
