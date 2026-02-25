package core

import (
	"context"
	"crypto/ecdsa"
	"encoding/asn1"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// mockKMSAPI implements the KMSAPI interface for testing
type mockKMSAPI struct {
	CreateKeyFunc    func(ctx context.Context, params *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error)
	DescribeKeyFunc  func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	GetPublicKeyFunc func(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	SignFunc         func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
}

func (m *mockKMSAPI) CreateKey(ctx context.Context, params *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
	if m.CreateKeyFunc != nil {
		return m.CreateKeyFunc(ctx, params, optFns...)
	}
	return nil, nil
}

func (m *mockKMSAPI) DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	if m.DescribeKeyFunc != nil {
		return m.DescribeKeyFunc(ctx, params, optFns...)
	}
	return nil, nil
}

func (m *mockKMSAPI) GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	if m.GetPublicKeyFunc != nil {
		return m.GetPublicKeyFunc(ctx, params, optFns...)
	}
	return nil, nil
}

func (m *mockKMSAPI) Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
	if m.SignFunc != nil {
		return m.SignFunc(ctx, params, optFns...)
	}
	return nil, nil
}

// generateTestKeys generates a random ECDSA key to mock a KMS key.
func generateTestKeys() (*ecdsa.PrivateKey, *ecdsa.PublicKey, []byte) {
	privateKey, _ := crypto.GenerateKey()
	pubKey := privateKey.Public().(*ecdsa.PublicKey)
	pubKeyBytes := crypto.FromECDSAPub(pubKey)

	// Convert to ASN1 as KMS returns
	asn1Struct := asn1EcPublicKey{
		EcPublicKeyInfo: asn1EcPublicKeyInfo{
			Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1},
			Parameters: asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}, // secp256k1
		},
		PublicKey: asn1.BitString{
			Bytes:     pubKeyBytes,
			BitLength: len(pubKeyBytes) * 8,
		},
	}
	derBytes, _ := asn1.Marshal(asn1Struct)

	return privateKey, pubKey, derBytes
}

func TestRegisterKey(t *testing.T) {
	_, pubKey, derBytes := generateTestKeys()
	expectedAddress := crypto.PubkeyToAddress(*pubKey).Hex()

	mock := &mockKMSAPI{
		CreateKeyFunc: func(ctx context.Context, params *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
			return &kms.CreateKeyOutput{
				KeyMetadata: &types.KeyMetadata{
					KeyId: aws.String("test-key-id"),
				},
			}, nil
		},
		GetPublicKeyFunc: func(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
			return &kms.GetPublicKeyOutput{
				PublicKey: derBytes,
			}, nil
		},
	}

	client := &KMSClient{client: mock}
	keyId, address, err := client.RegisterKey(context.TODO(), "test description")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if keyId != "test-key-id" {
		t.Errorf("Expected test-key-id, got %s", keyId)
	}

	if address != expectedAddress {
		t.Errorf("Expected address %s, got %s", expectedAddress, address)
	}
}

func TestValidateKey(t *testing.T) {
	mock := &mockKMSAPI{
		DescribeKeyFunc: func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			return &kms.DescribeKeyOutput{}, nil
		},
	}

	client := &KMSClient{client: mock}
	valid := client.ValidateKey(context.TODO(), "test-key")
	if !valid {
		t.Errorf("Expected ValidateKey to return true")
	}
}

func TestGetAddressFromKeyId(t *testing.T) {
	_, pubKey, derBytes := generateTestKeys()
	expectedAddress := crypto.PubkeyToAddress(*pubKey).Hex()

	mock := &mockKMSAPI{
		GetPublicKeyFunc: func(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
			return &kms.GetPublicKeyOutput{
				PublicKey: derBytes,
			}, nil
		},
	}

	client := &KMSClient{client: mock}
	address, err := client.GetAddressFromKeyId(context.TODO(), "test-key")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if address != expectedAddress {
		t.Errorf("Expected address %s, got %s", expectedAddress, address)
	}
}
