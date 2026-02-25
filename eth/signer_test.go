package eth

import (
	"context"
	"crypto/ecdsa"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/squall-chua/kms-signer/core"
)

type mockKMSAPI struct {
	GetPublicKeyFunc func(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	SignFunc         func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
}

func (m *mockKMSAPI) CreateKey(ctx context.Context, params *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
	return nil, nil
}
func (m *mockKMSAPI) DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	return nil, nil
}
func (m *mockKMSAPI) GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	return m.GetPublicKeyFunc(ctx, params, optFns...)
}
func (m *mockKMSAPI) Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
	return m.SignFunc(ctx, params, optFns...)
}

func TestNewAwsKmsTransactorWithChainID(t *testing.T) {
	privateKey, _ := crypto.GenerateKey()
	pubKey := privateKey.Public().(*ecdsa.PublicKey)
	pubKeyBytes := crypto.FromECDSAPub(pubKey)

	// Convert to ASN1 as KMS returns
	type asn1EcPublicKeyInfo struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.ObjectIdentifier
	}
	type asn1EcPublicKey struct {
		EcPublicKeyInfo asn1EcPublicKeyInfo
		PublicKey       asn1.BitString
	}
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

	mock := &mockKMSAPI{
		GetPublicKeyFunc: func(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
			return &kms.GetPublicKeyOutput{
				PublicKey: derBytes,
			}, nil
		},
		SignFunc: func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
			signature, _ := crypto.Sign(params.Message, privateKey)
			type asn1EcSig struct {
				R asn1.RawValue
				S asn1.RawValue
			}
			sigAsn1 := asn1EcSig{
				R: asn1.RawValue{Class: 0, Tag: 2, IsCompound: false, Bytes: signature[:32]},
				S: asn1.RawValue{Class: 0, Tag: 2, IsCompound: false, Bytes: signature[32:64]},
			}
			sigDerBytes, _ := asn1.Marshal(sigAsn1)
			return &kms.SignOutput{
				Signature: sigDerBytes,
			}, nil
		},
	}
	client := core.NewKMSClient(mock)

	chainID := big.NewInt(1)
	opts, err := NewAwsKmsTransactorWithChainID(client, "test-key-id", chainID)
	if err != nil {
		t.Fatalf("Failed to create transactor: %v", err)
	}

	if opts.From != crypto.PubkeyToAddress(*pubKey) {
		t.Errorf("Expected address %s, got %s", crypto.PubkeyToAddress(*pubKey).Hex(), opts.From.Hex())
	}

	// Test signing
	tx := types.NewTransaction(0, crypto.PubkeyToAddress(*pubKey), big.NewInt(0), 0, big.NewInt(0), nil)
	signedTx, err := opts.Signer(opts.From, tx)
	if err != nil {
		t.Fatalf("Failed to sign transaction: %v", err)
	}
	if signedTx == nil {
		t.Errorf("Expected signed transaction")
	}
}
