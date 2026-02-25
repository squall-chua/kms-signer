package core

import (
	"context"
	"encoding/asn1"
	"encoding/hex"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestGetPubKey(t *testing.T) {
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

	// Make sure cache is empty for this key ID
	keyCache.mutex.Lock()
	delete(keyCache.pubKeys, "test-key")
	keyCache.mutex.Unlock()

	fetchedPubKey, err := client.GetPubKey("test-key")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	fetchedAddress := crypto.PubkeyToAddress(*fetchedPubKey).Hex()
	if fetchedAddress != expectedAddress {
		t.Errorf("Expected address %s, got %s", expectedAddress, fetchedAddress)
	}

	// Test cache
	cachedPubKey := keyCache.Get("test-key")
	if cachedPubKey == nil {
		t.Errorf("Expected public key to be cached")
	}
}

func TestGetSignatureFromKms(t *testing.T) {
	mock := &mockKMSAPI{
		SignFunc: func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {

			// Mock a DER encoded ECDSA signature for testing Unmarshal
			// To make it easy, we just supply a valid dummy ASN1 struct
			sigAsn1 := asn1EcSig{
				R: asn1.RawValue{Class: 0, Tag: 2, IsCompound: false, Bytes: []byte{1, 2, 3}},
				S: asn1.RawValue{Class: 0, Tag: 2, IsCompound: false, Bytes: []byte{4, 5, 6}},
			}
			derBytes, _ := asn1.Marshal(sigAsn1)

			return &kms.SignOutput{
				Signature: derBytes,
			}, nil
		},
	}

	client := &KMSClient{client: mock}
	r, s, err := client.GetSignatureFromKms("test-key", []byte("testhash"))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(r) != 3 || len(s) != 3 {
		t.Errorf("Expected R and S length 3, got R:%d S:%d", len(r), len(s))
	}
}

func TestGetDeriveSignature(t *testing.T) {
	privateKey, pubKey, _ := generateTestKeys()
	pubKeyBytes := crypto.FromECDSAPub(pubKey)

	txHash := crypto.Keccak256([]byte("hello world"))

	// Sign via go-ethereum to get a valid V (0 or 1)
	signature, err := crypto.Sign(txHash, privateKey)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	r := signature[:32]
	s := signature[32:64]

	// Use GetDeriveSignature to find V
	derivedSig, err := GetDeriveSignature(pubKeyBytes, txHash, r, s)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(derivedSig) != 65 {
		t.Fatalf("Expected derived signature length 65, got %d", len(derivedSig))
	}

	recoveredPubKey, err := crypto.Ecrecover(txHash, derivedSig)
	if err != nil {
		t.Fatalf("Failed to ecrecover: %v", err)
	}

	if hex.EncodeToString(recoveredPubKey) != hex.EncodeToString(pubKeyBytes) {
		t.Errorf("Recovered pubkey doesn't match")
	}
}
