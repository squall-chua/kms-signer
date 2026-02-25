package core

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/asn1"
	"encoding/hex"
	"math/big"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmsTypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
)

var keyCache = newPubKeyCache()

var Secp256k1N = crypto.S256().Params().N
var Secp256k1HalfN = new(big.Int).Div(Secp256k1N, big.NewInt(2))

type asn1EcPublicKey struct {
	EcPublicKeyInfo asn1EcPublicKeyInfo
	PublicKey       asn1.BitString
}

type asn1EcPublicKeyInfo struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.ObjectIdentifier
}

type asn1EcSig struct {
	R asn1.RawValue
	S asn1.RawValue
}

func (k *KMSClient) getPublicKeyDerBytesFromKMS(keyId string) ([]byte, error) {
	getPubKeyOutput, err := k.GetPublicKey(
		context.Background(),
		&kms.GetPublicKeyInput{
			KeyId: aws.String(keyId),
		})
	if err != nil {
		return nil, errors.Wrapf(err, "can not get public key from KMS for KeyId=%s", keyId)
	}

	var asn1pubk asn1EcPublicKey
	_, err = asn1.Unmarshal(getPubKeyOutput.PublicKey, &asn1pubk)
	if err != nil {
		return nil, errors.Wrapf(err, "can not parse asn1 public key for KeyId=%s", keyId)
	}

	return asn1pubk.PublicKey.Bytes, nil
}

func (k *KMSClient) GetSignatureFromKms(keyId string, txHashBytes []byte) ([]byte, []byte, error) {
	signInput := &kms.SignInput{
		KeyId:            aws.String(keyId),
		SigningAlgorithm: kmsTypes.SigningAlgorithmSpecEcdsaSha256,
		MessageType:      kmsTypes.MessageTypeDigest,
		Message:          txHashBytes,
	}

	signOutput, err := k.Sign(context.Background(), signInput)
	if err != nil {
		return nil, nil, err
	}

	var sigAsn1 asn1EcSig
	_, err = asn1.Unmarshal(signOutput.Signature, &sigAsn1)
	if err != nil {
		return nil, nil, err
	}

	return sigAsn1.R.Bytes, sigAsn1.S.Bytes, nil
}

func GetDeriveSignature(expectedPublicKeyBytes []byte, txHash []byte, r []byte, s []byte) ([]byte, error) {
	rsSignature := append(adjustSignatureLength(r), adjustSignatureLength(s)...)
	signature := append(rsSignature, []byte{0}...)

	recoveredPublicKeyBytes, err := crypto.Ecrecover(txHash, signature)
	if err != nil {
		return nil, err
	}

	if hex.EncodeToString(recoveredPublicKeyBytes) != hex.EncodeToString(expectedPublicKeyBytes) {
		signature = append(rsSignature, []byte{1}...)
		recoveredPublicKeyBytes, err = crypto.Ecrecover(txHash, signature)
		if err != nil {
			return nil, err
		}

		if hex.EncodeToString(recoveredPublicKeyBytes) != hex.EncodeToString(expectedPublicKeyBytes) {
			return nil, errors.New("can not reconstruct public key from sig")
		}
	}

	return signature, nil
}

func (k *KMSClient) GetPubKey(keyId string) (*ecdsa.PublicKey, error) {
	pubkey := keyCache.Get(keyId)

	if pubkey == nil {
		pubKeyBytes, err := k.getPublicKeyDerBytesFromKMS(keyId)
		if err != nil {
			return nil, err
		}

		pubkey, err = crypto.UnmarshalPubkey(pubKeyBytes)
		if err != nil {
			return nil, errors.Wrap(err, "can not construct secp256k1 public key from key bytes")
		}
		keyCache.Add(keyId, pubkey)
	}
	return pubkey, nil
}

func adjustSignatureLength(buffer []byte) []byte {
	buffer = bytes.TrimLeft(buffer, "\x00")
	for len(buffer) < 32 {
		zeroBuf := []byte{0}
		buffer = append(zeroBuf, buffer...)
	}
	return buffer
}
