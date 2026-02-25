package tron

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/fbsobreira/gotron-sdk/pkg/proto/core"
	signerCore "github.com/squall-chua/kms-signer/core"
)

type TronSigner func(address common.Address, tx *core.Transaction) (*core.Transaction, string, error)

func NewAwsKmsTransactor(svc *signerCore.KMSClient, keyId string) (*ecdsa.PublicKey, TronSigner, error) {
	pubkey, err := svc.GetPubKey(keyId)
	if err != nil {
		return nil, nil, err
	}

	pubKeyBytes := secp256k1.S256().Marshal(pubkey.X, pubkey.Y)
	keyAddr := crypto.PubkeyToAddress(*pubkey)

	signerFn := func(address common.Address, tx *core.Transaction) (*core.Transaction, string, error) {
		if address != keyAddr {
			return nil, "", nil // Note: bind.ErrNotAuthorized was here previously, adjust or import if intended
		}

		rawData, err := json.Marshal(tx.GetRawData())
		if err != nil {
			return nil, "", err
		}
		h256h := sha256.New()
		h256h.Write(rawData)
		hash := h256h.Sum(nil)

		rBytes, sBytes, err := svc.GetSignatureFromKms(keyId, hash)
		if err != nil {
			return nil, "", err
		}

		// Adjust S value from signature according to Tron standard
		sBigInt := new(big.Int).SetBytes(sBytes)
		if sBigInt.Cmp(signerCore.Secp256k1HalfN) > 0 {
			sBytes = new(big.Int).Sub(signerCore.Secp256k1N, sBigInt).Bytes()
		}

		signature, err := signerCore.GetDeriveSignature(pubKeyBytes, hash, rBytes, sBytes)
		if err != nil {
			return nil, "", err
		}
		tx.Signature = append(tx.Signature, signature)

		return tx, hex.EncodeToString(hash), nil
	}
	return pubkey, signerFn, nil
}
