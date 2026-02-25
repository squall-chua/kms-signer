package eth

import (
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/squall-chua/kms-signer/core"
)

func NewAwsKmsTransactorWithChainID(svc *core.KMSClient, keyId string, chainID *big.Int) (*bind.TransactOpts, error) {
	pubkey, err := svc.GetPubKey(keyId)
	if err != nil {
		return nil, err
	}

	pubKeyBytes := secp256k1.S256().Marshal(pubkey.X, pubkey.Y)

	keyAddr := crypto.PubkeyToAddress(*pubkey)
	if chainID == nil {
		return nil, bind.ErrNoChainID
	}

	signer := types.LatestSignerForChainID(chainID)

	signerFn := func(address common.Address, tx *types.Transaction) (*types.Transaction, error) {
		if address != keyAddr {
			return nil, bind.ErrNotAuthorized
		}

		txHashBytes := signer.Hash(tx).Bytes()

		rBytes, sBytes, err := svc.GetSignatureFromKms(keyId, txHashBytes)
		if err != nil {
			return nil, err
		}

		// Adjust S value from signature according to Ethereum standard
		sBigInt := new(big.Int).SetBytes(sBytes)
		if sBigInt.Cmp(core.Secp256k1HalfN) > 0 {
			sBytes = new(big.Int).Sub(core.Secp256k1N, sBigInt).Bytes()
		}

		signature, err := core.GetDeriveSignature(pubKeyBytes, txHashBytes, rBytes, sBytes)
		if err != nil {
			return nil, err
		}

		return tx.WithSignature(signer, signature)
	}

	return &bind.TransactOpts{
		From:   keyAddr,
		Signer: signerFn,
	}, nil
}
