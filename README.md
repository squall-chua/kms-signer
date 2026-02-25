# KMS Signer

`kms-signer` provides a clean, subpackage-based approach to signing transactions using AWS Key Management Service (KMS) for different blockchain networks. The ECDSA signatures generated via AWS KMS are natively compatible with networks like Ethereum and Tron.

## Installation

```bash
go get github.com/squall-chua/kms-signer
```

## Structure

- `core`: Shared operations to fetch KMS keys and construct signatures.
- `eth`: An AWS KMS Transaction Signer for Ethereum. Provides `NewAwsKmsTransactorWithChainID` to create a `bind.TransactOpts`.
- `tron`: An AWS KMS Transaction Signer for Tron. Provides `NewAwsKmsTransactor` returning a `TronSigner`.

---

## Usage Examples

### Key Management

To create, validate, and retrieve addresses from KMS keys, use the `core.KMSClient`:

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/squall-chua/kms-signer/core"
)

func main() {
	// Initialize AWS KMS client
	kmsSvc, err := core.InitKMSWithProfile(context.TODO(), "us-east-1", "default", map[string]string{})
	if err != nil {
		log.Fatalf("failed to init KMS: %v", err)
	}

	// 1. Register a new key
	walletDescription := "My new test wallet"
	keyID, address, err := kmsSvc.RegisterKey(context.TODO(), walletDescription)
	if err != nil {
		log.Fatalf("failed to register key: %v", err)
	}
	fmt.Printf("Registered Key ID: %s, Address: %s\n", keyID, address)

	// 2. Validate an existing key
	isValid := kmsSvc.ValidateKey(context.TODO(), keyID)
	fmt.Printf("Is Key Valid? %t\n", isValid)

	// 3. Get Address from an existing Key ID
	retrievedAddress, err := kmsSvc.GetAddressFromKeyId(context.TODO(), keyID)
	if err != nil {
		log.Fatalf("failed to get address: %v", err)
	}
	fmt.Printf("Retrieved Address: %s\n", retrievedAddress)
}
```

### Ethereum

To sign an Ethereum transaction using AWS KMS, use the `eth` package:

```go
package main

import (
	"context"
	"fmt"
	"log"
	"math/big"

	"github.com/squall-chua/kms-signer/core"
	"github.com/squall-chua/kms-signer/eth"
)

func main() {
	// Initialize AWS KMS client
	kmsSvc, err := core.InitKMSWithProfile(context.TODO(), "us-east-1", "default", map[string]string{})
	if err != nil {
		log.Fatalf("failed to init KMS: %v", err)
	}
	keyID := "your-kms-key-id"

	// Look up address for key identity
	address, err := kmsSvc.GetAddressFromKeyId(context.TODO(), keyID)
	if err != nil {
		log.Fatalf("failed to fetch address: %v", err)
	}
	fmt.Printf("Wallet Address: %s\n", address)

	// Set chain ID (e.g., Ethereum Mainnet = 1)
	chainID := big.NewInt(1)

	// Create Ethereum Transactor
	transactor, err := eth.NewAwsKmsTransactorWithChainID(kmsSvc, keyID, chainID)
	if err != nil {
		log.Fatalf("failed to create transactor: %v", err)
	}

	// The transactor can now be used with go-ethereum's abigen bindings
	// e.g., myContract.Transfer(transactor, toAddress, amount)
	_ = transactor // Use transactor
}
```

### Tron

To sign a Tron transaction using AWS KMS, use the `tron` package:

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/squall-chua/kms-signer/core"
	"github.com/squall-chua/kms-signer/tron"
	"github.com/fbsobreira/gotron-sdk/pkg/client"
)

func main() {
	// Initialize AWS KMS client
	kmsSvc, err := core.InitKMSWithProfile(context.TODO(), "us-east-1", "default", map[string]string{})
	if err != nil {
		log.Fatalf("failed to init KMS: %v", err)
	}
	keyID := "your-kms-key-id"

	// Look up address for key identity
	address, err := kmsSvc.GetAddressFromKeyId(context.TODO(), keyID)
	if err != nil {
		log.Fatalf("failed to fetch address: %v", err)
	}
	fmt.Printf("Wallet Address: %s\n", address)

	// Create Tron Signer
	pubKey, signerFn, err := tron.NewAwsKmsTransactor(kmsSvc, keyID)
	if err != nil {
		log.Fatalf("failed to create Tron signer: %v", err)
	}

	fmt.Printf("Public Key: %x\n", pubKey)

	// You can use the signerFn to sign a constructed `core.Transaction`
	// signedTx, txHash, err := signerFn(address, unsignedTx)
	_ = signerFn // Use signer function
}
```

### Testing / Local Development

If you are developing locally or in a CI/CD environment where accessing actual AWS KMS is not feasible, you can use [local-kms](https://github.com/nsmithuk/local-kms) to mock the KMS endpoints.

To use `local-kms` with `kms-signer`, you just need to pass the local endpoint URL to the `kmsUrl` parameter in `core.InitKMS`. The SDK will be configured automatically with dummy credentials to communicate with the local instance.

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/squall-chua/kms-signer/core"
)

func main() {
	// Initialize AWS KMS client with local-kms endpoint
	// Assuming local-kms is running on the default port 8080
	localKmsUrl := "http://localhost:8080"
	
	kmsSvc, err := core.InitLocalKMS(context.TODO(), localKmsUrl, map[string]string{})
	if err != nil {
		log.Fatalf("failed to init local KMS: %v", err)
	}

	// 1. Register a new key in local-kms
	walletDescription := "My local test wallet"
	keyID, address, err := kmsSvc.RegisterKey(context.TODO(), walletDescription)
	if err != nil {
		log.Fatalf("failed to register key: %v", err)
	}
	fmt.Printf("Registered Local Key ID: %s, Address: %s\n", keyID, address)

	// You can now proceed to use this local KMS client with the eth or tron packages
	// just like you would with the real AWS KMS.
}
```
