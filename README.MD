# Uledger SDK for Go

## Installation

```bash
go get github.com/ULedgerInc/golang-sdk
```

## Usage Examples

### Generating a wallet

This generates a new wallet using the secp256k1 algorithm and saves it to the specified output folder.
Auth provides an optional parameter to set authority groups for the wallet, such as "wallet" or "admin".

```bash
go run examples/generate_wallets/main.go --keyType=secp256k1 --output=./wallets --auth='{"wallet":{"update":true}}'
```

Additionally you can pipe the output directly to the register wallet command:

```bash
go run examples/generate_wallets/main.go | xargs -I {} go run examples/register_wallets/main.go --blockchain=08c28f29a62819120958984b761ddf8ccb45951612731409873994958fd150a2 --node=https://node.example.com -i '{}'
```

Because this loses the private key, it is recommended to save the output to a file first.

### Registering a wallet

This registers all wallets in the /wallets folder to the target blockchain.

```bash
go run examples/register_wallets/main.go --blockchain=08c28f29a62819120958984b761ddf8ccb45951612731409873994958fd150a2 --node=https://node.example.com
```

### Altering a wallet

This sends the wallet data found in the /wallets folder to the target blockchain as an alter wallet transaction.
It is perfectly legal to author a transaction that results in no change to a wallet.

```bash
go run examples/alter_wallets/main.go --target=fd97f868cf2bb29caa4703c79113ca0deb8f4e3110102e378d9d171254eec2aa --blockchain=08c28f29a62819120958984b761ddf8ccb45951612731409873994958fd150a2 --node=https://node.example.com
```
