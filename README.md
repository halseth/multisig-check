# 🔐 P2WSH Multisig Address Verification and Key Possession Toolkit

This repository contains a toolchain for creating, signing, and verifying
_invalid_ Bitcoin native SegWit multisig (`P2WSH`) transactions using Go. This
in order to prove that one can sign for a multisig quorum without signing a
broadcastable transaction.

---

## 🧰 Tools Overview

### 1. `cmd/gen`

Generates:

- A random m-of-n P2WSH multisig setup
- `xpubs.json` — public xpub + derivation path data
- `privkeys.json` — private keys with xpriv, derived WIF keys, and derivation paths
- Prints the derived P2WSH address and redeem script

Used to generate example data for testing, SHOULD NOT be used in a production
setting.

### 2. `cmd/create-unsigned`

Takes:

- The expected P2WSH address
- A 32-byte hex string (essentially the message to sign)
- The `xpubs.json` file
- The `m` threshold value (e.g. 2 for 2-of-3)

Produces:

- An **unsigned transaction hex** spending from that address, sending a dummy
  amount back to the same address. The prevout will be a hash of the random hex
  string provided, meaning the transaction is not valid as a real bitcoin spend.
- Validates that the derived redeem script matches the given address
- Saves **unsigned transaction JSON files** (`unsigned-tx0.json`, `unsigned-tx1.json`, etc.) for each xpub, containing the transaction, derivation path, and redeem script in base64 format

### 3. `cmd/sign`

Signs the transaction from the previous step using:

- `privkeys.json` (private keys with paths)
- Unsigned transaction JSON files (from `cmd/create-unsigned`)
- The P2WSH address

Matches private keys to unsigned transactions based on derivation paths and produces:

- A fully **signed transaction hex** with witness data

### 4. `cmd/verify-signed`

Takes:

- A signed transaction
- The 32-byte hex string from step 2.
- The P2WSH address it spends from
- The redeem script (`redeem.txt`)

Runs:

- Script engine to validate the witness stack

---

## ⚙️ Prerequisites

- Go 1.18+
- OpenSSL (for testing random input)

---

## 🔧 Workflow Example

### ⚙️  Step 1: Generate Keys and Multisig Info

```bash
go run ./cmd/gen
```

Output:
- `xpubs.json`
- `privkeys.json`
- Prints the P2WSH address and redeem script

---

### ⚙️  Step 2: Construct Unsigned Transaction

Generate a random 32-byte hex string:
```bash
HEX=$(openssl rand -hex 32)
```

Run:

```bash
go run ./cmd/create-unsigned \
  -address <P2WSH_ADDRESS> \
  -hex $HEX \
  -xpubs xpubs.json \
  -m 2
```

Output:
- Unsigned TX hex (printed)
- Redeem script hex (printed)
- `unsigned-tx0.json`, `unsigned-tx1.json`, etc. (one per key)

---

### ⚙️ Step 3: Sign Transaction

For a 2-of-3 multisig, sign with the first 2 keys:

```bash
go run ./cmd/sign \
  -address <P2WSH_ADDRESS> \
  -tx unsigned-tx0.json \
  -tx unsigned-tx1.json \
  -privkeys privkeys.json
```

The command matches private keys to unsigned transactions based on their derivation paths. You need to provide as many `-tx` arguments as required signatures (m).

---

### ⚙️  Step 4: Verify Witness Stack

```bash
go run ./cmd/verify-signed \
  -tx <SIGNED_TX_HEX> \
  -hex $HEX \
  -address <P2WSH_ADDRESS> 
```

If valid:

```
✅ Witness verification succeeded.
```

---

## 📁 File Outputs

| File                   | Purpose                                                          |
|------------------------|------------------------------------------------------------------|
| `xpubs.json`           | Public xpubs with derivation paths (used for unsigned tx)        |
| `privkeys.json`        | Private keys with xprivs, derived WIF keys, and paths (for signing) |
| `unsigned-tx*.json`    | Unsigned transaction JSON files (one per key, base64 encoded)    |

---

## 📌 Notes

- The signed tx use a fake prevout from the 32 byte random seed. This ensure
  the the transaction will never be a valid, broadcastable tx. And the the 32
  byte value acts as the message to sign.
- The dummy value in witness stack is required for `OP_CHECKMULTISIG`
- Witness must include exactly `m` signatures
- Amount is hardcoded to 1000 sats (tx is not valid, so doesn't really matter).

---

## 🛠️ TODO / Future Improvements

- PSBT export for hardware wallet signing
- Support regtest / testnet network selection
- File output for unsigned and signed TX hex

---

## 🛡 Disclaimer

This toolchain is for **development and testing only**.
Do not use on mainnet without serious auditing and secure key handling.

MIT License.

