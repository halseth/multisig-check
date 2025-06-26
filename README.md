# 🔐 P2WSH Multisig Address Verification Key Possession  Toolkit

This repository contains a toolchain for creating, signing, and verifying _invalid_ Bitcoin native SegWit multisig (`P2WSH`) transactions using Go. This in order to prove that one can sign for a multisig quorum without signing a broadcastable transaction.

---

## 🧰 Tools Overview

### 1. `cmd/gen`

Generates:

- A random m-of-n P2WSH multisig setup
- `xpubs.json` — public xpub + derivation path data
- `privkeys.json` — private keys in WIF format
- Prints the derived P2WSH address and redeem script

Used to generate example data for testing, SHOULD NOT be used in a production setting.

### 2. `cmd/create-unsigned`

Takes:

- The expected P2WSH address
- A 32-byte hex string (essentially the message to sign)
- The `xpubs.json` file
- The `m` threshold value (e.g. 2 for 2-of-3)

Produces:

- An **unsigned transaction hex** spending from that address, sending a dummy amount back to the same address. The prevout will be a hash of the random hex string prvided, meaning the transaction is not valid as a real bitcoin spend.
- Validates that the derived redeem script matches the given address
- Saves the `redeem script` as `redeem.txt`

### 3. `sign_multisig_tx.go`

Signs the transaction using:

- `privkeys.json` (private keys)
- The redeem script (from `redeem.txt`)
- The unsigned transaction hex
- The UTXO amount
- The `threshold` number of required signatures

Produces:

- A fully **signed transaction hex**

### 4. `verify_multisig_witness.go`

Takes:

- A signed transaction
- The P2WSH address it spends from
- The redeem script (`redeem.txt`)
- The UTXO amount

Runs:

- Script engine to validate the witness stack

---

## ⚙️ Prerequisites

- Go 1.18+
- OpenSSL (for testing random input)
- `btcd` libraries:

```bash
go get github.com/btcsuite/btcd
go get github.com/btcsuite/btcutil
```

---

## 🔧 Workflow Example

### ✅ Step 1: Generate Keys and Multisig Info

```bash
go run gen_multisig_test_data.go
```

Output:
- `xpubs.json`
- `privkeys.json`
- Prints the P2WSH address and redeem script

---

### ✅ Step 2: Construct Unsigned Transaction

Generate a random 32-byte hex string:
```bash
HEX=$(openssl rand -hex 32)
```

Run:

```bash
go run multisig_tx_tool.go \
  -address <P2WSH_ADDRESS> \
  -hex $HEX \
  -xpubs xpubs.json \
  -threshold 2
```

Output:
- Unsigned TX hex (printed)
- `redeem.txt` file

---

### ✅ Step 3: Sign Transaction

```bash
go run sign_multisig_tx.go \
  -tx <UNSIGNED_TX_HEX> \
  -redeem $(cat redeem.txt) \
  -privkeys privkeys.json \
  -amount 1000 \
  -threshold 2
```

Only the first `N` private keys (matching the threshold) will be used.

---

### ✅ Step 4: Verify Witness Stack

```bash
go run verify_multisig_witness.go \
  -tx <SIGNED_TX_HEX> \
  -address <P2WSH_ADDRESS> \
  -redeem $(cat redeem.txt) \
  -amount 1000
```

If valid:

```
✅ Witness verification succeeded.
```

If broken:

```
❌ Witness verification failed: multisig dummy argument has length 72 instead of 0
```

---

## 📁 File Outputs

| File           | Purpose                                |
|----------------|----------------------------------------|
| `xpubs.json`   | Public metadata (used for unsigned tx) |
| `privkeys.json`| Private keys (used for signing)        |
| `redeem.txt`   | Redeem script in hex (used in all steps) |

---

## 📌 Notes

- All txs use a fake prevout: `double_sha256(hex input)`
- The dummy value in witness stack is required for `OP_CHECKMULTISIG`
- Witness must include exactly `threshold` signatures
- Amount is hardcoded to 1000 sats (for test/demo)

---

## 🛠️ TODO / Future Improvements

- PSBT export for hardware wallet signing
- Support regtest / testnet network selection
- File output for unsigned and signed TX hex
- Auto-signing via mnemonic phrase or HSM

---

## 🛡 Disclaimer

This toolchain is for **development and testing only**.
Do not use on mainnet without serious auditing and secure key handling.

MIT License.

