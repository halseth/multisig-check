# 🔐 P2WSH Multisig Address & Unsigned Transaction Toolkit

This repository provides three Go command-line tools to:

1. Generate a **2-of-3 P2WSH multisig address** and test data.
2. Construct and verify an **unsigned Bitcoin transaction** spending from the generated address.
3. Verify the **witness of a signed transaction** spending from the multisig address.

---

## 📁 Tools

### 1. `gen_multisig_test_data.go`

Generates:

- A random **2-of-3 multisig P2WSH address**
- 3 `xpub`s with matching `0/0` derivation paths
- The **redeem script** used to compute the address

### 2. `multisig_tx_tool.go`

Verifies:

- That the given `xpubs + derivation paths` correctly reconstruct the expected P2WSH address

Creates:

- An **unsigned Bitcoin transaction** spending from that address
- The `prevout` is a **double SHA256 of a 32-byte hex input**
- The transaction **pays back** to the same multisig address

### 3. `verify_multisig_witness.go`

Verifies:

- That the **witness on a signed P2WSH transaction** is valid
- Takes a signed tx hex, a P2WSH address, the redeem script, and the amount being spent

---

## 🚀 Prerequisites

- Go 1.18+
- Git and bash-compatible shell

Install dependencies (optional, but these are used under the hood):
```bash
go get github.com/btcsuite/btcd
go get github.com/btcsuite/btcutil
```

---

## 🔧 Usage

### ✅ Step 1: Generate Test Data

```bash
go run gen_multisig_test_data.go
```

#### 🔎 Output Example:

```
=== ✅ Multisig Test Vector ===
P2WSH Address: bc1qxyzabc...

JSON Xpubs:
[
  {
    "xpub": "xpub6CUGRUonZSQ4TWtTMmz...",
    "path": "0/0"
  },
  ...
]

Redeem Script (hex):
522103...ae
```

Copy the **address**, **JSON xpubs**, and **redeem script** for the next step.

---

### ✅ Step 2: Run Verification & TX Tool

Generate a 32-byte hex value (used to construct a fake txid):

```bash
HEX=$(openssl rand -hex 32)
```

Then run:

```bash
go run multisig_tx_tool.go \
  -address <P2WSH_ADDRESS_FROM_STEP_1> \
  -hex $HEX \
  -xpubs '<PASTE_JSON_FROM_STEP_1>' \
  -threshold 2
```

#### 💡 Example

```bash
go run multisig_tx_tool.go \
  -address bc1qxyzabc... \
  -hex 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  -xpubs '[{"xpub":"xpub6...","path":"0/0"},{"xpub":"xpub6...","path":"0/0"},{"xpub":"xpub6...","path":"0/0"}]' \
  -threshold 2
```

This produces an unsigned tx hex.

---

### ✅ Step 3: Sign the Transaction (external)

Use your preferred Bitcoin signer (e.g. HWI, Specter, Core) to sign the unsigned tx created in Step 2. Once signed, you'll have the **signed tx hex**.

---

### ✅ Step 4: Verify the Witness

```bash
go run verify_multisig_witness.go \
  -tx <SIGNED_TX_HEX> \
  -address <P2WSH_ADDRESS> \
  -redeem <REDEEM_SCRIPT_HEX> \
  -amount <AMOUNT_IN_SATS>
```

#### 💡 Example

```bash
go run verify_multisig_witness.go \
  -tx 010000000001... \
  -address bc1qxyzabc... \
  -redeem 522103...ae \
  -amount 1000
```

### 🟢 Output

```
✅ Witness verification succeeded.
```

Or:

```
❌ Witness verification failed: <reason>
```

---

## 📌 Notes

- The transaction created in Step 2 is **unsigned** and **non-broadcastable** until signed.
- `verify_multisig_witness.go` is useful for **testing or verifying signature correctness** without relying on full nodes.
- Amounts are set to **1000 sats (dummy)** in test transactions. Adjust as needed.

---

## 🛠 Future Improvements

- PSBT output for signing tools
- Import/export mnemonic + HD path flexibility
- Auto-detect redeem script from witness
- Add regtest/testnet support toggle

---

## 📄 License

MIT License. Use at your own risk—testnet only unless extended with secure key handling!

