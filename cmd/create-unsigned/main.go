package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

var PREVOUT_PREFIX = []byte("txid random prefix")

type XpubDerivation struct {
	Xpub   string `json:"xpub"`
	Path   string `json:"path"`
	Pubkey string `json:"pubkey"`
}

type JSON struct {
	Path       string   `json:"path"`
	Tx         string   `json:"tx"`          // standard (non-url safe) base64
	VinValues  []uint64 `json:"vin_values"`  // nullable
	ScriptSigs []string `json:"script_sigs"` // standard (non-url safe) base64s
}

func main() {
	var (
		hexStr    string
		xpubFile  string
		threshold int
	)

	flag.StringVar(&hexStr, "hex", "", "32-byte random hex string (to use as seed for prevout)")
	flag.StringVar(&xpubFile, "xpubs", "", "Path to xpubs.json")
	flag.IntVar(&threshold, "m", 2, "m: Multisig threshold (e.g. 2-of-3)")
	flag.Parse()

	if threshold <= 0 || hexStr == "" || xpubFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	if err := run(hexStr, xpubFile, threshold); err != nil {
		log.Fatalf("❌ Error: %v", err)
	}
}

func run(hexStr, xpubPath string, threshold int) error {
	data, err := ioutil.ReadFile(xpubPath)
	if err != nil {
		return fmt.Errorf("failed to read xpub file: %w", err)
	}

	var xpubs []XpubDerivation
	if err := json.Unmarshal(data, &xpubs); err != nil {
		return fmt.Errorf("failed to parse xpubs JSON: %w", err)
	}

	var pubKeys []*btcutil.AddressPubKey
	for _, x := range xpubs {
		// Decode the hex pubkey directly
		pubkeyBytes, err := hex.DecodeString(x.Pubkey)
		if err != nil {
			return fmt.Errorf("invalid pubkey hex %q: %w", x.Pubkey, err)
		}

		// Create AddressPubKey from the compressed pubkey bytes
		addrPubKey, err := btcutil.NewAddressPubKey(pubkeyBytes, &chaincfg.MainNetParams)
		if err != nil {
			return fmt.Errorf("error creating AddressPubKey: %w", err)
		}
		pubKeys = append(pubKeys, addrPubKey)
	}

	// Build redeem script and verify address
	redeemScript, err := txscript.MultiSigScript(pubKeys, threshold)
	if err != nil {
		return fmt.Errorf("failed to create multisig script: %w", err)
	}
	redeemHex := hex.EncodeToString(redeemScript)

	witnessProg := sha256.Sum256(redeemScript)
	addr, err := btcutil.NewAddressWitnessScriptHash(witnessProg[:], &chaincfg.MainNetParams)
	if err != nil {
		return fmt.Errorf("failed to derive P2WSH address: %w", err)
	}

	// Compute SHA256 of the input hex string to simulate txid
	// To ensure real transaction data cannot be inserted here, we prepend the message with a fixed string.
	rawBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return fmt.Errorf("invalid hex string: %w", err)
	}

	b := PREVOUT_PREFIX[:]
	b = append(b, rawBytes...)

	h := sha256.Sum256(b)
	txid := chainhash.Hash(h)

	outpoint := wire.NewOutPoint(&txid, 0)

	tx := wire.NewMsgTx(wire.TxVersion)
	txIn := wire.NewTxIn(outpoint, nil, nil)
	tx.AddTxIn(txIn)

	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return fmt.Errorf("failed to create pkScript: %w", err)
	}
	txOut := wire.NewTxOut(1000, pkScript) // dummy amount
	tx.AddTxOut(txOut)

	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return fmt.Errorf("failed to serialize transaction: %w", err)
	}

	txHash := tx.TxHash()

	fmt.Printf("Unsigned TX (hex): %x\n", buf.Bytes())
	fmt.Printf("Unsigned TX (base64): %s\n", base64.StdEncoding.EncodeToString(buf.Bytes()))
	fmt.Printf("TX Hash: %s\n", txHash.String())
	fmt.Printf("Redeem Script (hex): %s\n", redeemHex)
	fmt.Printf("Address: %s\n", addr.EncodeAddress())

	for i, x := range xpubs {
		jsonBytes := createJson(x.Path, buf.Bytes(), redeemScript)

		jsonName := fmt.Sprintf("unsigned-tx%d.json", i)
		if err := os.WriteFile(jsonName, jsonBytes, 0644); err != nil {
			return fmt.Errorf("failed to write unsigned-tx.json: %w",
				err)
		}

		fmt.Println("→ tx written to :", jsonName)
	}

	return nil
}

func createJson(path string, txBytes, redeemScript []byte) []byte {
	b64 := base64.StdEncoding

	scriptSigs := make([]string, 1)
	scriptSigs[0] = b64.EncodeToString(redeemScript)

	j := JSON{
		Path:       path,
		Tx:         b64.EncodeToString(txBytes),
		VinValues:  []uint64{1000},
		ScriptSigs: scriptSigs,
	}

	jsonBytes, _ := json.Marshal(j)

	return jsonBytes
}
