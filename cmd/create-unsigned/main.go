package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type XpubDerivation struct {
	Xpub string `json:"xpub"`
	Path string `json:"path"`
}

func parseDerivationPath(path string) ([]uint32, error) {
	if path == "" {
		return nil, fmt.Errorf("empty derivation path")
	}
	segs := strings.Split(path, "/")
	var out []uint32
	for _, s := range segs {
		var i uint32
		_, err := fmt.Sscanf(s, "%d", &i)
		if err != nil {
			return nil, fmt.Errorf("invalid path segment %q: %w", s, err)
		}
		out = append(out, i)
	}
	return out, nil
}

func main() {
	var addressStr string
	var hexStr string
	var xpubFile string
	var threshold int

	flag.StringVar(&addressStr, "address", "", "P2WSH Bitcoin address to verify")
	flag.StringVar(&hexStr, "hex", "", "32-byte hex string (for double SHA256 prevout)")
	flag.StringVar(&xpubFile, "xpubs", "", "Path to xpubs.json")
	flag.IntVar(&threshold, "threshold", 2, "Multisig threshold (e.g. 2-of-3)")
	flag.Parse()

	if addressStr == "" || hexStr == "" || xpubFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	if err := run(addressStr, hexStr, xpubFile, threshold); err != nil {
		log.Fatalf("❌ Error: %v", err)
	}
}

func run(addressStr, hexStr, xpubPath string, threshold int) error {
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
		extKey, err := hdkeychain.NewKeyFromString(x.Xpub)
		if err != nil {
			return fmt.Errorf("invalid xpub: %w", err)
		}

		path, err := parseDerivationPath(x.Path)
		if err != nil {
			return fmt.Errorf("invalid path %q: %w", x.Path, err)
		}

		for _, i := range path {
			extKey, err = extKey.Derive(i)
			if err != nil {
				return fmt.Errorf("error deriving child key: %w", err)
			}
		}

		pubKey, err := extKey.ECPubKey()
		if err != nil {
			return fmt.Errorf("error getting pubkey: %w", err)
		}
		addrPubKey, err := btcutil.NewAddressPubKey(pubKey.SerializeCompressed(), &chaincfg.MainNetParams)
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
	witnessProg := sha256.Sum256(redeemScript)
	addr, err := btcutil.NewAddressWitnessScriptHash(witnessProg[:], &chaincfg.MainNetParams)
	if err != nil {
		return fmt.Errorf("failed to derive P2WSH address: %w", err)
	}

	if addr.EncodeAddress() != addressStr {
		return fmt.Errorf("address mismatch: derived %s != expected %s", addr.EncodeAddress(), addressStr)
	}
	fmt.Println("✅ Address verification successful.")

	// Compute double SHA256 of the input hex string to simulate txid
	rawBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return fmt.Errorf("invalid hex string: %w", err)
	}
	h := sha256.Sum256(rawBytes)
	hh := sha256.Sum256(h[:])
	txid := chainhash.Hash(hh)

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

	fmt.Printf("Unsigned TX (hex): %x\n", buf.Bytes())
	return nil
}
