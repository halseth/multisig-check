package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"strings"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

var PREVOUT_PREFIX = []byte("txid random prefix")

func decodeTx(txHex string) (*wire.MsgTx, error) {
	raw, err := hex.DecodeString(txHex)
	if err != nil {
		return nil, fmt.Errorf("invalid tx hex: %w", err)
	}
	tx := wire.NewMsgTx(wire.TxVersion)
	if err := tx.Deserialize(strings.NewReader(string(raw))); err != nil {
		return nil, fmt.Errorf("failed to deserialize tx: %w", err)
	}
	return tx, nil
}

func getScriptPubKeyFromAddress(address string) ([]byte, error) {
	addr, err := btcutil.DecodeAddress(address, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to decode address: %w", err)
	}
	if _, ok := addr.(*btcutil.AddressWitnessScriptHash); !ok {
		return nil, errors.New("address must be a P2WSH address")
	}
	script, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to create scriptPubKey: %w", err)
	}
	return script, nil
}

func main() {
	var (
		txHex      string
		hexStr     string
		address    string
		amountSats int64 = 1000
	)

	flag.StringVar(&txHex, "tx", "", "Signed transaction hex")
	flag.StringVar(&hexStr, "hex", "", "32-byte random hex string (for double SHA256 prevout)")
	flag.StringVar(&address, "address", "", "P2WSH address being spent from")
	flag.Parse()

	if hexStr == "" || txHex == "" || address == "" || amountSats <= 0 {
		flag.Usage()
		log.Fatal("All flags are required")
	}

	tx, err := decodeTx(txHex)
	if err != nil {
		log.Fatalf("❌ Transaction decode error: %v", err)
	}

	fmt.Println("Witness stack:")
	for i, w := range tx.TxIn[0].Witness {
		fmt.Printf("  [%d] %x (len=%d)\n", i, w, len(w))
	}

	if len(tx.TxIn) == 0 {
		log.Fatal("❌ No inputs in transaction")
	}

	// Ensure the outppoint points to the given hex string.
	rawBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		log.Fatal("❌ invalid hex string: %w", err)
	}

	b := PREVOUT_PREFIX[:]
	b = append(b, rawBytes...)

	h := sha256.Sum256(b)
	txid := chainhash.Hash(h)

	outpoint := wire.NewOutPoint(&txid, 0)
	if tx.TxIn[0].PreviousOutPoint != *outpoint {
		log.Fatal("❌ wrong prevout")
	}

	scriptPubKey, err := getScriptPubKeyFromAddress(address)
	if err != nil {
		log.Fatalf("❌ ScriptPubKey error: %v", err)
	}

	prevOutFetcher := txscript.NewCannedPrevOutputFetcher(
		scriptPubKey, amountSats,
	)

	sigHashes := txscript.NewTxSigHashes(tx, prevOutFetcher)

	inputIndex := 0
	vm, err := txscript.NewEngine(
		scriptPubKey,
		tx,
		inputIndex,
		txscript.StandardVerifyFlags,
		nil,
		sigHashes,
		amountSats,
		prevOutFetcher,
	)
	if err != nil {
		log.Fatalf("❌ Failed to create script engine: %v", err)
	}

	if err := vm.Execute(); err != nil {
		log.Fatalf("❌ Witness verification failed: %v", err)
	}

	fmt.Println("✅ Witness verification succeeded.")
}
