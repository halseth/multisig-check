package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type PrivData struct {
	PrivKeyWIF string `json:"derived_priv"`
	Path       string `json:"path"`
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
		address    string
		txHex      string
		redeemHex  string
		privFile   string
		threshold  int
		amountSats int64 = 1000
	)

	flag.StringVar(&address, "address", "", "P2WSH address being spent from")
	flag.StringVar(&txHex, "tx", "", "Unsigned transaction hex")
	flag.StringVar(&redeemHex, "redeem", "", "Redeem script hex")
	flag.StringVar(&privFile, "privkeys", "", "Path to privkeys.json")
	flag.IntVar(&threshold, "m", 2, "Multisig threshold (e.g. 2-of-3)")
	flag.Int64Var(&amountSats, "amount", 0, "UTXO amount in sats")
	flag.Parse()

	if address == "" || txHex == "" || redeemHex == "" || privFile == "" || amountSats <= 0 {
		flag.Usage()
		log.Fatal("All flags are required")
	}

	rawTx, err := hex.DecodeString(txHex)
	if err != nil {
		log.Fatalf("Invalid tx hex: %v", err)
	}

	tx := wire.NewMsgTx(wire.TxVersion)
	if err := tx.Deserialize(bytes.NewReader(rawTx)); err != nil {
		log.Fatalf("Failed to deserialize tx: %v", err)
	}

	redeemScript, err := hex.DecodeString(redeemHex)
	if err != nil {
		log.Fatalf("Invalid redeem script: %v", err)
	}

	scriptPubKey, err := getScriptPubKeyFromAddress(address)
	if err != nil {
		log.Fatalf("❌ ScriptPubKey error: %v", err)
	}

	// Load private keys
	data, err := ioutil.ReadFile(privFile)
	if err != nil {
		log.Fatalf("Failed to read privkeys file: %v", err)
	}
	var privEntries []PrivData
	if err := json.Unmarshal(data, &privEntries); err != nil {
		log.Fatalf("Failed to parse privkeys JSON: %v", err)
	}

	var sigs [][]byte

	for _, p := range privEntries {
		wif, err := btcutil.DecodeWIF(p.PrivKeyWIF)
		if err != nil {
			log.Fatalf("Invalid WIF: %v", err)
		}

		prevOutFetcher := txscript.NewCannedPrevOutputFetcher(
			scriptPubKey, amountSats,
		)

		sigHashes := txscript.NewTxSigHashes(tx, prevOutFetcher)

		sig, err := txscript.RawTxInWitnessSignature(
			tx, sigHashes, 0, amountSats,
			redeemScript, txscript.SigHashAll, wif.PrivKey,
		)
		if err != nil {
			log.Fatalf("Signing failed: %v", err)
		}
		sigs = append(sigs, sig)
	}

	// Build multisig witness stack: empty + sig1 + sig2 + redeem script
	witness := wire.TxWitness{[]byte{}}
	for i := 0; i < threshold; i++ {
		sig := sigs[i]
		witness = append(witness, sig)

	}
	witness = append(witness, redeemScript)

	tx.TxIn[0].Witness = witness

	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		log.Fatalf("Failed to serialize tx: %v", err)
	}

	fmt.Printf("✅ Signed TX (hex): %x\n", buf.Bytes())
}
