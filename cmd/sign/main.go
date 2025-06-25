package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
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

func main() {
	var (
		txHex      string
		redeemHex  string
		privFile   string
		amountSats int64
	)

	flag.StringVar(&txHex, "tx", "", "Unsigned transaction hex")
	flag.StringVar(&redeemHex, "redeem", "", "Redeem script hex")
	flag.StringVar(&privFile, "privkeys", "", "Path to privkeys.json")
	flag.Int64Var(&amountSats, "amount", 0, "UTXO amount in sats")
	flag.Parse()

	if txHex == "" || redeemHex == "" || privFile == "" || amountSats <= 0 {
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
	hashType := txscript.SigHashAll

	for _, p := range privEntries {
		wif, err := btcutil.DecodeWIF(p.PrivKeyWIF)
		if err != nil {
			log.Fatalf("Invalid WIF: %v", err)
		}
		sig, err := txscript.RawTxInWitnessSignature(
			tx, txscript.NewTxSigHashes(tx), 0, amountSats,
			redeemScript, txscript.SigHashAll, wif.PrivKey,
		)
		if err != nil {
			log.Fatalf("Signing failed: %v", err)
		}
		sigs = append(sigs, sig)
	}

	pubKeys, err := txscript.ExtractPkScriptAddrs(redeemScript, &chaincfg.MainNetParams)
	if err != nil {
		log.Fatalf("Failed to extract pubkeys: %v", err)
	}

	// Build multisig witness stack: empty + sig1 + sig2 + redeem script
	witness := wire.TxWitness{[]byte{}}
	for _, sig := range sigs {
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
