package main

import (
	"bytes"
	"encoding/base64"
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

type JSON struct {
	Path       string   `json:"path"`
	Tx         string   `json:"tx"`          // standard (non-url safe) base64
	VinValues  []int64  `json:"vin_values"`  // nullable
	ScriptSigs []string `json:"script_sigs"` // standard (non-url safe) base64s
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

type arrayFlags []string

// String is an implementation of the flag.Value interface
func (i *arrayFlags) String() string {
	return fmt.Sprintf("%v", *i)
}

// Set is an implementation of the flag.Value interface
func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func main() {
	var (
		address  string
		txFiles  arrayFlags
		privFile string
	)

	flag.StringVar(&address, "address", "", "P2WSH address being spent from")
	flag.Var(&txFiles, "tx", "Unsigned transaction json")
	flag.StringVar(&privFile, "privkeys", "", "Path to privkeys.json")
	flag.Parse()

	if address == "" || len(txFiles) == 0 || privFile == "" {
		flag.Usage()
		log.Fatal("All flags are required")
	}

	var txJson []JSON
	for _, f := range txFiles {
		data, err := ioutil.ReadFile(f)
		if err != nil {
			log.Fatalf("Failed to read json file: %v", err)
		}

		var tx JSON
		if err := json.Unmarshal(data, &tx); err != nil {
			log.Fatalf("Failed to parse privkeys JSON: %v", err)
		}

		txJson = append(txJson, tx)
	}

	var rawTxHex string
	var redeemHex string
	var amountSats int64
	for _, j := range txJson {
		raw := j.Tx
		redeem := j.ScriptSigs
		amt := j.VinValues
		if rawTxHex != "" && rawTxHex != raw {
			log.Fatalf("tx hex doesnt match")
		}
		if len(redeem) != 1 {
			log.Fatalf("no sript sigs")
		}
		if redeemHex != "" && redeemHex != redeem[0] {
			log.Fatalf("sript sigs dont match")
		}
		if len(amt) != 1 {
			log.Fatalf("no vin")
		}
		if amountSats != 0 && amountSats != amt[0] {
			log.Fatalf("amounts dont match")
		}

		rawTxHex = raw
		redeemHex = redeem[0]
		amountSats = amt[0]
	}

	b64 := base64.StdEncoding
	rawTx, err := b64.DecodeString(rawTxHex)
	if err != nil {
		log.Fatalf("Invalid tx hex: %v", err)
	}

	tx := wire.NewMsgTx(wire.TxVersion)
	if err := tx.Deserialize(bytes.NewReader(rawTx)); err != nil {
		log.Fatalf("Failed to deserialize tx: %v", err)
	}

	redeemScript, err := b64.DecodeString(redeemHex)
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
	for _, j := range txJson {
		for _, p := range privEntries {
			if p.Path != j.Path {
				continue
			}

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
			break
		}
	}

	// Build multisig witness stack: empty + sig1 + sig2 + redeem script
	witness := wire.TxWitness{[]byte{}}
	for i := 0; i < len(txJson); i++ {
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
