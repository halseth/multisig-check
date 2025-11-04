package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

type PubOutput struct {
	Xpub string `json:"xpub"`
	Path string `json:"path"`
}

type PrivOutput struct {
	Xpriv      string `json:"xpriv"`
	PrivKeyWIF string `json:"derived_priv"`
	Path       string `json:"path"`
}

func main() {
	var (
		threshold int
		nKeys     int
	)

	flag.IntVar(&nKeys, "n", 3, "n: Total keys(e.g. 2-of-3)")
	flag.IntVar(&threshold, "m", 2, "m: Multisig threshold (e.g. 2-of-3)")
	flag.Parse()

	if nKeys <= 0 || threshold <= 0 || threshold > nKeys {
		flag.Usage()
		log.Fatal("All flags are required for m-of-n setup")
	}

	if err := run(threshold, nKeys); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error: %v\n", err)
		os.Exit(1)
	}
}

func run(nRequired, nKeys int) error {

	var pubs []PubOutput
	var privs []PrivOutput
	var addrPubKeys []*btcutil.AddressPubKey

	seed, err := randomSeed()
	if err != nil {
		return fmt.Errorf("failed to generate seed: %w", err)
	}

	for i := 0; i < nKeys; i++ {
		path := []uint32{0, uint32(i)}
		pub, priv, addrPubKey, err := deriveKeyData(seed, path)
		if err != nil {
			return fmt.Errorf("failed to derive key: %w", err)
		}

		pubs = append(pubs, pub)
		privs = append(privs, priv)
		addrPubKeys = append(addrPubKeys, addrPubKey)
	}

	// Create redeem script and address
	redeemScript, err := txscript.MultiSigScript(addrPubKeys, nRequired)
	if err != nil {
		return fmt.Errorf("failed to create redeem script: %w", err)
	}
	witnessProg := sha256.Sum256(redeemScript)
	addr, err := btcutil.NewAddressWitnessScriptHash(witnessProg[:], &chaincfg.MainNetParams)
	if err != nil {
		return fmt.Errorf("failed to create P2WSH address: %w", err)
	}

	// Write public key data
	if err := writeJSON("xpubs.json", pubs); err != nil {
		return fmt.Errorf("failed to write xpubs.json: %w", err)
	}

	// Write private key data
	if err := writeJSON("privkeys.json", privs); err != nil {
		return fmt.Errorf("failed to write privkeys.json: %w", err)
	}

	// Output summary
	fmt.Println("✅ Generated multisig data")
	fmt.Println("P2WSH Address:", addr.EncodeAddress())
	fmt.Println("Redeem Script (hex):", hex.EncodeToString(redeemScript))
	fmt.Println("→ Public metadata saved to: xpubs.json")
	fmt.Println("→ Private keys saved to:    privkeys.json")

	return nil
}

func randomSeed() ([]byte, error) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	return seed, nil
}

func deriveKeyData(seed []byte, path []uint32) (PubOutput, PrivOutput, *btcutil.AddressPubKey, error) {
	master, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return PubOutput{}, PrivOutput{}, nil, err
	}

	// Derive child key
	current := master
	pathStr := ""
	for _, i := range path {
		if pathStr != "" {
			pathStr += "/"
		}
		pathStr += fmt.Sprintf("%d", i)
		current, err = current.Derive(i)
		if err != nil {
			return PubOutput{}, PrivOutput{}, nil, err
		}
	}

	pubKey, err := current.ECPubKey()
	if err != nil {
		return PubOutput{}, PrivOutput{}, nil, err
	}

	addrPubKey, err := btcutil.NewAddressPubKey(pubKey.SerializeCompressed(), &chaincfg.MainNetParams)
	if err != nil {
		return PubOutput{}, PrivOutput{}, nil, err
	}

	privKey, err := current.ECPrivKey()
	if err != nil {
		return PubOutput{}, PrivOutput{}, nil, err
	}
	privWIF, err := btcutil.NewWIF(privKey, &chaincfg.MainNetParams, true)
	if err != nil {
		return PubOutput{}, PrivOutput{}, nil, err
	}

	xpub, err := master.Neuter()
	if err != nil {
		return PubOutput{}, PrivOutput{}, nil, err
	}

	pub := PubOutput{
		Xpub: xpub.String(),
		Path: pathStr,
	}
	priv := PrivOutput{
		Xpriv:      master.String(),
		PrivKeyWIF: privWIF.String(),
		Path:       pathStr,
	}
	return pub, priv, addrPubKey, nil
}

func writeJSON(filename string, v interface{}) error {
	bytes, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, bytes, 0600)
}
