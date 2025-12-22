package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/tyler-smith/go-bip39"
)

type PubOutput struct {
	Xpub   string `json:"xpub"`
	Path   string `json:"path"`
	Pubkey string `json:"pubkey"`
}

type PrivOutput struct {
	Xpriv      string `json:"xpriv"`
	PrivKeyWIF string `json:"derived_priv"`
	Path       string `json:"path"`
}

func main() {
	var (
		threshold    int
		nKeys        int
		hexSeed      string
		mnemonic     string
		pathTemplate string
	)

	flag.StringVar(&hexSeed, "hex_seed", "", "BIP32 master seed in hex (if not set, a random one will be used)")
	flag.StringVar(&mnemonic, "mnemonic", "", "BIP39 mnemonic phrase to import")
	flag.StringVar(&pathTemplate, "path", "m/84'/0'/0'/0/i", "Derivation path template (use 'i' for key index)")
	flag.IntVar(&nKeys, "n", 3, "n: Total keys(e.g. 2-of-3)")
	flag.IntVar(&threshold, "m", 2, "m: Multisig threshold (e.g. 2-of-3)")
	flag.Parse()

	if hexSeed != "" && mnemonic != "" {
		log.Fatal("❌ Error: cannot specify both -hex_seed and -mnemonic")
	}

	var seed []byte
	var err error

	if mnemonic != "" {
		seed, err = mnemonicToSeed(mnemonic)
		if err != nil {
			log.Fatalf("❌ Error: %v", err)
		}
	} else if hexSeed != "" {
		seed, err = decodeHexSeed(hexSeed)
		if err != nil {
			log.Fatalf("❌ Error: %v", err)
		}
	} else {
		fmt.Println("Generating random seed")
		seed, err = randomSeed()
		if err != nil {
			log.Fatalf("❌ failed to generate seed: %v", err)
		}
	}

	if err := printXpubFromSeed(seed); err != nil {
		log.Fatalf("❌ Error: %v", err)
	}

	if nKeys <= 0 || threshold <= 0 || threshold > nKeys {
		flag.Usage()
		log.Fatal("All flags are required for m-of-n setup")
	}

	if err := run(seed, threshold, nKeys, pathTemplate); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error: %v\n", err)
		os.Exit(1)
	}
}

func decodeHexSeed(hexSeed string) ([]byte, error) {
	// Decode the hex seed
	return hex.DecodeString(hexSeed)
}

func mnemonicToSeed(mnemonic string) ([]byte, error) {
	// Validate the mnemonic
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("invalid mnemonic phrase")
	}

	// Convert mnemonic to seed (using empty passphrase)
	seed := bip39.NewSeed(mnemonic, "")
	return seed, nil
}

func parsePath(pathTemplate string, index int) ([]uint32, error) {
	// Replace 'i' placeholder with actual index
	path := strings.ReplaceAll(pathTemplate, "i", fmt.Sprintf("%d", index))

	// Ensure path starts with 'm/' to avoid ethereum's default path prepending
	if !strings.HasPrefix(path, "m/") && !strings.HasPrefix(path, "m") {
		path = "m/" + path
	}

	derivPath, err := accounts.ParseDerivationPath(path)
	if err != nil {
		return nil, err
	}

	return []uint32(derivPath), nil
}

func printXpubFromSeed(seed []byte) error {
	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return fmt.Errorf("failed to create master key: %w", err)
	}

	// Neuter the key to get the public version (xpub)
	pubKey, err := masterKey.Neuter()
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}

	// Get the xpub string
	xpub := pubKey.String()
	fmt.Printf("Derived xpub: %s\n", xpub)

	return nil
}

func run(seed []byte, nRequired, nKeys int, pathTemplate string) error {

	var pubs []PubOutput
	var privs []PrivOutput
	var addrPubKeys []*btcutil.AddressPubKey

	for i := 0; i < nKeys; i++ {
		path, err := parsePath(pathTemplate, i)
		if err != nil {
			return fmt.Errorf("failed to parse path for key %d: %w", i, err)
		}
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
	fmt.Println("Redeem Script (base64):", base64.StdEncoding.EncodeToString(redeemScript))
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
	for _, i := range path {
		current, err = current.Derive(i)
		if err != nil {
			return PubOutput{}, PrivOutput{}, nil, err
		}
	}

	// Use ethereum's DerivationPath for consistent path formatting
	pathStr := accounts.DerivationPath(path).String()

	pubKey, err := current.ECPubKey()
	if err != nil {
		return PubOutput{}, PrivOutput{}, nil, err
	}

	// Get compressed pubkey (33 bytes with 02/03 prefix)
	compressedPubkey := pubKey.SerializeCompressed()

	addrPubKey, err := btcutil.NewAddressPubKey(compressedPubkey, &chaincfg.MainNetParams)
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
		Xpub:   xpub.String(),
		Path:   pathStr,
		Pubkey: hex.EncodeToString(compressedPubkey),
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
