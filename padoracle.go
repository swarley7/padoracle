package main

import (
	"flag"
	"fmt"

	"./libpadoracle"
)

func main() {
	var cfg libpadoracle.Config
	var cipherText string
	var iv string
	flag.StringVar(&cipherText, "ciphertext", "", "Provide the base ciphertext that you're trying to decipher (ripped straight from your request)")
	flag.StringVar(&iv, "iv", "", "Optional: provide the IV for Block 0 of your ciphertext (if the application has done Crypto bad, and treated the IV as secret)")
	flag.IntVar(&cfg.BlockSize, "bs", 16, "Block size for the ciphertext. Common values are 8 (DES), 16 (AES)")
	flag.IntVar(&cfg.Threads, "T", 100, "Number of threads to use for testing")

	fmt.Println(cipherText)

	cfg.BaseCiphertext = libpadoracle.DecodeCiphertextPayload(cipherText)
	if iv != "" {
		cfg.IV = libpadoracle.DecodeIV(iv)
	}
	libpadoracle.Run(cfg)
}
