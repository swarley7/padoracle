package main

import (
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"

	"./libpadoracle"
)

func main() {
	var cfg libpadoracle.Config
	var cipherText string
	var iv string
	flag.StringVar(&cipherText, "c", "", "Provide the base ciphertext that you're trying to decipher (ripped straight from your request)")
	flag.StringVar(&iv, "iv", "", "Optional: provide the IV for Block 0 of your ciphertext (if the application has done Crypto bad, and treated the IV as secret)")
	flag.IntVar(&cfg.BlockSize, "bs", 16, "Block size for the ciphertext. Common values are 8 (DES), 16 (AES)")
	flag.IntVar(&cfg.Threads, "T", 100, "Number of threads to use for testing")
	flag.BoolVar(&cfg.Debug, "d", false, "Debug mode")

	flag.Parse()
	if cfg.Debug {
		go func() {
			fmt.Println("Profiler running on: localhost:6060")
			http.ListenAndServe("localhost:6060", nil)
		}()
	}
	cfg.BaseCiphertext = libpadoracle.DecodeCiphertextPayload(cipherText)
	if iv != "" {
		cfg.IV = libpadoracle.DecodeIV(iv)
	}
	libpadoracle.Run(cfg)
}
