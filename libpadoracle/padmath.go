package libpadoracle

import (
	"errors"
	"fmt"
	"sync"
)

// PerByteOperations performs the actual math on each byte of the CipherText
func PadOperations(cfg Config, cipherText []byte, decipherChan chan Data) {
	threadCh := make(chan struct{}, cfg.Threads)
	wg := sync.WaitGroup{}
	if cfg.IV != nil { // IV was supplied by the user - let's prepend to the Decoded Ciphertext
		cipherText = append(cfg.IV, cipherText...)
	}
	Blocks := ChunkBytes(cipherText, cfg.BlockSize)
	if lastBlockLen := len(Blocks[len(Blocks)]); lastBlockLen != cfg.BlockSize {
		err := errors.New(fmt.Sprintf("Invalid Block Size at Block #%d: %v bytes", len(Blocks), lastBlockLen))
		panic(err)
	}
	wg.Add(len(Blocks))
	for blockNum, blockData := range Blocks[1:] {
		go PerBlockOperations(wg, cfg, threadCh, decipherChan, blockNum, blockData, Blocks[blockNum-1])
	}
	wg.Wait()
}

// PerByteOperations performs the actual math on each byte of the CipherText
func PerBlockOperations(wg sync.WaitGroup, cfg Config, threadCh chan struct{}, decipherChan chan Data, blockNum int, blockData []byte, iv []byte) {
	// TODO stuff here
	defer wg.Done()
	wg2 := sync.WaitGroup{}
	for byteNum, byteData := range blockData { // Iterate over each byte
		fmt.Printf("Checking Block: %d; Byte %d; val: %d\n", blockNum, byteNum, byteData)
		for i := 0; i < 256; i++ {
			go PerByteOperations(wg2, threadCh, decipherChan, cfg, i, byteNum, blockNum, blockData, iv)
		}
	}
}

// PerByteOperations performs the actual math on each byte of the CipherText
func PerByteOperations(wg sync.WaitGroup, threadCh chan struct{}, decipherChan chan Data, cfg Config, bruteForceByteValue int, byteNum int, blockNum int, blockData []byte, IV []byte) {
	defer func() {
		<-threadCh // Release a thread once we're done with this goroutine
	}()
	var RawOracleData []byte
	var returnData Data
	// TODO stuff here

	padBlock := BuildPaddedBlock(iv, blockData, bruteForceByteValue, cfg.blockSize)

	encodedPayload := EncodePayload(RawOracleData)
	responseData := CallOracle(encodedPayload)
	if CheckResponse(responseData) {
		defer wg.Done()
		decipherChan <- returnData
	}
}
