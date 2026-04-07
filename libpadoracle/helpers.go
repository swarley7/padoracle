package libpadoracle

import (
	"bytes"
	"fmt"

	"github.com/fatih/color"
)

const (
	MODE_DECRYPT = 0
	MODE_ENCRYPT = 1
)

// Oracle interface for the attack
type Oracle interface {
	Call(payload []byte) bool
}

// Get yo colours sorted
var g = color.New(color.FgHiGreen)
var gb = color.New(color.FgHiGreen, color.Bold)
var y = color.New(color.FgHiYellow, color.Bold)
var r = color.New(color.FgHiRed, color.Bold)
var m = color.New(color.FgHiMagenta, color.Bold)
var b = color.New(color.FgHiCyan)
var bb = color.New(color.FgHiCyan, color.Bold)
var cyan = color.New(color.FgHiCyan)
var white = color.New(color.FgHiWhite, color.Bold)

func Banner() {
	fmt.Println(gb.Sprint(`
  _____          _____   ____  _____            _____ _      ______ 
 |  __ \   /\   |  __ \ / __ \|  __ \     /\   / ____| |    |  ____|
 | |__) | /  \  | |  | | |  | | |__) |   /  \ | |    | |    | |__   
 |  ___/ / /\ \ | |  | | |  | |  _  /   / /\ \| |    | |    |  __|  
 | |    / ____ \| |__| | |__| | | \ \  / ____ \ |____| |____| |____ 
 |_|   /_/    \_\_____/ \____/|_|  \_\/_/    \_\_____|______|______|
`))
	fmt.Println(white.Sprint(" [ Modern, Fast, Concurrent Padding Oracle Exploit Toolkit ]\n"))
}

// pkcs7pad add pkcs7 padding
func PKCS7(data []byte, blockSize int) ([]byte, error) {
	if blockSize < 1 || blockSize > 256 {
		return nil, fmt.Errorf("pkcs7: Invalid block size %d", blockSize)
	}
	padLen := blockSize - len(data)%blockSize
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...), nil
}

type WriteData struct {
	ByteNum    int
	Deciphered string
	ByteValue  string
	BlockData  string
	BlockNum   int
	NumBlocks  int
}

type Config struct {
	Mode            int
	Debug           bool
	IV              []byte
	BaseCiphertext  []byte
	TargetPlaintext []byte
	AsciiMode       bool
	BlockSize       int
	Algorithm       string
	Threads         int
	NumBlocks       int
	Sleep           int
	BlockRange      string
	Writer          chan WriteData
	NumRequests     *uint64
	NumHits         *uint64
	NumMisses       *uint64
	Statistics      Stats
	Oracle          Oracle
}

type Stats struct {
	NumRequests int
}

type Data struct {
	BlockNumber         int
	EncryptedBlockData  []byte
	DecipheredBlockData []byte
	NumberOperations    int
	UnpaddedCleartext   string
}

func Unpad(b []byte) (o []byte) {
	if len(b) == 0 {
		return b
	}
	padVal := int(b[len(b)-1])
	if padVal > len(b) || padVal <= 0 {
		return b
	}
	// Check if all padding bytes are the same
	for i := len(b) - padVal; i < len(b); i++ {
		if b[i] != byte(padVal) {
			return b
		}
	}
	return b[:len(b)-padVal]
}

// ChunkBytes chunks i into n-length chunks
func ChunkBytes(b []byte, n int) (chunks [][]byte) {
	if n <= 0 {
		return [][]byte{b}
	}
	for i := 0; i < len(b); i += n {
		nn := i + n
		if nn > len(b) {
			nn = len(b)
		}
		chunks = append(chunks, b[i:nn])
	}
	return chunks
}

// XORBytes performs a byte-wise xor of two supplied bytearrays
func XORBytes(a []byte, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("cannot XOR unequal length byte arrays (a=%d - b=%d)", len(a), len(b))
	}
	out := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		out[i] = a[i] ^ b[i]
	}
	return out, nil
}

// BuildPaddingBlock constructs a block padded to PCKS5/7 standard based upon the blocksize
func BuildPaddingBlock(byteNum int, blockSize int) (padding []byte) {
	padding = make([]byte, blockSize)
	padVal := byte(byteNum + 1)
	for i := blockSize - 1; i >= blockSize-1-byteNum; i-- {
		padding[i] = padVal
	}
	return padding
}

// BuildSearchBlock constructs a block of forged ciphertext that will be used to test the padding oracle
func BuildSearchBlock(decipheredBlockBytes []byte, padByteValue byte, blockSize int) (searchBlock []byte) {
	searchBlock = make([]byte, blockSize)
	searchBlock[blockSize-1-len(decipheredBlockBytes)] = padByteValue
	copy(searchBlock[blockSize-len(decipheredBlockBytes):], decipheredBlockBytes)
	return searchBlock
}

// BuildRawOraclePayload
func BuildRawOraclePayload(paddingBlock []byte, cipherTextBlock []byte) []byte {
	out := make([]byte, len(paddingBlock)+len(cipherTextBlock))
	copy(out, paddingBlock)
	copy(out[len(paddingBlock):], cipherTextBlock)
	return out
}
