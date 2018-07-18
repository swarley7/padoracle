package libpadoracle

import (
	"errors"
	"fmt"

	"github.com/fatih/color"
)

// Get yo colours sorted
var g = color.New(color.FgGreen, color.Bold)
var y = color.New(color.FgYellow, color.Bold)
var r = color.New(color.FgRed, color.Bold)
var m = color.New(color.FgMagenta, color.Bold)
var b = color.New(color.FgBlue, color.Bold)

func Check(err error) {
	if err != nil {
		panic(err)
	}
}

type Config struct {
	Debug          bool
	IV             []byte
	BaseCiphertext []byte
	BlockSize      int
	Algorithm      string
	Threads        int
	NumBlocks      int
}

type Data struct {
	BlockNumber         int
	EncryptedBlockData  []byte
	DecipheredBlockData []byte
	NumberOperations    int
	UnpaddedCleartext   string
}

func Unpad(b []byte) (o []byte) {
	padVal := int(b[len(b)-1])
	for i := 0; i < len(b)-padVal; i++ {
		o = append(o, b[i])
	}
	return o
}

func Pad(b []byte, padVal int) (o []byte) {
	b = append(o, b...)
	for i := len(b); i < padVal; i++ {
		o = append(o, byte(i))
	}
	return o
}

// ChunkBytes chunks i into n-length chunks
func ChunkBytes(b []byte, n int) (chunks [][]byte) {
	for i := 0; i < len(b); i += n {
		nn := i + n
		if nn > len(b) {
			nn = len(b)
		}
		chunks = append(chunks, b[i:nn])
	}
	return chunks
}

// ChunkStr chunks i into n-length chunks
func ChunkStr(s string, n int) (chunks []string) {
	runes := []rune(s)
	if len(runes) == 0 {
		return []string{s}
	}
	for i := 0; i < len(runes); i += n {
		nn := i + n
		if nn > len(runes) {
			nn = len(runes)
		}
		chunks = append(chunks, string(runes[i:nn]))
	}
	return chunks
}

// XORBytes performs a byte-wise xor of two supplied bytearrays
func XORBytes(a []byte, b []byte) []byte {
	if len(a) != len(b) {
		err := errors.New(fmt.Sprintf("Cannot XOR unequal length byte arrays (a=%d - b=%d)", len(a), len(b)))
		panic(err)
	}
	var xorResult []byte
	for i := 0; i < len(a); i++ {
		xorByte := a[i] ^ b[i]
		xorResult = append(xorResult, xorByte)
	}
	return xorResult
}

// BuildPaddingBlock constructs a block padded to PCKS5/7 standard based upon the blocksize
func BuildPaddingBlock(byteNum int, blockSize int) (padding []byte) {
	for i := 1; i <= blockSize; i++ {
		if (i >= blockSize-byteNum) && (byteNum <= blockSize) {
			padding = append(padding, byte(byteNum+1))
		} else {
			padding = append(padding, byte(0))
		}
	}
	return padding
}

// BuildSearchBlock constructs a block of forged ciphertext that will be used to test the padding oracle
func BuildSearchBlock(decipheredBlockBytes []byte, padByteValue int, blockSize int) (searchBlock []byte) {
	searchBlock = append([]byte{byte(padByteValue)}, decipheredBlockBytes...)
	maxLen := len(searchBlock)
	for i := 0; i < blockSize-maxLen; i++ {
		searchBlock = append([]byte{byte(0)}, searchBlock...)
	}
	return searchBlock
}

// BuildRawOraclePayload
func BuildRawOraclePayload(paddingBlock []byte, cipherTextBlock []byte) []byte {
	return append(paddingBlock, cipherTextBlock...)
}
