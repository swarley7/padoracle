package libpadoracle

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/fatih/color"
)

const (
	MODE_DECRYPT = 0
	MODE_ENCRYPT = 1
)

// The Pad interface
type pad interface {
	EncodePayload([]byte) string
	DecodeCiphertextPayload(string) []byte
	DecodeIV(string) []byte
	CallOracle(string) bool
	// CheckResponse(interface{}) bool
}

// Get yo colours sorted
var g = color.New(color.FgGreen)

var gb = color.New(color.FgGreen, color.Bold)
var y = color.New(color.FgYellow, color.Bold)
var r = color.New(color.FgRed, color.Bold)
var m = color.New(color.FgMagenta, color.Bold)
var b = color.New(color.FgBlue)
var bb = color.New(color.FgBlue, color.Bold)

func Reverse(s string) string {
	var reverse string
	for i := len(s) - 1; i >= 0; i-- {
		reverse += string(s[i])
	}
	return reverse
}

func Check(err error) {
	if err != nil {
		panic(err)
	}
}

// pkcs7pad add pkcs7 padding
func PKCS7(data []byte, blockSize int) ([]byte, error) {
	if blockSize < 0 || blockSize > 256 {
		return nil, fmt.Errorf("pkcs7: Invalid block size %d", blockSize)
	} else {
		padLen := 16 - len(data)%blockSize
		padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
		return append(data, padding...), nil
	}
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
	MetricsChan     chan int
	Statistics      Stats
	Pad             pad
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

type Out struct {
	Ok bool
	D  []byte
}

// BuildSearchBlock constructs a block of forged ciphertext that will be used to test the padding oracle
func BuildSearchBlock(decipheredBlockBytes []byte, padByteValue byte, blockSize int) (searchBlock []byte) {
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

func GenerateFullSlice(data byte, size int) []byte {
	out := make([]byte, size)
	for i := 0; i < size; i++ {
		out[i] = data
	}
	return out
}
