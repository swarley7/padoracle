package libpadoracle

import (
	"errors"
	"fmt"
)

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
}

type Data struct {
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
	for i := 0; i < blockSize; i++ {
		if (i >= blockSize-byteNum) && (byteNum <= blockSize) {
			padding = append(padding, byte(byteNum))
		} else {
			padding = append(padding, byte(0))
		}
	}
	return padding
}

// GenerateSearchBlock constructs a block of forged ciphertext that will be used to test the padding oracle
func GenerateSearchBlock(previousBlock []byte, blockData []byte, byteNum int, blockNum int, padByteValue int, blockSize int) (searchBlock []byte) {
	for i := 0; i < blockSize; i++ {
		if i < blockSize-padByteValue {
			searchBlock = append(searchBlock, byte(padByteValue))
		} else {
			searchBlock = append(searchBlock, byte(0))
		}
	}
	return searchBlock
}
