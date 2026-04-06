package libpadoracle

import (
	"bytes"
	"testing"
)

func TestPKCS7(t *testing.T) {
	data := []byte("TEST")
	padded, err := PKCS7(data, 8)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []byte("TEST\x04\x04\x04\x04")
	if !bytes.Equal(padded, expected) {
		t.Errorf("PKCS7 failed: got %x, expected %x", padded, expected)
	}

	data = []byte("12345678")
	padded, err = PKCS7(data, 8)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected = []byte("12345678\x08\x08\x08\x08\x08\x08\x08\x08")
	if !bytes.Equal(padded, expected) {
		t.Errorf("PKCS7 failed: got %x, expected %x", padded, expected)
	}
}

func TestUnpad(t *testing.T) {
	data := []byte("TEST\x04\x04\x04\x04")
	unpadded := Unpad(data)
	expected := []byte("TEST")
	if !bytes.Equal(unpadded, expected) {
		t.Errorf("Unpad failed: got %x, expected %x", unpadded, expected)
	}
}

func TestChunkBytes(t *testing.T) {
	data := []byte("123456789")
	chunks := ChunkBytes(data, 4)
	if len(chunks) != 3 {
		t.Fatalf("expected 3 chunks, got %d", len(chunks))
	}
	if !bytes.Equal(chunks[0], []byte("1234")) {
		t.Errorf("Chunk 0 failed: got %x", chunks[0])
	}
	if !bytes.Equal(chunks[1], []byte("5678")) {
		t.Errorf("Chunk 1 failed: got %x", chunks[1])
	}
	if !bytes.Equal(chunks[2], []byte("9")) {
		t.Errorf("Chunk 2 failed: got %x", chunks[2])
	}
}

func TestXORBytes(t *testing.T) {
	a := []byte{0x01, 0x02, 0x03}
	b := []byte{0x01, 0x04, 0x07}
	expected := []byte{0x00, 0x06, 0x04}
	res := XORBytes(a, b)
	if !bytes.Equal(res, expected) {
		t.Errorf("XORBytes failed: got %x, expected %x", res, expected)
	}
}

func TestBuildPaddingBlock(t *testing.T) {
	// byteNum represents index of the byte from the end, 0-indexed? Wait, the code says:
	// if (i >= blockSize-byteNum) && (byteNum <= blockSize)
	// byteNum = 0 -> padding should be [0,0,0,..,1]
	res := BuildPaddingBlock(0, 4)
	expected := []byte{0x00, 0x00, 0x00, 0x01}
	if !bytes.Equal(res, expected) {
		t.Errorf("BuildPaddingBlock(0, 4) failed: got %x, expected %x", res, expected)
	}

	res = BuildPaddingBlock(1, 4)
	expected = []byte{0x00, 0x00, 0x02, 0x02}
	if !bytes.Equal(res, expected) {
		t.Errorf("BuildPaddingBlock(1, 4) failed: got %x, expected %x", res, expected)
	}
}

func TestBuildSearchBlock(t *testing.T) {
	// decipheredBlockBytes is the already found bytes
	dec := []byte{0x41, 0x42} // A, B
	padByteValue := byte(0x43) // C
	res := BuildSearchBlock(dec, padByteValue, 4)
	expected := []byte{0x00, 0x43, 0x41, 0x42}
	if !bytes.Equal(res, expected) {
		t.Errorf("BuildSearchBlock failed: got %x, expected %x", res, expected)
	}
}
