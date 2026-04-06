package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
)

var (
	key  = []byte("SUPERSECRETKEY77") // 16 bytes for AES-128
	port = flag.Int("p", 9000, "Port to listen on")
)

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, fmt.Errorf("invalid data length")
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > blockSize {
		return nil, fmt.Errorf("invalid padding byte")
	}
	for i := len(data) - padLen; i < len(data); i++ {
		if data[i] != byte(padLen) {
			return nil, fmt.Errorf("invalid padding value")
		}
	}
	return data[:len(data)-padLen], nil
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Expecting a hex-encoded ciphertext
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	ctHex := string(bytes.TrimSpace(buf[:n]))
	ciphertext, err := hex.DecodeString(ctHex)
	if err != nil {
		conn.Write([]byte("ERROR: Invalid Hex\n"))
		return
	}

	if len(ciphertext) < aes.BlockSize {
		conn.Write([]byte("ERROR: Ciphertext too short\n"))
		return
	}

	iv := ciphertext[:aes.BlockSize]
	ct := ciphertext[aes.BlockSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		conn.Write([]byte("ERROR: Internal Error\n"))
		return
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	pt := make([]byte, len(ct))
	mode.CryptBlocks(pt, ct)

	_, err = pkcs7Unpad(pt, aes.BlockSize)
	if err != nil {
		// LEAK: Distinct error message for padding failure
		conn.Write([]byte("PADDING_ERROR\n"))
		return
	}

	conn.Write([]byte("SUCCESS\n"))
}

func main() {
	flag.Parse()
	addr := fmt.Sprintf(":%d", *port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer l.Close()

	fmt.Printf(" [!] Vulnerable TCP Padding Oracle Server listening on %s\n", addr)
	fmt.Println(" [!] Target this with a custom CallOracle implementation in padoracle.go")

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}
