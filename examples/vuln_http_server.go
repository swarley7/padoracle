package main

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net/http"
)

var cryptoKey []byte
var IV []byte
var BS int
var host string
var port int

// func PKCS7(arr []byte, blocksize int) []byte {
// 	rem := blocksize - (len(arr) % blocksize)
// 	if rem == 0 {
// 		return arr
// 	}
// 	pad := make([]byte, rem)
// 	for i := range pad {
// 		pad[i] = byte(rem)
// 	}
// 	return append(arr, pad...)
// }

// // Unpads correctly padded PKCS7 data
// func UnPKCS7(arr []byte, blocksize int) ([]byte, error) {
// 	if len(arr)%blocksize != 0 {
// 		return nil, errors.New("Invalid data length")
// 	}
// 	padCount := int(arr[len(arr)-1])
// 	if padCount > blocksize {
// 		return nil, errors.New("not padded correctly")
// 	}
// 	for i := len(arr) - 1; i > len(arr)-1-padCount; i-- {
// 		if arr[i] != arr[len(arr)-1] {
// 			return nil, errors.New("not padded correctly")
// 		}
// 	}
// 	return arr[:len(arr)-padCount], nil
// }

// pkcs7strip remove pkcs7 padding
func UnPKCS7(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("pkcs7: Data is empty")
	}
	if length%blockSize != 0 {
		return nil, errors.New("pkcs7: Data is not block-aligned")
	}
	padLen := int(data[length-1])
	ref := bytes.Repeat([]byte{byte(padLen)}, padLen)
	if padLen > blockSize || padLen == 0 || !bytes.HasSuffix(data, ref) {
		return nil, errors.New("pkcs7: Invalid padding")
	}
	return data[:length-padLen], nil
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

func check(err error) {
	if err != nil {
		panic(err)
	}
}
func XORbytes(in []byte, key []byte) (out []byte) {
	if len(in) != len(key) {
		fmt.Println("A: ", len(in), "; B: ", len(key))
		panic("fuck")
	}
	for i := 0; i < len(in); i++ {
		out = append(out, in[i]^key[i])
	}
	return out
}

func EncryptAesCbc(data, key, iv []byte, blocksize int) []byte {
	cipher, _ := aes.NewCipher([]byte(key))
	encrypted := make([]byte, len(data))
	size := blocksize

	for bs, be := 0, size; bs < len(data); bs, be = bs+size, be+size {
		if bs == 0 { // Special case for first block - XOR plaintext against IV
			cipher.Encrypt(encrypted[bs:be], XORbytes(data[bs:be], iv)) // Encrypt
			continue
		}
		cipher.Encrypt(encrypted[bs:be], XORbytes(data[bs:be], encrypted[bs-size:be-size])) // Encrypt
	}
	return append(iv, encrypted...)
}

func DecryptAesCbc(data, key, iv []byte, blocksize int) []byte {
	cipher, _ := aes.NewCipher([]byte(key))
	decrypted := []byte{}
	ciphertextIv := append(iv, data...)

	size := blocksize
	for bs, be := size, size+size; bs < len(ciphertextIv); bs, be = bs+size, be+size {
		tmp := make([]byte, size)
		cipher.Decrypt(tmp, ciphertextIv[bs:be])                                       // Decrypt
		decrypted = append(decrypted, XORbytes(tmp, ciphertextIv[bs-size:be-size])...) // Plaintext XOR Iv after decrypting
	}
	return decrypted
}

func GenerateRandomBytes(size int) (out []byte) {
	out = make([]byte, size)
	_, err := rand.Read(out)
	check(err)
	return out
}

func main() {

	var stringKey string
	var iv string
	var bs int

	flag.IntVar(&port, "p", 8000, "Port to bind the service to.")
	flag.StringVar(&host, "l", "127.0.0.1", "Host address to bind the service to.")
	flag.StringVar(&iv, "i", "", "Optional IV (blocksize length bytes in ASCII-Hex notation)")
	flag.StringVar(&stringKey, "k", "YELLOW SUBMARINE", "Key value for encryption / decryption")
	flag.IntVar(&bs, "bs", 16, "Blocksize for the encryption / decryption. Common values are 8 or 16 (default).")
	flag.Parse()

	BS = bs
	cryptoKey = []byte(stringKey)
	IV = []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8}
	http.HandleFunc("/", VulnServer)
	http.ListenAndServe(fmt.Sprintf("%s:%d", host, port), nil)
}

func VulnServer(w http.ResponseWriter, r *http.Request) {
	ciphertext, ok := r.URL.Query()["vuln"]
	if !ok {
		data, err := PKCS7([]byte("This is a test for validating a padding oracle, see what you think?"), BS)
		if err != nil {
			return
		}
		cipherTextBytes := EncryptAesCbc(data, cryptoKey, IV, BS)
		// cipherTextBytes = append(IV, cipherTextBytes...)
		fmt.Fprintf(w, "Ciphertext: %s\nUsage:\n\n\nhttp://%s:%d/?vuln=%s", hex.EncodeToString(cipherTextBytes), host, port, hex.EncodeToString(cipherTextBytes))
		return
	}
	ct, err := hex.DecodeString(ciphertext[0])
	if err != nil {
		fmt.Println(r.URL.RequestURI())

		w.WriteHeader(500)
		fmt.Fprintf(w, "The vuln paramter value was incorrectly formatted and not valid ASCII-Hex\nPlease check\n\n(Note: this is not a marker for a valid padding oracle vulnerability; your input is well fucked).")
		return
	}
	pt, err := UnPKCS7(DecryptAesCbc(ct, cryptoKey, []byte{}, BS), BS)
	if err != nil {
		w.WriteHeader(500)
		// fmt.Println(r.URL.RequestURI())
		fmt.Fprintf(w, "%s", err)
		return
	}
	fmt.Fprintf(w, "The decrypted plaintext is:\n\n%s", pt)
	fmt.Printf("The decrypted plaintext is:\n\n%s", pt)
	return
}
