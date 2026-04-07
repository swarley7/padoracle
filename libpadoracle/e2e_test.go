package libpadoracle

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var testKey = []byte("0123456789abcdef")

func encrypt(plaintext []byte) []byte {
	block, _ := aes.NewCipher(testKey)
	plaintext, _ = PKCS7(plaintext, 16)
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	io.ReadFull(rand.Reader, iv)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)
	return ciphertext
}

func decrypt(ciphertext []byte) ([]byte, bool) {
	block, _ := aes.NewCipher(testKey)
	if len(ciphertext) < aes.BlockSize {
		return nil, false
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, false
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// check padding
	padLen := int(plaintext[len(plaintext)-1])
	if padLen == 0 || padLen > aes.BlockSize {
		return nil, false
	}
	for i := len(plaintext) - padLen; i < len(plaintext); i++ {
		if plaintext[i] != byte(padLen) {
			return nil, false
		}
	}
	return plaintext[:len(plaintext)-padLen], true
}

type dummyOracle struct {
	client *http.Client
	url    string
}

func (d dummyOracle) Call(payload []byte) bool {
	payloadHex := hex.EncodeToString(payload)
	resp, err := d.client.Get(d.url + "?ct=" + payloadHex)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

func TestEndToEnd(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctHex := r.URL.Query().Get("ct")
		ct, _ := hex.DecodeString(ctHex)
		_, ok := decrypt(ct)
		if ok {
			w.WriteHeader(200)
		} else {
			w.WriteHeader(500)
		}
	}))
	defer ts.Close()

	plaintext := []byte("secret message")
	ciphertext := encrypt(plaintext)

	cfg := Config{
		Mode:           MODE_DECRYPT,
		Debug:          false,
		BaseCiphertext: ciphertext,
		AsciiMode:      true,
		BlockSize:      16,
		Threads:        10,
		Oracle:         dummyOracle{client: ts.Client(), url: ts.URL},
	}

	done := make(chan bool)
	go func() {
		Run(cfg)
		done <- true
	}()

	select {
	case <-done:
		// success
	case <-time.After(30 * time.Second):
		t.Fatal("Run(cfg) took too long (possible deadlock)")
	}
}

func TestEndToEndEncrypt(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctHex := r.URL.Query().Get("ct")
		ct, _ := hex.DecodeString(ctHex)
		_, ok := decrypt(ct)
		if ok {
			w.WriteHeader(200)
		} else {
			w.WriteHeader(500)
		}
	}))
	defer ts.Close()

	plaintext := []byte("secret message encrypt with multiple blocks 1337")

	cfg := Config{
		Mode:            MODE_ENCRYPT,
		Debug:           false,
		TargetPlaintext: plaintext,
		AsciiMode:       true,
		BlockSize:       16,
		Threads:         10,
		Oracle:          dummyOracle{client: ts.Client(), url: ts.URL},
	}

	done := make(chan bool)
	go func() {
		Run(cfg)
		done <- true
	}()

	select {
	case <-done:
		// success
	case <-time.After(60 * time.Second):
		t.Fatal("Run(cfg) encrypt took too long")
	}
}
