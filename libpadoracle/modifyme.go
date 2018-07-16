package libpadoracle

import (
	"encoding/base64"
	"io/ioutil"
	"net/http"
	"strings"
)

var client = &http.Client{}

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
	return decoded
}

// DecodeIV decodes the optionally-supplied Block0 initialisation vector. Modify the decode routine to suit the format of the supplied IV
func DecodeIV(IV string) []byte {
	return DecodeCiphertextPayload(IV)
}

// CallOracle actually makes the HTTP/whatever request to the server that provides the padding oracle. Modify this to suit your application's needs.
func CallOracle(encodedPayload string) (*http.Response, string) {
	// Sample to be used with padex.py

	req, err := http.NewRequest("POST", "http://127.0.0.1:12345", strings.NewReader(encodedPayload))
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
