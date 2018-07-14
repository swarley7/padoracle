package libpadoracle

import (
	"encoding/base64"
	"io/ioutil"
	"net/http"
	"strings"
)

// EncodePayload turns the raw oracle payload (IV + Ciphertext) into whatever format is required by the endpoint server. Modify this routine to suit the specific needs of the application.
func EncodePayload(RawPadOraclePayload []byte) (encodedPayload string) {
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
func CallOracle(encodedPayload string) string {
	// Sample
	var client http.Client
	Url := "http://127.0.0.1:8888"
	resp, err := client.Get(Url)
	Check(err)

	defer resp.Body.Close()
	var bodyString string
	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		Check(err)
		bodyString = string(bodyBytes)
	}
	return bodyString
}

// CheckResponse tells the program whether the padding was invalid or not. Modify to suit the application's response when invalid padding is detected.
func CheckResponse(responseData string) bool {
	// Sample - the server's response includes the string "Invalid Padding"
	if strings.Contains(responseData, "Invalid Padding") {
		return false // Padding was bad!
	}
	return true // Padding was good :D
}
