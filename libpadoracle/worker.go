package libpadoracle

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sync"
)

func Run(cfg Config) {
	decipherChan := make(chan Data)
	wg := sync.WaitGroup{}
	wg.Add(2)
	go WriteOutput(&wg, decipherChan)
	go PadOperations(&wg, cfg, cfg.BaseCiphertext, decipherChan)
	wg.Wait()
}

func WriteOutput(wg *sync.WaitGroup, decipherChan chan Data) {
	defer wg.Done()
	Results := map[int]Data{}
	for block := range decipherChan {
		fmt.Printf("Decrypted [%v]\n╰> Original Ciphertext:\t[%v]\n╰> Decrypted (Hex):\t[%v]\n╰> Cleartext:\t\t[%v]\n", r.Sprintf("Block %d", block.BlockNumber), b.Sprintf(hex.EncodeToString(block.EncryptedBlockData)), g.Sprintf(hex.EncodeToString(block.DecipheredBlockData)), g.Sprintf(block.UnpaddedCleartext))
		Results[block.BlockNumber] = block
	}
	var ClearText bytes.Buffer
	for i := 1; i <= len(Results)+1; i++ { // need to fix this; sort on Results[i] instead of this crap - this won't work if you're not starting at block 1...
		ClearText.WriteString(Results[i].UnpaddedCleartext)
	}
	fmt.Printf("\n****** Decrypted data ********\n")
	fmt.Printf("%v\n", ClearText.String())

}
