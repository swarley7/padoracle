package libpadoracle

import (
	"bytes"
	"fmt"
	"sort"
	"sync"

	"github.com/gosuri/uiprogress"
)

func Run(cfg Config) {
	decipherChan := make(chan Data)
	cfg.Writer = make(chan WriteData)
	wg := sync.WaitGroup{}
	wg.Add(1)
	uiprogress.Start()

	go PadOperations(&wg, cfg, cfg.BaseCiphertext, decipherChan)
	wg.Wait()
}

func WriteOutput(wg *sync.WaitGroup, decipherChan chan Data, cfg Config) {
	defer wg.Done()
	Results := []Data{}

	for block := range decipherChan {

		// fmt.Printf("Decrypted [%v]\n╰> Original Ciphertext:\t[%v]\n╰> Decrypted (Hex):\t[%v]\n╰> Cleartext:\t\t[%v]\n", r.Sprintf("Block %d", block.BlockNumber), b.Sprintf(hex.EncodeToString(block.EncryptedBlockData)), g.Sprintf(hex.EncodeToString(block.DecipheredBlockData)), gb.Sprintf(block.UnpaddedCleartext))

		Results = append(Results, block)
	}
	var ClearText bytes.Buffer
	sort.Slice(Results, func(i, j int) bool { return Results[i].BlockNumber < Results[j].BlockNumber })
	for _, res := range Results { // need to fix this; sort on Results[i] instead of this crap - this won't work if you're not starting at block 1...
		ClearText.WriteString(res.UnpaddedCleartext)
	}
	uiprogress.Stop()

	fmt.Printf("\n******** %v ********\n", y.Sprintf("Decrypted data"))
	fmt.Printf("%v\n", ClearText.String())

}
