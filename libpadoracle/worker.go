package libpadoracle

import (
	"fmt"
	"sync"
)

func Run(cfg Config) {
	decipherChan := make(chan Data)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go WriteOutput(&wg, decipherChan)
	go PadOperations(cfg, cfg.BaseCiphertext, decipherChan)
	wg.Wait()
}

func WriteOutput(wg *sync.WaitGroup, decipherChan chan Data) {
	defer wg.Done()
	Results := map[int]Data{}
	for block := range decipherChan {
		fmt.Printf("Decrypted [Block %d]  - [%v]:[%v] - Cleartext: [%v]", block.BlockNumber, block.EncryptedBlockData, block.DecipheredBlockData, string(block.DecipheredBlockData))
		Results[block.BlockNumber] = block
	}
	var ClearText []byte
	for _, block := range Results {
		ClearText = append(ClearText, block.DecipheredBlockData...)
	}
	fmt.Printf("\n****** Decrypted data ********\n")
	fmt.Printf("%v\n", string(ClearText))

}
