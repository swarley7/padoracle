package libpadoracle

import (
	"bytes"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/gosuri/uiprogress"
)

var uiMutex sync.Mutex
var uiRunning bool
var uiOnce sync.Once

func Run(cfg Config) {
	Banner()
	var numReqs uint64
	cfg.NumRequests = &numReqs
	cfg.Statistics = Stats{
		NumRequests: 0,
	}

	decipherChan := make(chan Data)
	cfg.Writer = make(chan WriteData)
	wg := sync.WaitGroup{}
	wg.Add(1)

	uiOnce.Do(func() {
		uiprogress.Start()
	})

	if cfg.Mode == MODE_DECRYPT {
		fmt.Printf(" [+] Mode: %v | Block Size: %v | Threads: %v\n", y.Sprint("DECRYPT"), cfg.BlockSize, cfg.Threads)
		go PadOperations(&wg, &cfg, cfg.BaseCiphertext, decipherChan)
	} else if cfg.Mode == MODE_ENCRYPT {
		fmt.Printf(" [+] Mode: %v | Block Size: %v | Threads: %v\n", y.Sprint("ENCRYPT"), cfg.BlockSize, cfg.Threads)
		go PadOperationsEncrypt(&wg, &cfg, cfg.TargetPlaintext)
	}
	wg.Wait()
	
	if cfg.Mode == MODE_ENCRYPT {
		fmt.Printf("\n [🔓] %v: %v\n", y.Sprint("TOTAL REQUESTS"), white.Sprintf("%d", atomic.LoadUint64(cfg.NumRequests)))
		fmt.Printf(" [⚡] %v\n\n", gb.Sprint("ENCRYPTION COMPLETE"))
	}
}

func WriteOutput(wg *sync.WaitGroup, decipherChan chan Data, cfg *Config) {
	defer wg.Done()
	Results := []Data{}

	for block := range decipherChan {
		Results = append(Results, block)
	}
	var ClearText bytes.Buffer
	sort.Slice(Results, func(i, j int) bool { return Results[i].BlockNumber < Results[j].BlockNumber })
	for _, res := range Results { 
		ClearText.WriteString(res.UnpaddedCleartext)
	}
	
	fmt.Printf("\n [🔓] %v: %v\n", y.Sprint("TOTAL REQUESTS"), white.Sprintf("%d", atomic.LoadUint64(cfg.NumRequests)))
	fmt.Printf(" [💾] %v:\n\n%v\n\n", gb.Sprint("DECRYPTED DATA"), ClearText.String())
}
