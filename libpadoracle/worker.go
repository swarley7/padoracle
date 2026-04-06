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

func printStats(cfg Config) {
	reqs := atomic.LoadUint64(cfg.NumRequests)
	hits := atomic.LoadUint64(cfg.NumHits)
	misses := atomic.LoadUint64(cfg.NumMisses)
	reqsPerBlock := float64(reqs) / float64(cfg.NumBlocks)

	fmt.Printf("\n [%v] %v\n", cyan.Sprint("+"), cyan.Sprint("STATISTICS"))
	fmt.Printf("  ├── Total Requests: %v\n", white.Sprintf("%d", reqs))
	fmt.Printf("  ├── Valid Padding (Hits): %v\n", g.Sprintf("%d", hits))
	fmt.Printf("  ├── Invalid Padding (Misses): %v\n", r.Sprintf("%d", misses))
	fmt.Printf("  └── Avg Requests per Block: %v\n", white.Sprintf("%.2f", reqsPerBlock))
}

func Run(cfg Config) {
	Banner()
	var numReqs uint64
	var numHits uint64
	var numMisses uint64
	cfg.NumRequests = &numReqs
	cfg.NumHits = &numHits
	cfg.NumMisses = &numMisses
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
		fmt.Printf(" [%v] Mode: %v | Block Size: %v | Threads: %v\n", cyan.Sprint("+"), y.Sprint("DECRYPT"), cfg.BlockSize, cfg.Threads)
		go PadOperations(&wg, &cfg, cfg.BaseCiphertext, decipherChan)
	} else if cfg.Mode == MODE_ENCRYPT {
		fmt.Printf(" [%v] Mode: %v | Block Size: %v | Threads: %v\n", cyan.Sprint("+"), y.Sprint("ENCRYPT"), cfg.BlockSize, cfg.Threads)
		go PadOperationsEncrypt(&wg, &cfg, cfg.TargetPlaintext)
	}
	wg.Wait()

	uiMutex.Lock()
	if uiRunning {
		uiprogress.Stop()
		uiRunning = false
	}
	uiMutex.Unlock()

	if cfg.Mode == MODE_ENCRYPT {
		printStats(cfg)
		fmt.Printf("\n [%v] %v\n\n", gb.Sprint("*"), gb.Sprint("ENCRYPTION COMPLETE"))
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

	printStats(*cfg)
	fmt.Printf("\n [%v] %v\n\n%v\n\n", gb.Sprint("*"), gb.Sprint("DECRYPTED DATA"), ClearText.String())
}
