// Daemon mode: poll a directory, scan new/changed files with worker
// goroutines, print hits. Usage: go run ./daemon [watchDir]
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"openedr_example/openedr"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	pollInterval = 2 * time.Second
	maxSize      = 48 * 1024 * 1024
	workers      = 2
)

var flag = map[string]bool{"Malicious": true, "Suspicious": true}

type stats struct {
	mu           sync.Mutex
	scanned      int
	hits         int
	skippedCache int
}

func (s *stats) bump(field *int) {
	s.mu.Lock()
	*field++
	s.mu.Unlock()
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func extractVerdict(report string) string {
	var v struct {
		Verdict string `json:"verdict"`
	}
	if err := json.Unmarshal([]byte(report), &v); err != nil || v.Verdict == "" {
		return "Unknown"
	}
	return v.Verdict
}

func main() {
	watch := "../../OpenMalwareScannerPortable"
	if len(os.Args) > 1 {
		watch = os.Args[1]
	} else if home, err := os.UserHomeDir(); err == nil {
		watch = filepath.Join(home, "Downloads")
	}
	dllPath := "../../OpenMalwareScannerPortable/openedr_static.dll"
	rulesDir := "../../OpenMalwareScannerPortable"

	scanner, err := openedr.NewScanner(dllPath, rulesDir)
	if err != nil {
		log.Fatalf("[-] Failed to init scanner: %v", err)
	}

	seen := map[string][2]int64{}
	verdictCache := map[string]string{}
	var seenMu, cacheMu sync.Mutex
	st := &stats{}
	jobs := make(chan string, 1024)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				digest, err := sha256File(path)
				if err != nil {
					continue
				}
				cacheMu.Lock()
				cached, ok := verdictCache[digest]
				cacheMu.Unlock()
				if ok {
					if flag[cached] {
						st.bump(&st.hits)
						st.bump(&st.skippedCache)
						fmt.Printf("[!] %s (cached) :: %s\n", cached, path)
					}
					continue
				}
				report, err := scanner.ScanFile(path)
				if err != nil {
					continue
				}
				verdict := extractVerdict(report)
				cacheMu.Lock()
				verdictCache[digest] = verdict
				cacheMu.Unlock()
				st.bump(&st.scanned)
				if flag[verdict] {
					st.bump(&st.hits)
					fmt.Printf("[!] %s :: %s\n", verdict, path)
				}
			}
		}()
	}

	fmt.Printf("[*] Watching %s - Ctrl+C to stop\n", watch)
	for {
		filepath.Walk(watch, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || info.Size() == 0 || info.Size() > maxSize {
				return nil
			}
			key := [2]int64{info.Size(), info.ModTime().UnixNano()}
			seenMu.Lock()
			prev, dup := seen[p]
			seenMu.Unlock()
			if dup && prev == key {
				continue
			}
			select {
			case jobs <- p:
				seenMu.Lock()
				seen[p] = key
				seenMu.Unlock()
			default:
				// queue full: retry on next sweep
			}
			return nil
		})
		time.Sleep(pollInterval)
	}
}
