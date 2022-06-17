package tests

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMutexAdd(t *testing.T) {
	var a int32 = 0
	var wg sync.WaitGroup
	var mu sync.Mutex
	start := time.Now()
	for i := 0; i < 1000000; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mu.Lock()
			a += 1
			mu.Unlock()
		}()
	}
	wg.Wait()
	timeSpends := time.Since(start).Nanoseconds()
	fmt.Printf("use mutex a is %d, spend time: %v\n", a, timeSpends)
}

func TestAtomicAdd(t *testing.T) {
	var a int32 = 0
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < 1000000; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			atomic.AddInt32(&a, 1)
		}()
	}
	wg.Wait()
	timeSpends := time.Since(start).Nanoseconds()
	fmt.Printf("use atomic a is %d, spend time: %v\n", atomic.LoadInt32(&a), timeSpends)
}
