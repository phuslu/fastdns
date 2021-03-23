// Copyright 2017 PingCAP, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// See the License for the specific language governing permissions and
// limitations under the License.
// +build !leak

package fastdns

import (
	"sync"
	"testing"
	"time"
)

func TestBasicAPI(t *testing.T) {
	gp := newGoroutinePool(time.Second)
	var wg sync.WaitGroup
	wg.Add(1)
	// cover alloc()
	gp.Go(func() { wg.Done() })
	// cover put()
	wg.Wait()
	// cover get()
	gp.Go(func() {})
}

func TestGC(t *testing.T) {
	gp := newGoroutinePool(200 * time.Millisecond)
	var wg sync.WaitGroup
	wg.Add(100)
	for i := 0; i < 100; i++ {
		idx := i
		gp.Go(func() {
			time.Sleep(time.Duration(idx+1) * time.Millisecond)
			wg.Done()
		})
	}
	wg.Wait()

	time.Sleep(300 * time.Millisecond)
	gp.Go(func() {}) // To trigger count change.

	gp.Lock()
	count := len(gp.stack)
	gp.Unlock()
	if count > 1 {
		t.Error("all goroutines should be recycled", count)
	}
}

func TestRace(t *testing.T) {
	gp := newGoroutinePool(8 * time.Millisecond)
	var wg sync.WaitGroup
	begin := make(chan struct{})
	wg.Add(500)
	for i := 0; i < 50; i++ {
		go func() {
			<-begin
			for i := 0; i < 10; i++ {
				gp.Go(func() {
					wg.Done()
				})
				time.Sleep(5 * time.Millisecond)
			}
		}()
	}
	close(begin)
	wg.Wait()
}
