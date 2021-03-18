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
	"sync/atomic"
	"time"
)

// goroutinePool is a struct to represent goroutine pool.
type goroutinePool struct {
	stack       []*goroutine
	idleTimeout time.Duration
	sync.Mutex
}

// goroutine is actually a background goroutine, with a channel binded for communication.
type goroutine struct {
	ch     chan func()
	status int32
}

const (
	goroutineStatusIdle  int32 = 0
	goroutineStatusInUse int32 = 1
	goroutineStatusDead  int32 = 2
)

// newGoroutinePool returns a new *goroutinePool object.
func newGoroutinePool(idleTimeout time.Duration) *goroutinePool {
	pool := &goroutinePool{
		idleTimeout: idleTimeout,
		stack:       make([]*goroutine, 0, 20000),
	}
	return pool
}

// Go works like go func(), but goroutines are pooled for reusing.
// This strategy can avoid runtime.morestack, because pooled goroutine is already enlarged.
func (pool *goroutinePool) Go(f func()) {
	for {
		g := pool.get()
		if atomic.CompareAndSwapInt32(&g.status, goroutineStatusIdle, goroutineStatusInUse) {
			g.ch <- f
			return
		}
		// Status already changed from goroutineStatusIdle => goroutineStatusDead, drop it, find next one.
	}
}

func (pool *goroutinePool) get() *goroutine {
	pool.Lock()
	if len(pool.stack) == 0 {
		pool.Unlock()
		return pool.alloc()
	}

	ret := pool.stack[len(pool.stack)-1]
	pool.stack = pool.stack[:len(pool.stack)-1]
	pool.Unlock()
	return ret
}

func (pool *goroutinePool) alloc() *goroutine {
	g := &goroutine{
		ch: make(chan func(), 1),
	}
	go g.workLoop(pool)
	return g
}

func (g *goroutine) put(pool *goroutinePool) {
	g.status = goroutineStatusIdle
	pool.Lock()

	// Recycle dead goroutine space.
	i := 0
	for ; i < len(pool.stack) && atomic.LoadInt32(&pool.stack[i].status) == goroutineStatusDead; i++ {
	}
	pool.stack = append(pool.stack[i:], g)
	pool.Unlock()
}

func (g *goroutine) workLoop(pool *goroutinePool) {
	timer := time.NewTimer(pool.idleTimeout)
	for {
		select {
		case <-timer.C:
			// Check to avoid a corner case that the goroutine is take out from pool,
			// and get this signal at the same time.
			succ := atomic.CompareAndSwapInt32(&g.status, goroutineStatusIdle, goroutineStatusDead)
			if succ {
				return
			}
		case work := <-g.ch:
			work()
			// Put g back to the pool.
			// This is the normal usage for a resource pool:
			//
			//     obj := pool.get()
			//     use(obj)
			//     pool.put(obj)
			//
			// But when goroutine is used as a resource, we can't pool.put() immediately,
			// because the resource(goroutine) maybe still in use.
			// So, put back resource is done here,  when the goroutine finish its work.
			g.put(pool)
		}
		timer.Reset(pool.idleTimeout)
	}
}
