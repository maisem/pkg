// Copyright (c) 2025 AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package lazy

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSyncMapGet(t *testing.T) {
	var sm SyncMap[string, int]
	if got := sm.Get("42", func() int { return 42 }); got != 42 {
		t.Fatalf("Get = %v; want 42", got)
	}
	if got := sm.Len(); got != 1 {
		t.Fatalf("Len = %v; want 1", got)
	}

	n := int(testing.AllocsPerRun(1000, func() {
		got := sm.Get("42", func() int {
			t.Fatal("fill called after value was cached")
			return 0
		})
		if got != 42 {
			t.Fatalf("Get = %v; want 42", got)
		}
	}))
	if n != 0 {
		t.Errorf("allocs = %v; want 0", n)
	}
}

func TestSyncMapGetErr(t *testing.T) {
	var sm SyncMap[string, int]
	wantErr := errors.New("boom")
	var calls int
	got, err := sm.GetErr("42", func() (int, error) {
		calls++
		return 12, wantErr
	})
	if got != 12 || !errors.Is(err, wantErr) {
		t.Fatalf("GetErr = %v, %v; want 12, %v", got, err, wantErr)
	}

	got, err = sm.GetErr("42", func() (int, error) {
		t.Fatal("fill called after error was cached")
		return 0, nil
	})
	if got != 12 || !errors.Is(err, wantErr) {
		t.Fatalf("second GetErr = %v, %v; want 12, %v", got, err, wantErr)
	}
	if calls != 1 {
		t.Fatalf("fill calls = %v; want 1", calls)
	}
}

func TestSyncMapSet(t *testing.T) {
	var sm SyncMap[string, int]
	if !sm.Set("42", 42) {
		t.Fatal("first Set failed")
	}
	if sm.Set("42", 43) {
		t.Fatal("second Set succeeded")
	}
	if got := sm.Get("42", func() int { return 0 }); got != 42 {
		t.Fatalf("Get = %v; want 42", got)
	}
}

func TestSyncMapDelete(t *testing.T) {
	var sm SyncMap[string, int]
	if got := sm.Get("42", func() int { return 42 }); got != 42 {
		t.Fatalf("Get = %v; want 42", got)
	}
	sm.Delete("42")
	if got := sm.Len(); got != 0 {
		t.Fatalf("Len = %v; want 0", got)
	}

	var calls int
	if got := sm.Get("42", func() int {
		calls++
		return 43
	}); got != 43 {
		t.Fatalf("Get after Delete = %v; want 43", got)
	}
	if calls != 1 {
		t.Fatalf("fill calls = %v; want 1", calls)
	}
}

func TestSyncMapSetAfterDelete(t *testing.T) {
	var sm SyncMap[string, int]
	sm.MustSet("42", 42)
	sm.Delete("42")
	if !sm.Set("42", 43) {
		t.Fatal("Set after Delete failed")
	}
	if got := sm.Get("42", func() int { return 0 }); got != 43 {
		t.Fatalf("Get = %v; want 43", got)
	}
}

func TestSyncMapReplace(t *testing.T) {
	var sm SyncMap[string, int]
	if got := sm.Get("42", func() int { return 42 }); got != 42 {
		t.Fatalf("Get = %v; want 42", got)
	}

	sm.Replace("42", 43)
	if sm.Set("42", 44) {
		t.Fatal("Set succeeded after Replace")
	}
	if got := sm.Get("42", func() int {
		t.Fatal("fill called after Replace")
		return 0
	}); got != 43 {
		t.Fatalf("Get = %v; want 43", got)
	}
}

func TestSyncMapReplaceUsesFreshSlot(t *testing.T) {
	var (
		sm      SyncMap[string, int]
		filling = make(chan struct{})
		release = make(chan struct{})
		done    = make(chan int, 1)
	)
	go func() {
		done <- sm.Get("42", func() int {
			close(filling)
			<-release
			return 42
		})
	}()

	select {
	case <-filling:
	case <-time.After(time.Second):
		t.Fatal("fill was not called")
	}
	sm.Replace("42", 43)
	if got := sm.Get("42", func() int {
		t.Fatal("fill called after Replace")
		return 0
	}); got != 43 {
		t.Fatalf("Get after Replace = %v; want 43", got)
	}

	close(release)
	if got := <-done; got != 42 {
		t.Fatalf("in-flight Get = %v; want 42", got)
	}
}

func TestSyncMapReplaceAfterError(t *testing.T) {
	var sm SyncMap[string, int]
	wantErr := errors.New("boom")
	if got, err := sm.GetErr("42", func() (int, error) {
		return 12, wantErr
	}); got != 12 || !errors.Is(err, wantErr) {
		t.Fatalf("GetErr = %v, %v; want 12, %v", got, err, wantErr)
	}

	sm.Replace("42", 43)
	if got, err := sm.GetErr("42", func() (int, error) {
		t.Fatal("fill called after Replace")
		return 0, nil
	}); got != 43 || err != nil {
		t.Fatalf("GetErr = %v, %v; want 43, nil", got, err)
	}
}

func TestSyncMapRefill(t *testing.T) {
	var sm SyncMap[string, int]
	if got := sm.Get("42", func() int { return 42 }); got != 42 {
		t.Fatalf("Get = %v; want 42", got)
	}

	var calls int
	if got := sm.Refill("42", func() int {
		calls++
		return 43
	}); got != 43 {
		t.Fatalf("Refill = %v; want 43", got)
	}
	if calls != 1 {
		t.Fatalf("fill calls = %v; want 1", calls)
	}
	if got := sm.Get("42", func() int {
		t.Fatal("fill called after Refill")
		return 0
	}); got != 43 {
		t.Fatalf("Get = %v; want 43", got)
	}
}

func TestSyncMapRefillBlocksLaterGet(t *testing.T) {
	var (
		sm       SyncMap[string, int]
		filling  = make(chan struct{})
		release  = make(chan struct{})
		refilled = make(chan int, 1)
		gotCh    = make(chan int, 1)
	)
	sm.MustSet("42", 42)

	go func() {
		refilled <- sm.Refill("42", func() int {
			close(filling)
			<-release
			return 43
		})
	}()
	select {
	case <-filling:
	case <-time.After(time.Second):
		t.Fatal("fill was not called")
	}

	go func() {
		gotCh <- sm.Get("42", func() int {
			t.Fatal("fill called after Refill")
			return 0
		})
	}()
	select {
	case v := <-gotCh:
		t.Fatalf("Get returned during Refill with %v", v)
	case <-time.After(10 * time.Millisecond):
	}

	close(release)
	if got := <-refilled; got != 43 {
		t.Fatalf("Refill = %v; want 43", got)
	}
	if got := <-gotCh; got != 43 {
		t.Fatalf("Get after Refill = %v; want 43", got)
	}
}

func TestSyncMapRefillPanicsLeavesExistingValue(t *testing.T) {
	var sm SyncMap[string, int]
	sm.MustSet("42", 42)
	func() {
		defer func() {
			if e := recover(); e == nil {
				t.Fatal("Refill succeeded")
			}
		}()
		sm.Refill("42", func() int {
			panic("boom")
		})
	}()
	if got := sm.Get("42", func() int { return 0 }); got != 42 {
		t.Fatalf("Get = %v; want 42", got)
	}
}

func TestSyncMapMustSet(t *testing.T) {
	var sm SyncMap[string, int]
	sm.MustSet("42", 42)
	defer func() {
		if e := recover(); e == nil {
			t.Fatal("second MustSet succeeded")
		}
	}()
	sm.MustSet("42", 43)
}

func TestSyncMapConcurrentGetCallsFillOnce(t *testing.T) {
	var (
		sm      SyncMap[string, int]
		calls   atomic.Int32
		wg      sync.WaitGroup
		start   = make(chan struct{})
		filled  = make(chan struct{})
		release = make(chan struct{})
		once    sync.Once
	)

	const routines = 100
	wg.Add(routines)
	for range routines {
		go func() {
			defer wg.Done()
			<-start
			got := sm.Get("42", func() int {
				calls.Add(1)
				once.Do(func() { close(filled) })
				<-release
				return 42
			})
			if got != 42 {
				t.Errorf("Get = %v; want 42", got)
			}
		}()
	}

	close(start)
	select {
	case <-filled:
	case <-time.After(time.Second):
		t.Fatal("fill was not called")
	}
	close(release)
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Fatalf("fill calls = %v; want 1", got)
	}
}

func TestSyncMapFillCanInitializeAnotherKey(t *testing.T) {
	var sm SyncMap[string, int]
	done := make(chan int, 1)
	go func() {
		done <- sm.Get("a", func() int {
			return sm.Get("b", func() int { return 2 }) + 1
		})
	}()

	var got int
	select {
	case got = <-done:
	case <-time.After(time.Second):
		t.Fatal("fill blocked while initializing another key")
	}
	if got != 3 {
		t.Fatalf("Get = %v; want 3", got)
	}
	if got := sm.Len(); got != 2 {
		t.Fatalf("Len = %v; want 2", got)
	}
}
