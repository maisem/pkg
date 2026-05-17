// Copyright (c) 2025 AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package lazy provides helpers for lazily initialized values.
package lazy

import (
	"sync"

	"tailscale.com/syncs"
	tslazy "tailscale.com/types/lazy"
)

// SyncMap is a map of lazily computed Tailscale SyncValue entries, keyed by a
// comparable type.
//
// Use either Get or GetErr, depending on whether your fill function returns an
// error.
//
// Recursive use of a SyncMap key from its own fill function will deadlock.
//
// SyncMap is safe for concurrent use.
type SyncMap[K comparable, V any] struct {
	store syncs.Map[K, *syncMapEntry[V]]
}

// Len returns the number of entries in the map.
func (s *SyncMap[K, V]) Len() int {
	return s.store.Len()
}

// Delete deletes the value for k.
func (s *SyncMap[K, V]) Delete(k K) {
	s.store.Delete(k)
}

// Init attempts to set the value of k to v, and reports whether it succeeded.
// Init only succeeds if k has never been called with Get/GetErr/Init before.
func (s *SyncMap[K, V]) Init(k K, v V) bool {
	return s.entry(k).init(v)
}

// Replace replaces the value of k with v, even if k already has a value.
func (s *SyncMap[K, V]) Replace(k K, v V) {
	s.entry(k).replace(v)
}

// Refill calls fill and replaces the value of k with its result.
// Refill locks only the entry for k while fill runs, so operations blocked
// behind Refill see the replacement without blocking operations on other keys.
// If fill panics, the existing value is left unchanged.
func (s *SyncMap[K, V]) Refill(k K, fill func() V) V {
	return s.entry(k).refill(fill)
}

// Get returns the value for k, computing it with fill if it's not already
// present.
func (s *SyncMap[K, V]) Get(k K, fill func() V) V {
	return s.entry(k).get(fill)
}

// GetErr returns the value for k, computing it with fill if it's not already
// present.
func (s *SyncMap[K, V]) GetErr(k K, fill func() (V, error)) (V, error) {
	return s.entry(k).getErr(fill)
}

func (s *SyncMap[K, V]) entry(k K) *syncMapEntry[V] {
	e, _ := s.store.LoadOrInit(k, newSyncMapEntry[V])
	return e
}

type syncMapEntry[V any] struct {
	mu sync.Mutex
	z  *tslazy.SyncValue[V]
}

func newSyncMapEntry[V any]() *syncMapEntry[V] {
	return &syncMapEntry[V]{z: new(tslazy.SyncValue[V])}
}

func filledSyncValue[V any](v V) *tslazy.SyncValue[V] {
	z := new(tslazy.SyncValue[V])
	z.MustSet(v)
	return z
}

func (e *syncMapEntry[V]) init(v V) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.z.Set(v)
}

func (e *syncMapEntry[V]) replace(v V) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.z = filledSyncValue(v)
}

func (e *syncMapEntry[V]) refill(fill func() V) V {
	e.mu.Lock()
	defer e.mu.Unlock()
	v := fill()
	e.z = filledSyncValue(v)
	return v
}

func (e *syncMapEntry[V]) get(fill func() V) V {
	e.mu.Lock()
	z := e.z
	e.mu.Unlock()
	return z.Get(fill)
}

func (e *syncMapEntry[V]) getErr(fill func() (V, error)) (V, error) {
	e.mu.Lock()
	z := e.z
	e.mu.Unlock()
	return z.GetErr(fill)
}
