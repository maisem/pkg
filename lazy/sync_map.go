// Copyright (c) 2025 AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package lazy provides helpers for lazily initialized values.
package lazy

import (
	"tailscale.com/syncs"
	tslazy "tailscale.com/types/lazy"
)

// SyncMap is a map of lazily computed Tailscale SyncValue pointers, keyed by
// a comparable type.
//
// Use either Get or GetErr, depending on whether your fill function returns an
// error.
//
// Recursive use of a SyncMap key from its own fill function will deadlock.
//
// SyncMap is safe for concurrent use.
type SyncMap[K comparable, V any] struct {
	store syncs.Map[K, *tslazy.SyncValue[V]]
}

// Len returns the number of entries in the map.
func (s *SyncMap[K, V]) Len() int {
	return s.store.Len()
}

// Delete deletes the value for k.
func (s *SyncMap[K, V]) Delete(k K) {
	s.store.Delete(k)
}

// Set attempts to set the value of k to v, and reports whether it succeeded.
// Set only succeeds if k has never been called with Get/GetErr/Set before.
func (s *SyncMap[K, V]) Set(k K, v V) bool {
	return s.value(k).Set(v)
}

// Replace replaces the value of k with v, even if k already has a value.
func (s *SyncMap[K, V]) Replace(k K, v V) {
	s.store.WithLock(func(m map[K]*tslazy.SyncValue[V]) {
		z := new(tslazy.SyncValue[V])
		z.MustSet(v)
		m[k] = z
	})
}

// Refill calls fill and replaces the value of k with its result.
// The map lock is held while fill runs, so operations blocked behind Refill
// see the replacement. fill must not call methods on s.
// If fill panics, the existing value is left unchanged.
func (s *SyncMap[K, V]) Refill(k K, fill func() V) V {
	var v V
	s.store.WithLock(func(m map[K]*tslazy.SyncValue[V]) {
		v = fill()
		z := new(tslazy.SyncValue[V])
		z.MustSet(v)
		m[k] = z
	})
	return v
}

// MustSet sets the value of k to v, or panics if k already has a value.
func (s *SyncMap[K, V]) MustSet(k K, v V) {
	if !s.Set(k, v) {
		panic("Set after already filled")
	}
}

// Get returns the value for k, computing it with fill if it's not already
// present.
func (s *SyncMap[K, V]) Get(k K, fill func() V) V {
	return s.value(k).Get(fill)
}

// GetErr returns the value for k, computing it with fill if it's not already
// present.
func (s *SyncMap[K, V]) GetErr(k K, fill func() (V, error)) (V, error) {
	return s.value(k).GetErr(fill)
}

func (s *SyncMap[K, V]) value(k K) *tslazy.SyncValue[V] {
	z, _ := s.store.LoadOrInit(k, func() *tslazy.SyncValue[V] {
		return new(tslazy.SyncValue[V])
	})
	return z
}
