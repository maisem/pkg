package sqlite

import (
	"context"
	"sync"
	"time"

	"tailscale.com/util/ctxkey"
)

// NewContext returns a new context with a TxTracker attached.
// It should only be used for root contexts, to attach a TxTracker to a child
// context use [AttachTracker].
func NewContext() context.Context {
	return AttachTracker(context.Background())
}

var txTrackerKey = ctxkey.New[*TxTracker]("sqlite.TxTracker", nil)
var UTCNowKey = ctxkey.New[func() time.Time]("sqlite.UTCNow", nil)

// AttachTracker attaches a TxTracker to the context.
func AttachTracker(ctx context.Context) context.Context {
	t := &TxTracker{}
	return txTrackerKey.WithValue(ctx, t)
}

// TxTracker tracks active SQL transactions in a context.
// It ensures that only one transaction is active at a time for a given context.
type TxTracker struct {
	mu     sync.Mutex
	cur    handle
	curWhy string
}

// handle is a pointer type used as a unique identifier for a transaction.
// We use a byte pointer as a lightweight unique identifier rather than
// storing the actual transaction object.
type handle *byte

// Track returns a function that untracks the tx from the tracker. It is safe to
// call this function multiple times.
func (t *TxTracker) Track(why string) (untrackOnce func()) {
	h := handle(new(byte))
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cur != nil {
		// We explicitly want to panic here because it is a programmer error to
		// have an active tx when we attach a new one. Rather than being lenient
		// and overwriting the tx, we want to crash hard.
		panic("active tx already set")
	}
	t.cur = h
	t.curWhy = why
	return sync.OnceFunc(func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		if t.cur != h {
			panic("untracked tx")
		}
		t.cur = nil
		t.curWhy = ""
	})
}
