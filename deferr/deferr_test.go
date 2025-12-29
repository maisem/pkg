package deferr

import (
	"errors"
	"slices"
	"testing"
)

func TestErrCloser(t *testing.T) {
	tests := []struct {
		name       string
		retErr     error
		shouldCall bool
	}{
		{name: "nil", retErr: nil, shouldCall: false},
		{name: "error", retErr: errors.New("test"), shouldCall: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var called bool
			f := func() {
				called = true
			}
			err := func() (err error) {
				var dc ErrCloser
				defer dc.CloseOnErr(&err)
				dc.Add(f)
				return test.retErr
			}()
			if err != test.retErr {
				t.Errorf("expected err=%v, got %v", test.retErr, err)
			}
			if test.shouldCall != called {
				t.Errorf("expected called=%v, got %v", test.shouldCall, called)
			}
		})
	}
}

func TestErrCloserCallOrder(t *testing.T) {
	var called []string
	f := func(s string) func() {
		return func() {
			called = append(called, s)
		}
	}
	var dc ErrCloser
	dc.Add(f("a"))
	dc.Add(f("b"))
	dc.Add(f("c"))
	dc.Close()
	if !slices.Equal(called, []string{"c", "b", "a"}) {
		t.Errorf("expected called=[c,b,a], got %v", called)
	}
}
