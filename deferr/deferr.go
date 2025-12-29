package deferr

// ErrCloser is a helper for cleaning up resources in case something later
// fails.
//
// Consider the following example:
//
//	type Component struct {
//	  r1, r2, r3 io.Closer
//	}
//
//	func NewComponent() (c *Component, err error) {
//	  r1, err := initResource1()
//	  if err != nil {
//	    return err
//	  }
//	  r2, err := initResource2()
//	  if err != nil {
//	    // an error means that we need to clean up the resources we initialized
//	    // so far.
//	    defer r1.Close()
//	    return err
//	  }
//	  r3, err := initResource3()
//	  if err != nil {
//	    // and that just keeps growing.
//	    defer r1.Close()
//	    defer r2.Close()
//	    return err
//	  }
//	  ...
//	  return &Component{r1, r2, r3}, nil
//	}
//
// The ErrCloser can be used to make this nicer, here is the same example using
// ErrCloser:
//
//	type Component struct {
//	  r1, r2, r3 io.Closer
//	}
//
//	func NewComponent() (c *Component, err error) {
//	  ec := NewErrCloser(&err)
//	  defer ec.Close()
//	  r1, err := initResource1()
//	  if err != nil {
//	    return nil, err
//	  }
//	  ec.AddClose(r1.Close)
//	  r2, err := initResource2()
//	  if err != nil {
//	    return nil, err
//	  }
//	  ec.AddClose(r2.Close)
//	  ...
//	  r3, err := initResource3()
//	  if err != nil {
//	    return nil, err
//	  }
//	  return &Component{r1, r2, r3}, nil
//	}
//
// Note that the ErrCloser is not safe for concurrent use.
type ErrCloser struct {
	fs []func()
}

func (c *ErrCloser) AddClose(f func() error) {
	c.fs = append(c.fs, func() {
		f()
	})
}

func (c *ErrCloser) Add(f func()) {
	c.fs = append(c.fs, f)
}

// Close calls all functions added to the ErrCloser in reverse order.
func (c *ErrCloser) Close() {
	for i := len(c.fs) - 1; i >= 0; i-- {
		c.fs[i]()
	}
}

// CloseOnErr calls Close if the err is not nil.
func (c *ErrCloser) CloseOnErr(err *error) {
	if *err == nil {
		return // nothing to do
	}
	c.Close()
}
