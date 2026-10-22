package server

import (
	"errors"
	"io"
	"sync/atomic"
)

// DefaultMaxBufferedBodyBytes caps the request-body bytes held in memory across
// all in-flight requests (each body is buffered whole before it is tunneled).
const DefaultMaxBufferedBodyBytes = 256 * 1024 * 1024

// errBodyBudgetExceeded is returned while reading a request body when the
// server-wide buffering budget is used up.
var errBodyBudgetExceeded = errors.New("too many request bodies buffered")

// byteBudget is a server-wide cap on buffered bytes. A nil budget is unlimited.
type byteBudget struct {
	max  int64
	used atomic.Int64
}

func newByteBudget(limit int64) *byteBudget {
	if limit <= 0 {
		return nil
	}
	return &byteBudget{max: limit}
}

func (b *byteBudget) take(n int64) bool {
	if b == nil {
		return true
	}
	for {
		u := b.used.Load()
		if u+n > b.max {
			return false
		}
		if b.used.CompareAndSwap(u, u+n) {
			return true
		}
	}
}

func (b *byteBudget) give(n int64) {
	if b != nil && n > 0 {
		b.used.Add(-n)
	}
}

// budgetBody charges every byte read from a request body to the budget until
// release is called, so a flood of concurrent (or trickling) large uploads
// cannot buffer an unbounded amount of memory.
type budgetBody struct {
	io.ReadCloser
	budget *byteBudget
	held   int64
}

func (b *budgetBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		if !b.budget.take(int64(n)) {
			return 0, errBodyBudgetExceeded
		}
		b.held += int64(n)
	}
	return n, err
}

// release returns everything this body charged to the budget.
func (b *budgetBody) release() {
	b.budget.give(b.held)
	b.held = 0
}
