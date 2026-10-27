package server

import (
	"io"
	"sync/atomic"
	"time"
)

// idleWatch fires onIdle once no data has moved for d. Each touch postpones it,
// so a busy connection is never cut however long it lives.
type idleWatch struct {
	d      time.Duration
	last   atomic.Int64 // unix nanos of the last transfer
	timer  *time.Timer
	onIdle func()
}

func newIdleWatch(d time.Duration, onIdle func()) *idleWatch {
	w := &idleWatch{d: d, onIdle: onIdle}
	w.last.Store(time.Now().UnixNano())
	w.timer = time.AfterFunc(d, w.check)
	return w
}

func (w *idleWatch) touch() { w.last.Store(time.Now().UnixNano()) }

func (w *idleWatch) stop() { w.timer.Stop() }

func (w *idleWatch) check() {
	idle := time.Since(time.Unix(0, w.last.Load()))
	if idle < w.d {
		w.timer.Reset(w.d - idle)
		return
	}
	w.onIdle()
}

// touchWriter marks activity on every write that passes through it.
type touchWriter struct {
	w io.Writer
	t *idleWatch
}

func (tw touchWriter) Write(p []byte) (int, error) {
	tw.t.touch()
	return tw.w.Write(p)
}
