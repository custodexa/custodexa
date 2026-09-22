package sshproxy

import (
	"io"
	"sync"
)

type transportFrame struct {
	kind int
	data []byte
}
type transportPipe struct {
	done chan struct{}
	once sync.Once
}

// InProcessTransport carries the same framed messages as WebSocket through bounded
// memory queues. Closing either endpoint wakes blocked readers and writers.
type InProcessTransport struct {
	pipe    *transportPipe
	in, out chan transportFrame
}

func NewInProcessTransportPair() (*InProcessTransport, *InProcessTransport) {
	p := &transportPipe{done: make(chan struct{})}
	a, b := make(chan transportFrame, 128), make(chan transportFrame, 128)
	return &InProcessTransport{p, a, b}, &InProcessTransport{p, b, a}
}
func (t *InProcessTransport) ReadMessage() (int, []byte, error) {
	select {
	case f := <-t.in:
		return f.kind, f.data, nil
	default:
	}
	select {
	case f := <-t.in:
		return f.kind, f.data, nil
	case <-t.pipe.done:
		return 0, nil, io.EOF
	}
}
func (t *InProcessTransport) WriteMessage(kind int, data []byte) error {
	select {
	case <-t.pipe.done:
		return io.ErrClosedPipe
	default:
	}
	f := transportFrame{kind, append([]byte(nil), data...)}
	select {
	case <-t.pipe.done:
		return io.ErrClosedPipe
	case t.out <- f:
		return nil
	}
}
func (t *InProcessTransport) Close() error { t.pipe.once.Do(func() { close(t.pipe.done) }); return nil }
