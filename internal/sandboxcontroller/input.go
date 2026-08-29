package sandboxcontroller

import (
	"bytes"
	"errors"
	"io"
	"sync"
)

var errRunnerInputClosed = errors.New("sandboxcontroller: runner input frame is closed")

// frameClosingWriter closes runner stdin immediately after the sole HRP/1
// controller frame delimiter is written. JSON string newlines are escaped, so
// the first literal newline unambiguously terminates run.start. This gives
// adapters that read until EOF the same lifecycle as adapters that decode one
// JSONL frame.
type frameClosingWriter struct {
	mu     sync.Mutex
	writer io.WriteCloser
	closed bool
}

func newFrameClosingWriter(writer io.WriteCloser) *frameClosingWriter {
	return &frameClosingWriter{writer: writer}
}

func (w *frameClosingWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.writer == nil {
		return 0, errRunnerInputClosed
	}
	delimiter := bytes.IndexByte(data, '\n')
	if delimiter < 0 {
		return w.writer.Write(data)
	}
	frame := data[:delimiter+1]
	written, writeErr := w.writer.Write(frame)
	if written == len(frame) {
		w.closed = true
		closeErr := w.writer.Close()
		if writeErr == nil {
			writeErr = closeErr
		}
	}
	if written < len(data) && writeErr == nil {
		writeErr = errRunnerInputClosed
	}
	return written, writeErr
}

func (w *frameClosingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.writer == nil {
		return nil
	}
	w.closed = true
	return w.writer.Close()
}

var _ io.WriteCloser = (*frameClosingWriter)(nil)
