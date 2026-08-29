package runnerwire

import (
	"bufio"
	"errors"
	"fmt"
	"io"
)

var (
	ErrEmptyFrame    = errors.New("empty HRP/1 frame")
	ErrFrameTooLarge = errors.New("HRP/1 frame exceeds line limit")
)

// Decoder reads HRP/1 JSON Lines. A framing or protocol error is fatal for the
// stream; callers must not attempt to resynchronize an untrusted runner stream.
type Decoder struct {
	reader *bufio.Reader
}

func NewDecoder(reader io.Reader) *Decoder {
	return &Decoder{reader: bufio.NewReaderSize(reader, 4096)}
}

func (d *Decoder) Decode() (Frame, error) {
	if d == nil || d.reader == nil {
		return nil, errors.New("runnerwire: nil decoder")
	}
	line, err := d.readLine()
	if err != nil {
		return nil, err
	}
	return DecodeFrame(line)
}

func (d *Decoder) DecodeRunnerFrame() (RunnerFrame, error) {
	frame, err := d.Decode()
	if err != nil {
		return nil, err
	}
	runner, ok := frame.(RunnerFrame)
	if !ok {
		return nil, fmt.Errorf("%w: got %q on runner channel", ErrUnexpectedFrameType, frame.FrameType())
	}
	return runner, nil
}

func (d *Decoder) DecodeControllerFrame() (ControllerFrame, error) {
	frame, err := d.Decode()
	if err != nil {
		return nil, err
	}
	controller, ok := frame.(ControllerFrame)
	if !ok {
		return nil, fmt.Errorf("%w: got %q on controller channel", ErrUnexpectedFrameType, frame.FrameType())
	}
	return controller, nil
}

func (d *Decoder) readLine() ([]byte, error) {
	line := make([]byte, 0, 4096)
	for {
		fragment, prefix, err := d.reader.ReadLine()
		if len(line)+len(fragment) > MaxFrameBytes {
			return nil, ErrFrameTooLarge
		}
		line = append(line, fragment...)
		if err != nil {
			if errors.Is(err, io.EOF) && len(line) > 0 {
				break
			}
			return nil, err
		}
		if !prefix {
			break
		}
	}
	if len(line) == 0 {
		return nil, ErrEmptyFrame
	}
	return line, nil
}

type Encoder struct {
	writer io.Writer
}

func NewEncoder(writer io.Writer) *Encoder {
	return &Encoder{writer: writer}
}

// Encode writes exactly one validated frame followed by LF.
func (e *Encoder) Encode(frame Frame) error {
	if e == nil || e.writer == nil {
		return errors.New("runnerwire: nil encoder")
	}
	data, err := MarshalFrame(frame)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	for len(data) > 0 {
		written, writeErr := e.writer.Write(data)
		if written > 0 {
			data = data[written:]
		}
		if writeErr != nil {
			return fmt.Errorf("write HRP/1 frame: %w", writeErr)
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
