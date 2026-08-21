package dispatchtrust

import (
	"testing"

	"github.com/FrankoonG/rendr/transport"
)

type recordingOwnedWriter struct {
	frame         []byte
	authorization transport.FrameDispatchAuthorization
}

func (w *recordingOwnedWriter) WriteOwnedFrameDispatch(
	_ Token,
	frame []byte,
	authorization transport.FrameDispatchAuthorization,
) (int, error) {
	w.frame = frame
	w.authorization = authorization
	return len(frame), nil
}

func TestWritePreservesOwnedFrameAndAuthorization(t *testing.T) {
	frame := []byte("owned-frame")
	authorization := transport.FrameDispatchAuthorization{Sequence: 17, AttemptID: 23}
	writer := new(recordingOwnedWriter)
	n, err := Write(writer, frame, authorization)
	if err != nil || n != len(frame) {
		t.Fatalf("write result=(%d, %v)", n, err)
	}
	if len(writer.frame) == 0 || &writer.frame[0] != &frame[0] {
		t.Fatal("owned-frame boundary copied the backing array")
	}
	if writer.authorization != authorization {
		t.Fatalf("authorization=%+v want %+v", writer.authorization, authorization)
	}
}
