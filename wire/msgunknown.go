package wire

import (
	"bytes"
	"fmt"
	"io"
)

// MsgUnknown is a fallback for unrecognized protocol commands. It reads and
// discards the payload so the connection can continue processing messages.
type MsgUnknown struct {
	command string
	Data    []byte
}

func (msg *MsgUnknown) BtcDecode(r io.Reader, pver uint32) error {
	buf, ok := r.(*bytes.Buffer)
	if !ok {
		return fmt.Errorf("MsgUnknown.BtcDecode reader is not a *bytes.Buffer")
	}
	msg.Data = buf.Bytes()
	buf.Reset()
	return nil
}

func (msg *MsgUnknown) BtcEncode(w io.Writer, pver uint32) error {
	_, err := w.Write(msg.Data)
	return err
}

func (msg *MsgUnknown) Command() string {
	return msg.command
}

func (msg *MsgUnknown) MaxPayloadLength(pver uint32) uint64 {
	return MaxMessagePayload
}
