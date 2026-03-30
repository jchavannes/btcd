package wire

import (
	"bytes"
	"fmt"
	"io"
)

// MsgAuthCh defines a bitcoin authch message used for authentication challenges.
type MsgAuthCh struct {
	Data []byte
}

func (msg *MsgAuthCh) BtcDecode(r io.Reader, pver uint32) error {
	buf, ok := r.(*bytes.Buffer)
	if !ok {
		return fmt.Errorf("MsgAuthCh.BtcDecode reader is not a *bytes.Buffer")
	}
	msg.Data = buf.Bytes()
	buf.Reset()
	return nil
}

func (msg *MsgAuthCh) BtcEncode(w io.Writer, pver uint32) error {
	_, err := w.Write(msg.Data)
	return err
}

func (msg *MsgAuthCh) Command() string {
	return CmdAuthCh
}

func (msg *MsgAuthCh) MaxPayloadLength(pver uint32) uint32 {
	return MaxMessagePayload
}
