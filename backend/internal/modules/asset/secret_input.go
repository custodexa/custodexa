package asset

import (
	"bytes"
	"github.com/custodexa/backend/internal/material"
)

// secretInput erases its owned source after the final read or an early close.
// SSH and WS-Man transport representations remain outside this ownership.
type secretInput struct {
	reader *bytes.Reader
	raw    []byte
}

func newSecretInput(raw []byte) *secretInput {
	return &secretInput{reader: bytes.NewReader(raw), raw: raw}
}
func (s *secretInput) Read(out []byte) (int, error) {
	n, err := s.reader.Read(out)
	if s.reader.Len() == 0 {
		s.Close()
	}
	return n, err
}
func (s *secretInput) Close() { material.Wipe(s.raw) }
