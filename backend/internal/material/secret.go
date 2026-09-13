package material

import (
	"errors"
	"sync"
)

var ErrDestroyed = errors.New("secret ownership is no longer available")
var ErrBorrowed = errors.New("secret has active borrowers")

// Secret owns one allocation. Copying a handle does not copy its ownership state.
// Borrowed bytes must not be retained, modified, or used after the callback returns.
type Secret struct{ state *secretState }
type secretState struct {
	mu        sync.Mutex
	bytes     []byte
	borrowers int
	closed    bool
}

// Adopt transfers the entire buffer capacity; the caller must stop using it.
func Adopt(raw []byte) *Secret { return &Secret{state: &secretState{bytes: raw}} }

// AdoptResult erases partial output on error and never returns a partial owner.
func AdoptResult(raw []byte, err error) (*Secret, error) {
	if err != nil {
		Wipe(raw)
		return nil, err
	}
	return Adopt(raw), nil
}

// Wipe overwrites the owned allocation, including unused capacity.
func Wipe(raw []byte) { clear(raw[:cap(raw)]) }

// Borrow pins the buffer until fn returns, including on error or panic.
// Destroy may be called from fn; erasure then waits for the last borrower.
func (s *Secret) Borrow(fn func([]byte) error) error {
	if s == nil || s.state == nil {
		return ErrDestroyed
	}
	st := s.state
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		return ErrDestroyed
	}
	st.borrowers++
	raw := st.bytes[:len(st.bytes):len(st.bytes)]
	st.mu.Unlock()
	defer func() {
		st.mu.Lock()
		defer st.mu.Unlock()
		st.borrowers--
		if st.closed && st.borrowers == 0 {
			Wipe(st.bytes)
			st.bytes = nil
		}
	}()
	return fn(raw)
}

// Transfer invalidates every copy of this handle without copying the buffer.
// An active borrow must finish before ownership can move.
func (s *Secret) Transfer() (*Secret, error) {
	if s == nil || s.state == nil {
		return nil, ErrDestroyed
	}
	st := s.state
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.closed {
		return nil, ErrDestroyed
	}
	if st.borrowers != 0 {
		return nil, ErrBorrowed
	}
	next := Adopt(st.bytes)
	st.bytes = nil
	st.closed = true
	return next, nil
}

// Destroy is idempotent. Existing borrows finish before the buffer is erased;
// new borrows and transfers are rejected as soon as Destroy is called.
func (s *Secret) Destroy() {
	if s == nil || s.state == nil {
		return
	}
	st := s.state
	st.mu.Lock()
	defer st.mu.Unlock()
	st.closed = true
	if st.borrowers == 0 {
		Wipe(st.bytes)
		st.bytes = nil
	}
}

// IsEmpty reports the presence of a usable optional field without copying it.
func (s *Secret) IsEmpty() bool {
	if s == nil || s.state == nil {
		return true
	}
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	return s.state.closed || len(s.state.bytes) == 0
}

// Move preserves absent optional fields while invalidating a present source.
func Move(s *Secret) (*Secret, error) {
	if s == nil {
		return nil, nil
	}
	return s.Transfer()
}

// Use borrows an optional field for a single operation without copying it.
func Use[T any](s *Secret, fn func([]byte) (T, error)) (T, error) {
	if s == nil {
		return fn(nil)
	}
	var out T
	err := s.Borrow(func(raw []byte) error {
		var err error
		out, err = fn(raw)
		return err
	})
	return out, err
}

// UsePair borrows two optional fields for one operation.
func UsePair[T any](a, b *Secret, fn func([]byte, []byte) (T, error)) (T, error) {
	return Use(a, func(left []byte) (T, error) {
		return Use(b, func(right []byte) (T, error) { return fn(left, right) })
	})
}
