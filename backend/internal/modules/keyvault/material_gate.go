package keyvault

import (
	"context"
	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/seal"
)

func (s *KeyManagerService) MaterialGate() *seal.MaterialGate { return &s.materialGate }
func gateOf(codec any) *seal.MaterialGate {
	if p, ok := codec.(interface{ MaterialGate() *seal.MaterialGate }); ok {
		return p.MaterialGate()
	}
	return &seal.MaterialGate{}
}
func vaultUse[T any](g *seal.MaterialGate, run func() (T, error), wipe func(T)) (out T, err error) {
	lease, err := g.Borrow()
	if err != nil {
		return out, err
	}
	defer lease.Finish(func(valid bool) {
		if !valid {
			if wipe != nil {
				wipe(out)
			}
			var empty T
			out = empty
			err = seal.ErrMaterialSealed
		}
	})
	return run()
}
func (s *KeyManagerService) DrainMaterial(ctx context.Context) error {
	s.materialGate.CloseWith(nil)
	return s.materialGate.Drain(ctx)
}
func wipePlain(raw []byte) { material.Wipe(raw) }
