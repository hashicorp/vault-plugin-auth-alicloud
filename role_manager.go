package ali

import (
	"context"
	"sync"

	"github.com/hashicorp/vault/logical"
)

type RoleManager struct {
	roleMutex sync.RWMutex
}

func (m *RoleManager) Read(ctx context.Context, s logical.Storage, roleName string) (*roleEntry, error) {
	m.roleMutex.RLock()
	defer m.roleMutex.RUnlock()
	return m.getRole(ctx, s, roleName)
}

func (m *RoleManager) List(ctx context.Context, s logical.Storage) ([]string, error) {
	m.roleMutex.RLock()
	defer m.roleMutex.RUnlock()
	return s.List(ctx, "role/")
}

func (m *RoleManager) Update(ctx context.Context, s logical.Storage, roleName string, roleEntry *roleEntry) error {
	m.roleMutex.Lock()
	defer m.roleMutex.Unlock()
	return m.setRole(ctx, s, roleName, roleEntry)
}

func (m *RoleManager) Delete(ctx context.Context, s logical.Storage, roleName string) error {
	m.roleMutex.Lock()
	defer m.roleMutex.Unlock()
	return s.Delete(ctx, "role/"+roleName)
}

func (m *RoleManager) getRole(ctx context.Context, s logical.Storage, roleName string) (*roleEntry, error) {
	entry, err := s.Get(ctx, "role/"+roleName)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var result roleEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (m *RoleManager) setRole(ctx context.Context, s logical.Storage, roleName string, roleEntry *roleEntry) error {
	entry, err := logical.StorageEntryJSON("role/"+roleName, roleEntry)
	if err != nil {
		return err
	}
	if err := s.Put(ctx, entry); err != nil {
		return err
	}
	return nil
}
