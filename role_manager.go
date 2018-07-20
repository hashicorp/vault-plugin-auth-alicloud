package ali

import (
	"context"

	"github.com/hashicorp/vault/logical"
)

func NewRoleManager() *RoleManager {
	return &RoleManager{
		prefix: "role/",
	}
}

type RoleManager struct {
	prefix string
}

func (r *RoleManager) Read(ctx context.Context, s logical.Storage, roleName string) (*roleEntry, error) {
	entry, err := s.Get(ctx, r.prefix+roleName)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	result := &roleEntry{}
	if err := entry.DecodeJSON(result); err != nil {
		return nil, err
	}
	return result, nil
}

func (r *RoleManager) List(ctx context.Context, s logical.Storage) ([]string, error) {
	return s.List(ctx, r.prefix)
}

func (r *RoleManager) Update(ctx context.Context, s logical.Storage, roleName string, roleEntry *roleEntry) error {
	entry, err := logical.StorageEntryJSON(r.prefix+roleName, roleEntry)
	if err != nil {
		return err
	}
	if err := s.Put(ctx, entry); err != nil {
		return err
	}
	return nil
}

func (r *RoleManager) Delete(ctx context.Context, s logical.Storage, roleName string) error {
	return s.Delete(ctx, r.prefix+roleName)
}
