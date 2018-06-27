package blacklist

import (
	"context"
	"fmt"

	"sync"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const (
	roletagBlacklistConfigPath = "config/tidy/roletag-blacklist"
)

type ConfigHandler struct {
	configMutex sync.RWMutex
}

func (h *ConfigHandler) PathConfigTidyRoletagBlacklist() *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("%s$", roletagBlacklistConfigPath),
		Fields: map[string]*framework.FieldSchema{
			"safety_buffer": {
				Type:    framework.TypeDurationSecond,
				Default: 15552000, //180d
				Description: `The amount of extra time that must have passed beyond the roletag
expiration, before it is removed from the backend storage.
Defaults to 4320h (180 days).`,
			},

			"disable_periodic_tidy": {
				Type:        framework.TypeBool,
				Default:     false,
				Description: "If set to 'true', disables the periodic tidying of blacklisted entries.",
			},
		},

		ExistenceCheck: h.pathConfigTidyRoletagBlacklistExistenceCheck,

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: h.pathConfigTidyRoletagBlacklistCreateUpdate,
			logical.UpdateOperation: h.pathConfigTidyRoletagBlacklistCreateUpdate,
			logical.ReadOperation:   h.pathConfigTidyRoletagBlacklistRead,
			logical.DeleteOperation: h.pathConfigTidyRoletagBlacklistDelete,
		},

		HelpSynopsis:    pathConfigTidyRoletagBlacklistHelpSyn,
		HelpDescription: pathConfigTidyRoletagBlacklistHelpDesc,
	}
}

func (h *ConfigHandler) pathConfigTidyRoletagBlacklistExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	entry, err := h.LockedConfigTidyRoleTags(ctx, req.Storage)
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

func (h *ConfigHandler) LockedConfigTidyRoleTags(ctx context.Context, s logical.Storage) (*tidyBlacklistRoleTagConfig, error) {
	h.configMutex.RLock()
	defer h.configMutex.RUnlock()

	return h.nonLockedConfigTidyRoleTags(ctx, s)
}

func (h *ConfigHandler) nonLockedConfigTidyRoleTags(ctx context.Context, s logical.Storage) (*tidyBlacklistRoleTagConfig, error) {
	entry, err := s.Get(ctx, roletagBlacklistConfigPath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result tidyBlacklistRoleTagConfig
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (h *ConfigHandler) pathConfigTidyRoletagBlacklistCreateUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	h.configMutex.Lock()
	defer h.configMutex.Unlock()

	configEntry, err := h.nonLockedConfigTidyRoleTags(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if configEntry == nil {
		configEntry = &tidyBlacklistRoleTagConfig{}
	}
	safetyBufferInt, ok := data.GetOk("safety_buffer")
	if ok {
		configEntry.SafetyBuffer = safetyBufferInt.(int)
	} else if req.Operation == logical.CreateOperation {
		configEntry.SafetyBuffer = data.Get("safety_buffer").(int)
	}
	disablePeriodicTidyBool, ok := data.GetOk("disable_periodic_tidy")
	if ok {
		configEntry.DisablePeriodicTidy = disablePeriodicTidyBool.(bool)
	} else if req.Operation == logical.CreateOperation {
		configEntry.DisablePeriodicTidy = data.Get("disable_periodic_tidy").(bool)
	}

	entry, err := logical.StorageEntryJSON(roletagBlacklistConfigPath, configEntry)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (h *ConfigHandler) pathConfigTidyRoletagBlacklistRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	clientConfig, err := h.LockedConfigTidyRoleTags(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if clientConfig == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"safety_buffer":         clientConfig.SafetyBuffer,
			"disable_periodic_tidy": clientConfig.DisablePeriodicTidy,
		},
	}, nil
}

func (h *ConfigHandler) pathConfigTidyRoletagBlacklistDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	h.configMutex.Lock()
	defer h.configMutex.Unlock()

	return nil, req.Storage.Delete(ctx, roletagBlacklistConfigPath)
}

type tidyBlacklistRoleTagConfig struct {
	SafetyBuffer        int  `json:"safety_buffer"`
	DisablePeriodicTidy bool `json:"disable_periodic_tidy"`
}

const pathConfigTidyRoletagBlacklistHelpSyn = `
Configures the periodic tidying operation of the blacklisted role tag entries.
`
const pathConfigTidyRoletagBlacklistHelpDesc = `
By default, the expired entries in the blacklist will be attempted to be removed
periodically. This operation will look for expired items in the list and purges them.
However, there is a safety buffer duration (defaults to 72h), purges the entries
only if they have been persisting this duration, past its expiration time.
`
