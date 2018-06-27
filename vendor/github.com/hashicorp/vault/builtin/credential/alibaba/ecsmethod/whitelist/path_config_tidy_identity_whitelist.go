package whitelist

import (
	"context"
	"fmt"
	"sync"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const (
	identityWhitelistConfigPath = "config/tidy/identity-whitelist"
)

type ConfigHandler struct {
	configMutex sync.RWMutex
}

func (h *ConfigHandler) PathConfigTidyIdentityWhitelist() *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("%s$", identityWhitelistConfigPath),
		Fields: map[string]*framework.FieldSchema{
			"safety_buffer": {
				Type:    framework.TypeDurationSecond,
				Default: 259200, //72h
				Description: `The amount of extra time that must have passed beyond the identity's
expiration, before it is removed from the backend storage.`,
			},
			"disable_periodic_tidy": {
				Type:        framework.TypeBool,
				Default:     false,
				Description: "If set to 'true', disables the periodic tidying of the 'identity-whitelist/<instance_id>' entries.",
			},
		},

		ExistenceCheck: h.pathConfigTidyIdentityWhitelistExistenceCheck,

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: h.pathConfigTidyIdentityWhitelistCreateUpdate,
			logical.UpdateOperation: h.pathConfigTidyIdentityWhitelistCreateUpdate,
			logical.ReadOperation:   h.pathConfigTidyIdentityWhitelistRead,
			logical.DeleteOperation: h.pathConfigTidyIdentityWhitelistDelete,
		},

		HelpSynopsis:    pathConfigTidyIdentityWhitelistHelpSyn,
		HelpDescription: pathConfigTidyIdentityWhitelistHelpDesc,
	}
}

func (h *ConfigHandler) pathConfigTidyIdentityWhitelistExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	entry, err := h.LockedConfigTidyIdentities(ctx, req.Storage)
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

func (h *ConfigHandler) LockedConfigTidyIdentities(ctx context.Context, s logical.Storage) (*tidyWhitelistIdentityConfig, error) {
	h.configMutex.RLock()
	defer h.configMutex.RUnlock()

	return h.nonLockedConfigTidyIdentities(ctx, s)
}

func (h *ConfigHandler) nonLockedConfigTidyIdentities(ctx context.Context, s logical.Storage) (*tidyWhitelistIdentityConfig, error) {
	entry, err := s.Get(ctx, identityWhitelistConfigPath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result tidyWhitelistIdentityConfig
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (h *ConfigHandler) pathConfigTidyIdentityWhitelistCreateUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	h.configMutex.Lock()
	defer h.configMutex.Unlock()

	configEntry, err := h.nonLockedConfigTidyIdentities(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if configEntry == nil {
		configEntry = &tidyWhitelistIdentityConfig{}
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

	entry, err := logical.StorageEntryJSON(identityWhitelistConfigPath, configEntry)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (h *ConfigHandler) pathConfigTidyIdentityWhitelistRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	clientConfig, err := h.LockedConfigTidyIdentities(ctx, req.Storage)
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

func (h *ConfigHandler) pathConfigTidyIdentityWhitelistDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	h.configMutex.Lock()
	defer h.configMutex.Unlock()

	return nil, req.Storage.Delete(ctx, identityWhitelistConfigPath)
}

type tidyWhitelistIdentityConfig struct {
	SafetyBuffer        int  `json:"safety_buffer"`
	DisablePeriodicTidy bool `json:"disable_periodic_tidy"`
}

const pathConfigTidyIdentityWhitelistHelpSyn = `
Configures the periodic tidying operation of the whitelisted identity entries.
`
const pathConfigTidyIdentityWhitelistHelpDesc = `
By default, the expired entries in the whitelist will be attempted to be removed
periodically. This operation will look for expired items in the list and purges them.
However, there is a safety buffer duration (defaults to 72h), purges the entries
only if they have been persisting this duration, past its expiration time.
`
