package whitelist

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

type TidyHandler struct {
	tidyWhitelistCASGuard uint32
}

func (h *TidyHandler) PathTidyIdentityWhitelist() *framework.Path {
	return &framework.Path{
		Pattern: "tidy/identity-whitelistConfig$",
		Fields: map[string]*framework.FieldSchema{
			"safety_buffer": {
				Type:    framework.TypeDurationSecond,
				Default: 259200,
				Description: `The amount of extra time that must have passed beyond the identity's
expiration, before it is removed from the backend storage.`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: h.pathTidyIdentityWhitelistUpdate,
		},

		HelpSynopsis:    pathTidyIdentityWhitelistSyn,
		HelpDescription: pathTidyIdentityWhitelistDesc,
	}
}

// TidyWhitelistIdentity is used to delete entries in the whitelistConfig that are expired.
func (h *TidyHandler) TidyWhitelistIdentity(ctx context.Context, s logical.Storage, safety_buffer int) error {
	grabbed := atomic.CompareAndSwapUint32(&h.tidyWhitelistCASGuard, 0, 1)
	if grabbed {
		defer atomic.StoreUint32(&h.tidyWhitelistCASGuard, 0)
	} else {
		return fmt.Errorf("identity whitelistConfig tidy operation already running")
	}

	bufferDuration := time.Duration(safety_buffer) * time.Second

	identities, err := s.List(ctx, "whitelistConfig/identity/")
	if err != nil {
		return err
	}

	for _, instanceID := range identities {
		identityEntry, err := s.Get(ctx, "whitelistConfig/identity/"+instanceID)
		if err != nil {
			return errwrap.Wrapf(fmt.Sprintf("error fetching identity of instanceID %q: {{err}}", instanceID), err)
		}

		if identityEntry == nil {
			return fmt.Errorf("identity entry for instanceID %q is nil", instanceID)
		}

		if identityEntry.Value == nil || len(identityEntry.Value) == 0 {
			return fmt.Errorf("found identity entry for instanceID %q but actual identity is empty", instanceID)
		}

		var result *Identity
		if err := identityEntry.DecodeJSON(&result); err != nil {
			return err
		}

		if time.Now().After(result.ExpirationTime.Add(bufferDuration)) {
			if err := s.Delete(ctx, "whitelistConfig/identity"+instanceID); err != nil {
				return errwrap.Wrapf(fmt.Sprintf("error deleting identity of instanceID %q from storage: {{err}}", instanceID), err)
			}
		}
	}

	return nil
}

// pathTidyIdentityWhitelistUpdate is used to delete entries in the whitelistConfig that are expired.
func (h *TidyHandler) pathTidyIdentityWhitelistUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return nil, h.TidyWhitelistIdentity(ctx, req.Storage, data.Get("safety_buffer").(int))
}

const pathTidyIdentityWhitelistSyn = `
Clean-up the whitelistConfig instance identity entries.
`

const pathTidyIdentityWhitelistDesc = `
When an instance identity is whitelisted, the expiration time of the whitelistConfig
entry is set based on the maximum 'max_ttl' value set on: the role, the role tag
and the backend's mount.

When this endpoint is invoked, all the entries that are expired will be deleted.
A 'safety_buffer' (duration in seconds) can be provided, to ensure deletion of
only those entries that are expired before 'safety_buffer' seconds. 
`
