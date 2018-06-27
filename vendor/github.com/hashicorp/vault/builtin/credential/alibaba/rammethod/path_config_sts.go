package rammethod

import (
	"context"
	"fmt"
	"sync"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// alibabaSTSEntry is used to store details of an STS role for assumption
type alibabaSTSEntry struct {
	StsRole string `json:"sts_role"`
}

type ConfigHandler struct {
	configMutex sync.RWMutex
}

func (h *ConfigHandler) PathListSts() *framework.Path {
	return &framework.Path{
		Pattern: "config/sts/?",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: h.pathStsList,
		},

		HelpSynopsis:    pathListStsHelpSyn,
		HelpDescription: pathListStsHelpDesc,
	}
}

func (h *ConfigHandler) PathConfigSts() *framework.Path {
	return &framework.Path{
		Pattern: "config/sts/" + framework.GenericNameRegex("account_id"),
		Fields: map[string]*framework.FieldSchema{
			"account_id": {
				Type: framework.TypeString,
				Description: `Alibaba account ID to be associated with STS role. If set,
Vault will use assumed credentials to verify any login attempts from ECS
instances in this account.`,
			},
			"sts_role": {
				Type: framework.TypeString,
				Description: `Alibaba ARN for STS role to be assumed when interacting with the account specified.
The Vault server must have permissions to assume this role.`,
			},
		},

		ExistenceCheck: h.pathConfigStsExistenceCheck,

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: h.pathConfigStsCreateUpdate,
			logical.UpdateOperation: h.pathConfigStsCreateUpdate,
			logical.ReadOperation:   h.pathConfigStsRead,
			logical.DeleteOperation: h.pathConfigStsDelete,
		},

		HelpSynopsis:    pathConfigStsSyn,
		HelpDescription: pathConfigStsDesc,
	}
}

// Establishes dichotomy of request operation between CreateOperation and UpdateOperation.
// Returning 'true' forces an UpdateOperation, CreateOperation otherwise.
func (h *ConfigHandler) pathConfigStsExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	accountID := data.Get("account_id").(string)
	if accountID == "" {
		return false, fmt.Errorf("missing account_id")
	}

	entry, err := h.LockedAwsStsEntry(ctx, req.Storage, accountID)
	if err != nil {
		return false, err
	}

	return entry != nil, nil
}

// pathStsList is used to list all the AWS STS role configurations
func (h *ConfigHandler) pathStsList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	h.configMutex.RLock()
	defer h.configMutex.RUnlock()
	sts, err := req.Storage.List(ctx, "config/sts/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(sts), nil
}

// nonLockedSetAwsStsEntry creates or updates an STS role association with the given accountID
// This method does not acquire the write lock before creating or updating. If locking is
// desired, use lockedSetAwsStsEntry instead
func (h *ConfigHandler) nonLockedSetAwsStsEntry(ctx context.Context, s logical.Storage, accountID string, stsEntry *alibabaSTSEntry) error {
	if accountID == "" {
		return fmt.Errorf("missing AWS account ID")
	}

	if stsEntry == nil {
		return fmt.Errorf("missing AWS STS Role ARN")
	}

	entry, err := logical.StorageEntryJSON("config/sts/"+accountID, stsEntry)
	if err != nil {
		return err
	}

	if entry == nil {
		return fmt.Errorf("failed to create storage entry for AWS STS configuration")
	}

	return s.Put(ctx, entry)
}

// lockedSetAwsStsEntry creates or updates an STS role association with the given accountID
// This method acquires the write lock before creating or updating the STS entry.
func (h *ConfigHandler) lockedSetAwsStsEntry(ctx context.Context, s logical.Storage, accountID string, stsEntry *alibabaSTSEntry) error {
	if accountID == "" {
		return fmt.Errorf("missing AWS account ID")
	}

	if stsEntry == nil {
		return fmt.Errorf("missing sts entry")
	}

	h.configMutex.Lock()
	defer h.configMutex.Unlock()

	return h.nonLockedSetAwsStsEntry(ctx, s, accountID, stsEntry)
}

// nonLockedAwsStsEntry returns the STS role associated with the given accountID.
// This method does not acquire the read lock before returning information. If locking is
// desired, use LockedAwsStsEntry instead
func (h *ConfigHandler) nonLockedAwsStsEntry(ctx context.Context, s logical.Storage, accountID string) (*alibabaSTSEntry, error) {
	entry, err := s.Get(ctx, "config/sts/"+accountID)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var stsEntry alibabaSTSEntry
	if err := entry.DecodeJSON(&stsEntry); err != nil {
		return nil, err
	}

	return &stsEntry, nil
}

// LockedAwsStsEntry returns the STS role associated with the given accountID.
// This method acquires the read lock before returning the association.
func (h *ConfigHandler) LockedAwsStsEntry(ctx context.Context, s logical.Storage, accountID string) (*alibabaSTSEntry, error) {
	h.configMutex.RLock()
	defer h.configMutex.RUnlock()

	return h.nonLockedAwsStsEntry(ctx, s, accountID)
}

// pathConfigStsRead is used to return information about an STS role/AWS accountID association
func (h *ConfigHandler) pathConfigStsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	accountID := data.Get("account_id").(string)
	if accountID == "" {
		return logical.ErrorResponse("missing account id"), nil
	}

	stsEntry, err := h.LockedAwsStsEntry(ctx, req.Storage, accountID)
	if err != nil {
		return nil, err
	}
	if stsEntry == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"sts_role": stsEntry.StsRole,
		},
	}, nil
}

// pathConfigStsCreateUpdate is used to associate an STS role with a given AWS accountID
func (h *ConfigHandler) pathConfigStsCreateUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	accountID := data.Get("account_id").(string)
	if accountID == "" {
		return logical.ErrorResponse("missing AWS account ID"), nil
	}

	h.configMutex.Lock()
	defer h.configMutex.Unlock()

	// Check if an STS role is already registered
	stsEntry, err := h.nonLockedAwsStsEntry(ctx, req.Storage, accountID)
	if err != nil {
		return nil, err
	}
	if stsEntry == nil {
		stsEntry = &alibabaSTSEntry{}
	}

	// Check that an STS role has actually been provided
	stsRole, ok := data.GetOk("sts_role")
	if ok {
		stsEntry.StsRole = stsRole.(string)
	} else if req.Operation == logical.CreateOperation {
		return logical.ErrorResponse("missing sts role"), nil
	}

	if stsEntry.StsRole == "" {
		return logical.ErrorResponse("sts role cannot be empty"), nil
	}

	// save the provided STS role
	if err := h.nonLockedSetAwsStsEntry(ctx, req.Storage, accountID, stsEntry); err != nil {
		return nil, err
	}

	return nil, nil
}

// pathConfigStsDelete is used to delete a previously configured STS configuration
func (h *ConfigHandler) pathConfigStsDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	h.configMutex.Lock()
	defer h.configMutex.Unlock()

	accountID := data.Get("account_id").(string)
	if accountID == "" {
		return logical.ErrorResponse("missing account id"), nil
	}

	return nil, req.Storage.Delete(ctx, "config/sts/"+accountID)
}

const pathConfigStsSyn = `
Specify STS roles to be assumed for certain AWS accounts.
`

const pathConfigStsDesc = `
Allows the explicit association of STS roles to satellite AWS accounts (i.e. those
which are not the account in which the Vault server is running.) Login attempts from
EC2 instances running in these accounts will be verified using credentials obtained
by assumption of these STS roles.

The environment in which the Vault server resides must have access to assume the
given STS roles.
`
const pathListStsHelpSyn = `
List all the AWS account/STS role relationships registered with Vault.
`

const pathListStsHelpDesc = `
AWS accounts will be listed by account ID, along with their respective role names.
`
