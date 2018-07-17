package ali

import (
	"context"
	"fmt"
	"strings"
	"time"

	"errors"
	"github.com/hashicorp/vault-plugin-auth-alibaba/helper/ttls"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathRole(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "role/" + framework.GenericNameRegex("role"),
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeString,
				Description: "The name of the role as it should appear in Vault.",
			},
			"arn": {
				Type:        framework.TypeString,
				Description: "ARN of the RAM to bind to this role.",
			},
			"policies": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Policies to be set on tokens issued using this role.",
			},
			"ttl": {
				Type: framework.TypeDurationSecond,
				Description: `Duration in seconds after which the issued token should expire. Defaults
to 0, in which case the value will fallback to the system/mount defaults.`,
			},
			"max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "The maximum allowed lifetime of tokens issued using this role.",
			},
			"period": {
				Type: framework.TypeDurationSecond,
				Description: `
If set, indicates that the token generated using this role should never expire.
The token should be renewed within the duration specified by this value. At
each renewal, the token's TTL will be set to the value of this parameter.`,
			},
		},
		ExistenceCheck: b.operationRoleExistenceCheck,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.operationRoleCreate,
			logical.UpdateOperation: b.operationRoleUpdate,
			logical.ReadOperation:   b.operationRoleRead,
			logical.DeleteOperation: b.operationRoleDelete,
		},
		HelpSynopsis:    pathRoleSyn,
		HelpDescription: pathRoleDesc,
	}
}

func pathListRole(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "role/?",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.operationRoleList,
		},
		HelpSynopsis:    pathListRolesHelpSyn,
		HelpDescription: pathListRolesHelpDesc,
	}
}

func pathListRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/?",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.operationRoleList,
		},
		HelpSynopsis:    pathListRolesHelpSyn,
		HelpDescription: pathListRolesHelpDesc,
	}
}

func (b *backend) operationRoleCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	roleName := data.Get("role").(string)
	if roleName == "" {
		return nil, errors.New("missing role")
	}

	entry := &roleEntry{}
	arn, err := parseARN(data.Get("arn").(string))
	if err != nil {
		return nil, fmt.Errorf("unable to parseARN arn %s: %s", arn, err)
	}
	if roleName != arn.RoleName {
		// All roles must bear the same name as the ramRole to facilitate looking them up at login time.
		return nil, fmt.Errorf("role name must match arn name of %s", arn.RoleName)
	}
	if arn.Type != arnTypeRole {
		return nil, fmt.Errorf(`only role arn types are supported at this time, but %s was provided`, entry.ARN)
	}

	entry.ARN = arn
	entry.Policies = data.Get("policies").([]string)
	entry.TTL = time.Duration(data.Get("ttl").(int)) * time.Second
	entry.MaxTTL = time.Duration(data.Get("max_ttl").(int)) * time.Second
	entry.Period = time.Duration(data.Get("period").(int)) * time.Second

	ttlValidator := ttls.MountHandler{
		RoleTTL:    entry.TTL,
		RoleMaxTTL: entry.MaxTTL,
	}
	if err := ttlValidator.Validate(b.System()); err != nil {
		return nil, err
	}

	if err := b.roleMgr.Update(ctx, req.Storage, roleName, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

// Establishes dichotomy of request operation between CreateOperation and UpdateOperation.
// Returning 'true' forces an UpdateOperation, CreateOperation otherwise.
func (b *backend) operationRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	entry, err := b.roleMgr.Read(ctx, req.Storage, strings.ToLower(data.Get("role").(string)))
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

func (b *backend) operationRoleUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	roleName := data.Get("role").(string)
	if roleName == "" {
		return nil, errors.New("missing role")
	}

	entry, err := b.roleMgr.Read(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		// This should be an error because it's possible for the existence check to return that a role exists,
		// then for a separate process to delete it, and then for the original existence-checker to arrive here
		// and have nothing to update. In that case, defaulting would create a result that would be unexpected
		// to the caller.
		return nil, fmt.Errorf("no entry found to update for %s", roleName)
	}

	if raw, ok := data.GetOk("arn"); ok {
		arn, err := parseARN(raw.(string))
		if err != nil {
			return nil, fmt.Errorf("unable to parseARN arn %s: %s", arn, err)
		}
		if roleName != arn.RoleName {
			// All roles must bear the same name as the ramRole to facilitate looking them up at login time.
			return nil, fmt.Errorf("role name must match arn name of %s", arn.RoleName)
		}
		if entry.ARN.Type != arnTypeRole {
			// We haven't tested with other arn types and would like to understand and test these use cases before blindly
			// granting access so we don't create a security vulnerability. Please open a ticket describing your use case
			// for another arn type to get that started.
			return nil, fmt.Errorf(`only role arn types are supported at this time, but %s was provided`, entry.ARN)
		}
		entry.ARN = arn
	}
	if raw, ok := data.GetOk("policies"); ok {
		entry.Policies = raw.([]string)
	}

	ttlsChanged := false
	if raw, ok := data.GetOk("ttl"); ok {
		ttlsChanged = true
		entry.TTL = time.Duration(raw.(int)) * time.Second
	}
	if raw, ok := data.GetOk("max_ttl"); ok {
		ttlsChanged = true
		entry.MaxTTL = time.Duration(raw.(int)) * time.Second
	}
	if ttlsChanged {
		ttlValidator := ttls.MountHandler{
			RoleTTL:    entry.TTL,
			RoleMaxTTL: entry.MaxTTL,
		}
		if err := ttlValidator.Validate(b.System()); err != nil {
			return nil, err
		}
	}

	if raw, ok := data.GetOk("period"); ok {
		entry.Period = time.Duration(raw.(int)) * time.Second
	}
	if err := b.roleMgr.Update(ctx, req.Storage, roleName, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) operationRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	entry, err := b.roleMgr.Read(ctx, req.Storage, strings.ToLower(data.Get("role").(string)))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	return &logical.Response{
		Data: entry.ToResponseData(),
	}, nil
}

func (b *backend) operationRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role").(string)
	if roleName == "" {
		return nil, errors.New("missing role")
	}
	return nil, b.roleMgr.Delete(ctx, req.Storage, roleName)
}

func (b *backend) operationRoleList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roles, err := b.roleMgr.List(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(roles), nil
}

const pathRoleSyn = `
Create a role and associate policies to it.
`

const pathRoleDesc = `
A precondition for login is that a role should be created in the backend.
The login endpoint takes in the role name against which the instance
should be validated. After authenticating the instance, the authorization
for the instance to access Vault's resources is determined by the policies
that are associated to the role though this endpoint.

Also, a 'max_ttl' can be configured in this endpoint that determines the maximum
duration for which a login can be renewed. Note that the 'max_ttl' has an upper
limit of the 'max_ttl' value on the backend's mount. The same applies to the 'ttl'.
`

const pathListRolesHelpSyn = `
Lists all the roles that are registered with Vault.
`

const pathListRolesHelpDesc = `
Roles will be listed by their respective role names.
`
