package ali

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathRole(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "role/" + framework.GenericNameRegex("role"),
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeLowerCaseString,
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
			logical.CreateOperation: b.operationRoleCreateUpdate,
			logical.UpdateOperation: b.operationRoleCreateUpdate,
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

// Establishes dichotomy of request operation between CreateOperation and UpdateOperation.
// Returning 'true' forces an UpdateOperation, CreateOperation otherwise.
func (b *backend) operationRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	entry, err := b.roleMgr.Read(ctx, req.Storage, data.Get("role").(string))
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

func (b *backend) operationRoleCreateUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	roleName := data.Get("role").(string)

	entry, err := b.roleMgr.Read(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if entry == nil && req.Operation == logical.UpdateOperation {
		return nil, fmt.Errorf("no entry found to update for %s", roleName)
	} else if entry == nil {
		entry = &roleEntry{}
	}

	if raw, ok := data.GetOk("arn"); ok {
		arn, err := parseARN(raw.(string))
		if err != nil {
			return nil, fmt.Errorf("unable to parse arn %s: %s", arn, err)
		}
		if roleName != arn.RoleName {
			// All roles must bear the same name as the ramRole to facilitate looking them up at login time.
			return nil, fmt.Errorf("role name must match arn name of %s", arn.RoleName)
		}
		if arn.Type != arnTypeRole {
			return nil, fmt.Errorf("only role arn types are supported at this time, but %s was provided", entry.ARN)
		}
		entry.ARN = arn
	} else if !ok && req.Operation == logical.CreateOperation {
		return nil, errors.New("the arn is required to create a role")
	}

	// None of the remaining fields are required.
	if raw, ok := data.GetOk("policies"); ok {
		entry.Policies = raw.([]string)
	}
	if raw, ok := data.GetOk("ttl"); ok {
		entry.TTL = time.Duration(raw.(int)) * time.Second
	}
	if raw, ok := data.GetOk("max_ttl"); ok {
		entry.MaxTTL = time.Duration(raw.(int)) * time.Second
	}
	if raw, ok := data.GetOk("period"); ok {
		entry.Period = time.Duration(raw.(int)) * time.Second
	}

	if entry.MaxTTL > 0 && entry.TTL > entry.MaxTTL {
		return nil, fmt.Errorf("ttl exceeds max_ttl")
	}
	if err := b.roleMgr.Update(ctx, req.Storage, roleName, entry); err != nil {
		return nil, err
	}
	if entry.TTL > b.System().MaxLeaseTTL() {
		resp := &logical.Response{}
		resp.AddWarning(fmt.Sprintf("ttl of %d exceeds the system max ttl of %d, the latter will be used during login", entry.TTL, b.System().MaxLeaseTTL()))
		return resp, nil
	}
	return nil, nil
}

func (b *backend) operationRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	entry, err := b.roleMgr.Read(ctx, req.Storage, data.Get("role").(string))
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
