package ali

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathRole(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "role/" + framework.GenericNameRegex("role"),
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeString,
				Description: "Name of the role.",
			},
			"bound_ram_principal_arn": {
				Type: framework.TypeCommaStringSlice,
				Description: `ARN of the RAM principals to bind to this role.`,
			},
			"resolve_ram_unique_ids": {
				Type:    framework.TypeBool,
				Default: true,
				Description: `If set, resolve all Alibaba RAM ARNs into Alibaba's internal unique IDs.
When an RAM entity (e.g., user, role, or instance profile) is deleted, then all references
to it within the role will be invalidated, which prevents a new RAM entity from being created
with the same name and matching the role's RAM binds. Once set, this cannot be unset.`,
			},
			"period": {
				Type:    framework.TypeDurationSecond,
				Default: 0,
				Description: `
If set, indicates that the token generated using this role should never expire.
The token should be renewed within the duration specified by this value. At
each renewal, the token's TTL will be set to the value of this parameter.`,
			},
			"ttl": {
				Type:    framework.TypeDurationSecond,
				Default: 0,
				Description: `Duration in seconds after which the issued token should expire. Defaults
to 0, in which case the value will fallback to the system/mount defaults.`,
			},
			"max_ttl": {
				Type:        framework.TypeDurationSecond,
				Default:     0,
				Description: "The maximum allowed lifetime of tokens issued using this role.",
			},
			"policies": {
				Type:        framework.TypeCommaStringSlice,
				Default:     "default",
				Description: "Policies to be set on tokens issued using this role.",
			},
		},
		ExistenceCheck: b.pathRoleExistenceCheck,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.pathRoleCreateUpdate,
			logical.UpdateOperation: b.pathRoleCreateUpdate,
			logical.ReadOperation:   b.pathRoleRead,
			logical.DeleteOperation: b.pathRoleDelete,
		},
		HelpSynopsis:    pathRoleSyn,
		HelpDescription: pathRoleDesc,
	}
}

func pathListRole(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "role/?",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathRoleList,
		},
		HelpSynopsis:    pathListRolesHelpSyn,
		HelpDescription: pathListRolesHelpDesc,
	}
}

func pathListRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/?",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathRoleList,
		},
		HelpSynopsis:    pathListRolesHelpSyn,
		HelpDescription: pathListRolesHelpDesc,
	}
}

// Establishes dichotomy of request operation between CreateOperation and UpdateOperation.
// Returning 'true' forces an UpdateOperation, CreateOperation otherwise.
func (b *backend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	entry, err := b.roleMgr.Read(ctx, req.Storage, strings.ToLower(data.Get("role").(string)))
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role"), nil
	}
	return nil, b.roleMgr.Delete(ctx, req.Storage, roleName)
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roles, err := b.roleMgr.List(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(roles), nil
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleEntry, err := b.roleMgr.Read(ctx, req.Storage, strings.ToLower(data.Get("role").(string)))
	if err != nil {
		return nil, err
	}
	if roleEntry == nil {
		return nil, nil
	}
	return &logical.Response{
		Data: roleEntry.ToResponseData(),
	}, nil
}

func (b *backend) pathRoleCreateUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := strings.ToLower(data.Get("role").(string))
	if roleName == "" {
		return logical.ErrorResponse("missing role"), nil
	}

	roleEntry, err := b.roleMgr.Read(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if roleEntry == nil {
		roleEntry = &RoleEntry{
			TTL: b.System().DefaultLeaseTTL(),
			MaxTTL:b.System().MaxLeaseTTL(),
		}
	}

	if resolveAWSUniqueIDsRaw, ok := data.GetOk("resolve_ram_unique_ids"); ok {
		if roleEntry.ResolveAlibabaUniqueIDs && !resolveAWSUniqueIDsRaw.(bool) {
			return logical.ErrorResponse("changing resolve_ram_unique_ids from true to false is not allowed"), nil
		}
		roleEntry.ResolveAlibabaUniqueIDs = resolveAWSUniqueIDsRaw.(bool)
	}

	if boundIamPrincipalARNRaw, ok := data.GetOk("bound_ram_principal_arn"); ok {
		roleEntry.BoundRamPrincipalARNs = boundIamPrincipalARNRaw.([]string)
	}

	if len(roleEntry.BoundRamPrincipalARNs) == 0 {
		return logical.ErrorResponse("at least be one bound parameter should be specified on the role"), nil
	}

	if policiesRaw, ok := data.GetOk("policies"); ok {
		roleEntry.Policies = policyutil.ParsePolicies(policiesRaw)
	}

	var resp logical.Response

	if ttlRaw, ok := data.GetOk("ttl"); ok {
		ttl := time.Duration(ttlRaw.(int)) * time.Second
		if ttl > roleEntry.TTL {
			// intentionally retain the default ttl set earlier
			resp.AddWarning(fmt.Sprintf("Given ttl of %d seconds greater than current mount/system default of %d seconds; ttl is capped", ttl/time.Second, roleEntry.TTL/time.Second))
		} else {
			if ttl < time.Duration(0) {
				return logical.ErrorResponse("ttl cannot be negative"), nil
			}
			roleEntry.TTL = ttl
		}
	}

	maxTTLInt, ok := data.GetOk("max_ttl")
	if ok {
		maxTTL := time.Duration(maxTTLInt.(int)) * time.Second
		if maxTTL > roleEntry.MaxTTL {
			// intentionally retain the default max ttl set earlier
			resp.AddWarning(fmt.Sprintf("Given max_ttl of %d seconds greater than current mount/system default of %d seconds; max_ttl is capped", maxTTL/time.Second, roleEntry.MaxTTL/time.Second))
		} else {
			if maxTTL < time.Duration(0) {
				return logical.ErrorResponse("max_ttl cannot be negative"), nil
			}
			roleEntry.MaxTTL = maxTTL
		}
	}

	if roleEntry.MaxTTL != 0 && roleEntry.MaxTTL < roleEntry.TTL {
		return logical.ErrorResponse("ttl should be shorter than max_ttl"), nil
	}

	if periodRaw, ok := data.GetOk("period"); ok {
		roleEntry.Period = time.Second * time.Duration(periodRaw.(int))
	}

	if roleEntry.Period > b.System().MaxLeaseTTL() {
		return logical.ErrorResponse(fmt.Sprintf("'period' of '%s' is greater than the backend's maximum lease TTL of '%s'", roleEntry.Period.String(), b.System().MaxLeaseTTL().String())), nil
	}

	if err := b.roleMgr.Update(ctx, req.Storage, roleName, roleEntry); err != nil {
		return nil, err
	}

	if len(resp.Warnings) == 0 {
		return nil, nil
	}

	return &resp, nil
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
