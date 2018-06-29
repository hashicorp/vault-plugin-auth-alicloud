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
				Type: framework.TypeString,
				Description: "The name of the role as it should appear in Vault.",
			},
			"arn": {
				Type: framework.TypeString,
				Description: `ARN of the RAM principals to bind to this role.`,
			},
			"policies": {
				Type:        framework.TypeCommaStringSlice,
				Default:     "default",
				Description: "Policies to be set on tokens issued using this role.",
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
			"period": {
				Type:    framework.TypeDurationSecond,
				Default: 0,
				Description: `
If set, indicates that the token generated using this role should never expire.
The token should be renewed within the duration specified by this value. At
each renewal, the token's TTL will be set to the value of this parameter.`,
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

	roleName := data.Get("role").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role"), nil
	}

	roleEntry, err := b.roleMgr.Read(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if roleEntry == nil {
		roleEntry = &RoleEntry{}
	}

	arn := data.Get("arn").(string)
	if arn == "" {
		return logical.ErrorResponse("missing arn"), nil
	}

	entity, err := parseRamArn(arn)
	if err != nil {
		return logical.ErrorResponse("unable to parse arn: " + arn + " due to " + err.Error()), nil
	}
	if entity.Type != "role" {
		return logical.ErrorResponse("only role arns are currently supported"), nil
	}

	if policies, ok := data.GetOk("policies"); ok {
		roleEntry.Policies = policyutil.ParsePolicies(policies)
	}
	if len(roleEntry.Policies) == 0 {
		return logical.ErrorResponse("at least one valid policy must be provided"), nil
	}

	// These default to 0 and if 0 is passed to the core, it defaults to the system settings.
	ttl := data.Get("ttl").(int)
	roleEntry.TTL = time.Duration(ttl) * time.Second

	maxTTL := data.Get("maxTTL").(int)
	roleEntry.MaxTTL = time.Duration(maxTTL) * time.Second

	period := data.Get("period").(int)
	roleEntry.Period = time.Duration(period) * time.Second

	// TODO may need additional logic regarding capping TTL's and the period at the system ones.
	if ttl > maxTTL {
		return logical.ErrorResponse(fmt.Sprintf("ttl of %d cannot be greater than max_ttl of %d", ttl, maxTTL)), nil
	}

	if err := b.roleMgr.Update(ctx, req.Storage, roleName, roleEntry); err != nil {
		return nil, err
	}
	return nil, nil
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
