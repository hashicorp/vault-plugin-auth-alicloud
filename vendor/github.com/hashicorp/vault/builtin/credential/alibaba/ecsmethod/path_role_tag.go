package ecsmethod

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/builtin/credential/alibaba/common"
	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

type RoleTagHandler struct {
	RoleMgr *common.RoleManager
	System  logical.SystemView
}

func (h *RoleTagHandler) PathRoleTag() *framework.Path {
	return &framework.Path{
		Pattern: "role/" + framework.GenericNameRegex("role") + "/tag$",
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeString,
				Description: "Name of the role.",
			},

			"instance_id": {
				Type: framework.TypeString,
				Description: `Instance ID for which this tag is intended for.
If set, the created tag can only be used by the instance with the given ID.`,
			},

			"policies": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Policies to be associated with the tag. If set, must be a subset of the role's policies. If set, but set to an empty value, only the 'default' policy will be given to issued tokens.",
			},

			"max_ttl": {
				Type:        framework.TypeDurationSecond,
				Default:     0,
				Description: "If set, specifies the maximum allowed token lifetime.",
			},

			"allow_instance_migration": {
				Type:        framework.TypeBool,
				Default:     false,
				Description: "If set, allows migration of the underlying instance where the client resides. This keys off of pendingTime in the metadata document, so essentially, this disables the client nonce check whenever the instance is migrated to a new host and pendingTime is newer than the previously-remembered time. Use with caution.",
			},

			"disallow_reauthentication": {
				Type:        framework.TypeBool,
				Default:     false,
				Description: "If set, only allows a single token to be granted per instance ID. In order to perform a fresh login, the entry in whitelistConfig for the instance ID needs to be cleared using the 'auth/aws-ec2/identity-whitelistConfig/<instance_id>' endpoint.",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: h.pathRoleTagUpdate,
		},

		HelpSynopsis:    pathRoleTagSyn,
		HelpDescription: pathRoleTagDesc,
	}
}

// pathRoleTagUpdate is used to create an EC2 instance tag which will
// identify the Vault resources that the instance will be authorized for.
func (h *RoleTagHandler) pathRoleTagUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := strings.ToLower(data.Get("role").(string))
	if roleName == "" {
		return logical.ErrorResponse("missing role"), nil
	}

	// Fetch the role entry
	roleEntry, err := h.RoleMgr.Read(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if roleEntry == nil {
		return logical.ErrorResponse(fmt.Sprintf("entry not found for role %s", roleName)), nil
	}

	// If RoleTag is empty, disallow creation of tag.
	if roleEntry.RoleTag == "" {
		return logical.ErrorResponse("tag creation is not enabled for this role"), nil
	}

	// There should be a HMAC key present in the role entry
	if roleEntry.HMACKey == "" {
		// Not being able to find the HMACKey is an internal error
		return nil, fmt.Errorf("failed to find the HMAC key")
	}

	resp := &logical.Response{}

	// Instance ID is an optional field.
	instanceID := strings.ToLower(data.Get("instance_id").(string))

	// If no policies field was not supplied, then the tag should inherit all the policies
	// on the role. But, it was provided, but set to empty explicitly, only "default" policy
	// should be inherited. So, by leaving the policies var unset to anything when it is not
	// supplied, we ensure that it inherits all the policies on the role.
	var policies []string
	policiesRaw, ok := data.GetOk("policies")
	if ok {
		policies = policyutil.ParsePolicies(policiesRaw)
	}
	if !strutil.StrListSubset(roleEntry.Policies, policies) {
		resp.AddWarning("Policies on the tag are not a subset of the policies set on the role. Login will not be allowed with this tag unless the role policies are updated.")
	}

	// This is an optional field.
	disallowReauthentication := data.Get("disallow_reauthentication").(bool)

	// This is an optional field.
	allowInstanceMigration := data.Get("allow_instance_migration").(bool)
	if allowInstanceMigration && !roleEntry.AllowInstanceMigration {
		resp.AddWarning("Role does not allow instance migration. Login will not be allowed with this tag unless the role value is updated.")
	}

	if disallowReauthentication && allowInstanceMigration {
		return logical.ErrorResponse("cannot set both disallow_reauthentication and allow_instance_migration"), nil
	}

	// max_ttl for the role tag should be less than the max_ttl set on the role.
	maxTTL := time.Duration(data.Get("max_ttl").(int)) * time.Second

	// max_ttl on the tag should not be greater than the system view's max_ttl value.
	if maxTTL > h.System.MaxLeaseTTL() {
		resp.AddWarning(fmt.Sprintf("Given max TTL of %d is greater than the mount maximum of %d seconds, and will be capped at login time.", maxTTL/time.Second, h.System.MaxLeaseTTL()/time.Second))
	}
	// If max_ttl is set for the role, check the bounds for tag's max_ttl value using that.
	if roleEntry.MaxTTL != time.Duration(0) && maxTTL > roleEntry.MaxTTL {
		resp.AddWarning(fmt.Sprintf("Given max TTL of %d is greater than the role maximum of %d seconds, and will be capped at login time.", maxTTL/time.Second, roleEntry.MaxTTL/time.Second))
	}

	if maxTTL < time.Duration(0) {
		return logical.ErrorResponse("max_ttl cannot be negative"), nil
	}

	// Create a random nonce.
	nonce, err := createRoleTagNonce()
	if err != nil {
		return nil, err
	}

	// Create a role tag out of all the information provided.
	rTagValue, err := createRoleTagValue(&common.RoleTag{
		Version:                  common.RoleTagVersion,
		Role:                     roleName,
		Nonce:                    nonce,
		Policies:                 policies,
		MaxTTL:                   maxTTL,
		InstanceID:               instanceID,
		DisallowReauthentication: disallowReauthentication,
		AllowInstanceMigration:   allowInstanceMigration,
	}, roleEntry)
	if err != nil {
		return nil, err
	}

	// Return the key to be used for the tag and the value to be used for that tag key.
	// This key value pair should be set on the EC2 instance.
	resp.Data = map[string]interface{}{
		"tag_key":   roleEntry.RoleTag,
		"tag_value": rTagValue,
	}

	return resp, nil
}

// createRoleTagValue prepares the plaintext version of the role tag,
// and appends a HMAC of the plaintext value to it, before returning.
func createRoleTagValue(rTag *common.RoleTag, roleEntry *common.RoleEntry) (string, error) {
	if rTag == nil {
		return "", fmt.Errorf("nil role tag")
	}

	if roleEntry == nil {
		return "", fmt.Errorf("nil role entry")
	}

	// Attach version, nonce, policies and maxTTL to the role tag value.
	rTagPlaintext, err := common.PrepareRoleTagPlaintextValue(rTag)
	if err != nil {
		return "", err
	}

	// Attach HMAC to tag's plaintext and return.
	return appendHMAC(rTagPlaintext, roleEntry)
}

// Takes in the plaintext part of the role tag, creates a HMAC of it and returns
// a role tag value containing both the plaintext part and the HMAC part.
func appendHMAC(rTagPlaintext string, roleEntry *common.RoleEntry) (string, error) {
	if rTagPlaintext == "" {
		return "", fmt.Errorf("empty role tag plaintext string")
	}

	if roleEntry == nil {
		return "", fmt.Errorf("nil role entry")
	}

	// Create the HMAC of the value
	hmacB64, err := common.CreateRoleTagHMACBase64(roleEntry.HMACKey, rTagPlaintext)
	if err != nil {
		return "", err
	}

	// attach the HMAC to the value
	rTagValue := fmt.Sprintf("%s:%s", rTagPlaintext, hmacB64)

	// This limit of 255 is enforced on the EC2 instance. Hence complying to that here.
	if len(rTagValue) > 255 {
		return "", fmt.Errorf("role tag 'value' exceeding the limit of 255 characters")
	}

	return rTagValue, nil
}

// Creates a base64 encoded random nonce.
func createRoleTagNonce() (string, error) {
	if uuidBytes, err := uuid.GenerateRandomBytes(8); err != nil {
		return "", err
	} else {
		return base64.StdEncoding.EncodeToString(uuidBytes), nil
	}
}

const pathRoleTagSyn = `
Create a tag on a role in order to be able to further restrict the capabilities of a role.
`

const pathRoleTagDesc = `
If there are needs to apply only a subset of role's capabilities to any specific
instance, create a role tag using this endpoint and attach the tag on the instance
before performing login.

To be able to create a role tag, the 'role_tag' option on the role should be
enabled via the endpoint 'role/<role>'. Also, the policies to be associated
with the tag should be a subset of the policies associated with the registered role.

This endpoint will return both the 'key' and the 'value' of the tag to be set
on the EC2 instance.
`
