package ali

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ram"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/sts"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/vault/helper/jsonutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathLogin(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "login$",
		Fields: map[string]*framework.FieldSchema{
			"identity_request_url": {
				Type:        framework.TypeString,
				Description: `Base64-encoded full URL against which to make the Alibaba request.`,
			},
			"identity_request_headers": {
				Type: framework.TypeString,
				Description: `Base64-encoded JSON representation of the request headers. 
This must include the headers over which Alibaba has included a signature.`,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathLoginUpdate,
		},
		HelpSynopsis:    pathLoginSyn,
		HelpDescription: pathLoginDesc,
	}
}

func (b *backend) pathLoginUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	rawUrlB64 := data.Get("identity_request_url").(string)
	if rawUrlB64 == "" {
		return logical.ErrorResponse("missing identity_request_url"), nil
	}
	rawUrl, err := base64.StdEncoding.DecodeString(rawUrlB64)
	if err != nil {
		return logical.ErrorResponse("failed to base64 decode identity_request_url"), nil
	}
	parsedUrl, err := url.Parse(string(rawUrl))
	if err != nil {
		return logical.ErrorResponse("error parsing identity_request_url"), nil
	}

	headersB64 := data.Get("identity_request_headers").(string)
	if headersB64 == "" {
		return logical.ErrorResponse("missing identity_request_headers"), nil
	}
	headers, err := parseRamRequestHeaders(headersB64)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("Error parsing identity_request_headers: %v", err)), nil
	}
	if headers == nil {
		return logical.ErrorResponse("nil response when parsing identity_request_headers"), nil
	}

	config, err := b.lockedClientConfigEntry(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse("error getting configuration"), nil
	}

	if config != nil {
		if config.InstanceIdentityAudience != "" {
			if err := validateVaultHeaderValue(headers, config.InstanceIdentityAudience); err != nil {
				return logical.ErrorResponse(fmt.Sprintf("error validating %s header: %v", instanceIdentityAudienceHeader, err)), nil
			}
		}
	}

	callerID, err := submitCallerIdentityRequest(headers, parsedUrl)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("error making upstream request: %v", err)), nil
	}

	ramRole, err := b.getMatchingRole(ctx, req.Storage, callerID.RoleId)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("error finding matching authTypeRole: %s", err)), nil
	}

	roleEntry, err := b.roleMgr.Read(ctx, req.Storage, ramRole.RoleName)
	if err != nil {
		return nil, err
	}
	if roleEntry == nil {
		return logical.ErrorResponse(fmt.Sprintf("entry for authTypeRole %s not found", ramRole.RoleName)), nil
	}

	// This check protects against someone creating a different role with the same name as one that has access in Vault,
	// and using it to gain access they shouldn't have.
	if roleEntry.ARN != callerID.Arn {
		return logical.ErrorResponse("the caller's ARN does not match the role's ARN"), nil
	}

	resp := &logical.Response{
		Auth: &logical.Auth{
			Period:   roleEntry.Period,
			Policies: roleEntry.Policies,
			Metadata: map[string]string{
				"account_id":    callerID.AccountId,
				"user_id":       callerID.UserId,
				"role_id":       callerID.RoleId,
				"arn":           callerID.Arn,
				"identity_type": callerID.IdentityType,
				"principal_id":  callerID.PrincipalId,
				"request_id":    callerID.RequestId,
				"role_name":     ramRole.RoleName,
			},
			InternalData: map[string]interface{}{
				"role_name": ramRole.RoleName,
			},
			DisplayName: callerID.PrincipalId,
			LeaseOptions: logical.LeaseOptions{
				Renewable: true,
				TTL:       roleEntry.TTL,
				MaxTTL:    roleEntry.MaxTTL,
			},
			Alias: &logical.Alias{
				Name: callerID.PrincipalId,
			},
		},
	}
	return resp, nil
}

func (b *backend) pathLoginRenew(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	arn := req.Auth.Metadata["arn"]
	if arn == "" {
		return nil, fmt.Errorf("unable to retrieve ARN from metadata during renewal")
	}
	roleName := req.Auth.InternalData["role_name"].(string)
	if roleName == "" {
		return nil, fmt.Errorf("error retrieving role_name during renewal")
	}

	roleEntry, err := b.roleMgr.Read(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if roleEntry == nil {
		return nil, fmt.Errorf("role entry not found")
	}

	if roleEntry.ARN != arn {
		return logical.ErrorResponse("the caller's ARN does not match the role's ARN"), nil
	}

	resp := &logical.Response{Auth: req.Auth}
	resp.Auth.TTL = roleEntry.TTL
	resp.Auth.MaxTTL = roleEntry.MaxTTL
	resp.Auth.Period = roleEntry.Period
	return resp, nil
}

func submitCallerIdentityRequest(headers http.Header, u *url.URL) (*sts.GetCallerIdentityResponse, error) {
	request, err := http.NewRequest(http.MethodPost, u.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header = headers

	client := cleanhttp.DefaultClient()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, errwrap.Wrapf("error making request: {{err}}", err)
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		b, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return nil, errwrap.Wrapf("error reading reponse body: {{err}}", err)
		}
		return nil, fmt.Errorf("received %d checking caller identity: %s", response.StatusCode, b)
	}

	result := &sts.GetCallerIdentityResponse{}
	if err := json.NewDecoder(response.Body).Decode(result); err != nil {
		return nil, errwrap.Wrapf("error decoding reponse: {{err}}", err)
	}
	return result, nil
}

// getMatchingRamRole lists all the ram roles to identify one with a matching authTypeRole ID.
// That's because the RAM API supports GetRole but only using the roleName, not the roleID,
// which is the only information we here.
// To lighten the potential API load against Alibaba, we cache the results of each page we get.
func (b *backend) getMatchingRole(ctx context.Context, s logical.Storage, roleId string) (ram.Role, error) {

	// Is it cached?
	roleIfc, found := b.remoteRoleCache.Get(roleId)
	if found {
		return roleIfc.(ram.Role), nil
	}

	// Nope, let's go find it!
	client, err := b.getRAMClient(ctx, s)
	if err != nil {
		return ram.Role{}, err
	}
	req := ram.CreateListRolesRequest()
	req.MaxItems = requests.NewInteger(500)

	shouldSearch := true
	for shouldSearch {
		resp, err := client.ListRoles(req)
		if err != nil {
			return ram.Role{}, err
		}

		found := false
		result := ram.Role{}
		for _, role := range resp.Roles.Role {
			b.remoteRoleCache.Set(role.RoleId, role, 0)
			if role.RoleId == roleId {
				// Since we went to the effort of making the API request,
				// let's cache all the results on this page before we return.
				found = true
				result = role
			}
		}
		if found {
			return result, nil
		}

		req.Marker = resp.Marker
		shouldSearch = resp.IsTruncated
	}
	return ram.Role{}, fmt.Errorf("no Alibaba authTypeRole matches roleID %s", roleId)
}

func validateVaultHeaderValue(headers http.Header, requiredHeaderValue string) error {
	providedValue := ""
	for k, v := range headers {
		if strings.ToLower(instanceIdentityAudienceHeader) == strings.ToLower(k) {
			providedValue = strings.Join(v, ",")
			break
		}
	}
	if providedValue == "" {
		return fmt.Errorf("missing header %q", instanceIdentityAudienceHeader)
	}

	// NOT doing a constant time compare here since the value is NOT intended to be secret
	if providedValue != requiredHeaderValue {
		return fmt.Errorf("expected %q but got %q", requiredHeaderValue, providedValue)
	}

	if authzHeaders, ok := headers["Authorization"]; ok {
		re := regexp.MustCompile(".*SignedHeaders=([^,]+)")
		authzHeader := strings.Join(authzHeaders, ",")
		matches := re.FindSubmatch([]byte(authzHeader))
		if len(matches) < 1 {
			return fmt.Errorf("vault header wasn't signed")
		}
		if len(matches) > 2 {
			return fmt.Errorf("found multiple SignedHeaders components")
		}
		signedHeaders := string(matches[1])
		return ensureHeaderIsSigned(signedHeaders, instanceIdentityAudienceHeader)
	}
	return fmt.Errorf("missing Authorization header")
}

func ensureHeaderIsSigned(signedHeaders, headerToSign string) error {
	// Not doing a constant time compare here, the values aren't secret
	for _, header := range strings.Split(signedHeaders, ";") {
		if header == strings.ToLower(headerToSign) {
			return nil
		}
	}
	return fmt.Errorf("vault header wasn't signed")
}

func parseRamRequestHeaders(headersB64 string) (http.Header, error) {
	headersJson, err := base64.StdEncoding.DecodeString(headersB64)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode identity_request_headers")
	}
	var headersDecoded map[string]interface{}
	err = jsonutil.DecodeJSON(headersJson, &headersDecoded)
	if err != nil {
		return nil, errwrap.Wrapf(fmt.Sprintf("failed to JSON decode identity_request_headers %q: {{err}}", headersJson), err)
	}
	headers := make(http.Header)
	for k, v := range headersDecoded {
		switch typedValue := v.(type) {
		case string:
			headers.Add(k, typedValue)
		case json.Number:
			headers.Add(k, typedValue.String())
		case []interface{}:
			for _, individualVal := range typedValue {
				switch possibleStrVal := individualVal.(type) {
				case string:
					headers.Add(k, possibleStrVal)
				case json.Number:
					headers.Add(k, possibleStrVal.String())
				default:
					return nil, fmt.Errorf("header %q contains value %q that has type %s, not string", k, individualVal, reflect.TypeOf(individualVal))
				}
			}
		default:
			return nil, fmt.Errorf("header %q value %q has type %s, not string or []interface", k, typedValue, reflect.TypeOf(v))
		}
	}
	return headers, nil
}

type authType int

const (
	authTypeRole authType = iota
)

type parsedRam struct {
	AccountNumber string
	AuthType      authType
	FriendlyName  string
}

func parseRamArn(ramArn string) (*parsedRam, error) {
	var parsed parsedRam
	fullParts := strings.Split(ramArn, ":")
	if len(fullParts) != 5 {
		return nil, fmt.Errorf("unrecognized arn: contains %d colon-separated parts, expected 5", len(fullParts))
	}
	if fullParts[0] != "acs" {
		return nil, fmt.Errorf("unrecognized arn: does not begin with \"acs:\"")
	}
	if fullParts[1] != "ram" {
		return nil, fmt.Errorf("unrecognized service: %v, not ram", fullParts[1])
	}
	parsed.AccountNumber = fullParts[3]
	parts := strings.Split(fullParts[4], "/")
	if len(parts) < 2 {
		return nil, fmt.Errorf("unrecognized arn: %q contains fewer than 2 slash-separated parts", fullParts[4])
	}
	entityType := parts[0]
	switch entityType {
	case "authTypeRole":
		parsed.AuthType = authTypeRole
	default:
		return &parsedRam{}, fmt.Errorf("unsupported parsed type: %s", entityType)
	}

	parsed.FriendlyName = parts[len(parts)-1]

	return &parsed, nil
}

const instanceIdentityAudienceHeader = "audience"

const pathLoginSyn = `
Authenticates an RAM entity with Vault.
`

const pathLoginDesc = `
Authenticate Alibaba entities using an arbitrary RAM principal.

RAM principals are authenticated by processing a signed sts:GetCallerIdentity
request and then parsing the response to see who signed the request.
`
