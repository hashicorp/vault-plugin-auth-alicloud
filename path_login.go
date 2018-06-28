package ali

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/vault/helper/jsonutil"
	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"io/ioutil"
)

func pathLogin(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "login$",
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type: framework.TypeString,
				Description: `Name of the role against which the login is being attempted.`,
			},
			"ram_request_url": {
				Type: framework.TypeString,
				Description: `Base64-encoded full URL against which to make the Alibaba request.`,
			},
			"ram_request_headers": {
				Type: framework.TypeString,
				Description: `Base64-encoded JSON representation of the request headers. 
This must include the headers over which Alibaba has included a signature.`,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation:         b.pathLoginUpdate,
			logical.AliasLookaheadOperation: b.pathLoginUpdate,
		},
		HelpSynopsis:    pathLoginSyn,
		HelpDescription: pathLoginDesc,
	}
}

func (b *backend) pathLoginUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if !hasValuesForRamAuth(data) {
		return logical.ErrorResponse("supplied some of the auth values for the ram auth type but not all"), nil
	}
	return b.pathLoginUpdateRam(ctx, req, data)
}

// pathLoginRenew is used to renew an authenticated token
func (b *backend) pathLoginRenew(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathLoginRenewRam(ctx, req, data)
}

func (b *backend) pathLoginRenewRam(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	canonicalArn := req.Auth.Metadata["canonical_arn"]
	if canonicalArn == "" {
		return nil, fmt.Errorf("unable to retrieve canonical ARN from metadata during renewal")
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

	if len(roleEntry.BoundRamPrincipalARNs) > 0 {
		switch {
		case !roleEntry.ResolveAlibabaUniqueIDs && strutil.StrListContains(roleEntry.BoundRamPrincipalARNs, canonicalArn):
		default:
			matchedWildcardBind := false
			for _, principalARN := range roleEntry.BoundRamPrincipalARNs {
				if strings.HasSuffix(principalARN, "*") && strutil.GlobbedStringsMatch(principalARN, canonicalArn) {
					matchedWildcardBind = true
					break
				}
			}
			if !matchedWildcardBind {
				return nil, fmt.Errorf("role no longer bound to ARN %q", canonicalArn)
			}
		}
	}

	resp := &logical.Response{Auth: req.Auth}
	resp.Auth.TTL = roleEntry.TTL
	resp.Auth.MaxTTL = roleEntry.MaxTTL
	resp.Auth.Period = roleEntry.Period
	return resp, nil
}

func (b *backend) pathLoginUpdateRam(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	rawUrlB64 := data.Get("ram_request_url").(string)
	if rawUrlB64 == "" {
		return logical.ErrorResponse("missing ram_request_url"), nil
	}
	rawUrl, err := base64.StdEncoding.DecodeString(rawUrlB64)
	if err != nil {
		return logical.ErrorResponse("failed to base64 decode ram_request_url"), nil
	}
	parsedUrl, err := url.Parse(string(rawUrl))
	if err != nil {
		return logical.ErrorResponse("error parsing ram_request_url"), nil
	}

	headersB64 := data.Get("ram_request_headers").(string)
	if headersB64 == "" {
		return logical.ErrorResponse("missing ram_request_headers"), nil
	}
	headers, err := parseRamRequestHeaders(headersB64)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("Error parsing ram_request_headers: %v", err)), nil
	}
	if headers == nil {
		return logical.ErrorResponse("nil response when parsing ram_request_headers"), nil
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
	// This could either be a "userID:SessionID" (in the case of an assumed role) or just a "userID"
	// (in the case of an RAM user).
	callerUniqueId := strings.Split(callerID.UserID, ":")[0]

	// If we're just looking up for MFA, return the Alias info
	if req.Operation == logical.AliasLookaheadOperation {
		return &logical.Response{
			Auth: &logical.Auth{
				Alias: &logical.Alias{
					Name: callerUniqueId,
				},
			},
		}, nil
	}

	entity, err := parseRamArn(callerID.ARN)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("error parsing arn %q: %v", callerID.ARN, err)), nil
	}

	roleName := data.Get("role").(string)
	if roleName == "" {
		roleName = entity.FriendlyName
	}

	roleEntry, err := b.roleMgr.Read(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if roleEntry == nil {
		return logical.ErrorResponse(fmt.Sprintf("entry for role %s not found", roleName)), nil
	}

	if len(roleEntry.BoundRamPrincipalARNs) > 0 {
		switch {
		case !roleEntry.ResolveAlibabaUniqueIDs && strutil.StrListContains(roleEntry.BoundRamPrincipalARNs, entity.canonicalArn()):
		default:
			matchedWildcardBind := false
			for _, principalARN := range roleEntry.BoundRamPrincipalARNs {
				if strings.HasSuffix(principalARN, "*") && strutil.GlobbedStringsMatch(principalARN, callerID.ARN) {
					matchedWildcardBind = true
					break
				}
			}
			if !matchedWildcardBind {
				return logical.ErrorResponse(fmt.Sprintf("RAM Principal %q does not belong to the role %q", callerID.ARN, roleName)), nil
			}
		}
	}

	resp := &logical.Response{
		Auth: &logical.Auth{
			Period:   roleEntry.Period,
			Policies: roleEntry.Policies,
			Metadata: map[string]string{
				"client_arn":           callerID.ARN,
				"canonical_arn":        entity.canonicalArn(),
				"client_user_id":       callerUniqueId,
				"account_id":           entity.AccountNumber,
			},
			InternalData: map[string]interface{}{
				"role_name": roleName,
			},
			DisplayName: entity.FriendlyName,
			LeaseOptions: logical.LeaseOptions{
				Renewable: true,
				TTL:       roleEntry.TTL,
				MaxTTL:    roleEntry.MaxTTL,
			},
			Alias: &logical.Alias{
				Name: callerUniqueId,
			},
		},
	}

	return resp, nil
}

func hasValuesForRamAuth(data *framework.FieldData) bool {
	_, hasRequestURL := data.GetOk("ram_request_url")
	_, hasRequestHeaders := data.GetOk("ram_request_headers")
	return hasRequestURL && hasRequestHeaders
}

func parseRamArn(ramArn string) (*ramEntity, error) {
	var entity ramEntity
	fullParts := strings.Split(ramArn, ":")
	if len(fullParts) != 5 {
		return nil, fmt.Errorf("unrecognized arn: contains %d colon-separated parts, expected 5", len(fullParts))
	}
	if fullParts[0] != "acs" {
		return nil, fmt.Errorf("unrecognized arn: does not begin with \"acs:\"")
	}
	entity.ACS = fullParts[0]
	if fullParts[1] != "ram" && fullParts[1] != "sts" {
		return nil, fmt.Errorf("unrecognized service: %v, not one of ram or sts", fullParts[1])
	}
	entity.AccountNumber = fullParts[3]
	parts := strings.Split(fullParts[4], "/")
	if len(parts) < 2 {
		return nil, fmt.Errorf("unrecognized arn: %q contains fewer than 2 slash-separated parts", fullParts[4])
	}
	entity.Type = parts[0]
	entity.Path = strings.Join(parts[1:len(parts)-1], "/")
	entity.FriendlyName = parts[len(parts)-1]
	// now, entity.FriendlyName should either be <UserName> or <RoleName>
	switch entity.Type {
	case "assumed-role":
		// Assumed roles don't have paths and have a slightly different format
		// parts[2] is <RoleSessionName>
		entity.Path = ""
		entity.FriendlyName = parts[1]
		entity.SessionInfo = parts[2]
	case "user":
	case "role":
	default:
		return &ramEntity{}, fmt.Errorf("unrecognized principal type: %q", entity.Type)
	}
	return &entity, nil
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
		return nil, fmt.Errorf("failed to base64 decode ram_request_headers")
	}
	var headersDecoded map[string]interface{}
	err = jsonutil.DecodeJSON(headersJson, &headersDecoded)
	if err != nil {
		return nil, errwrap.Wrapf(fmt.Sprintf("failed to JSON decode ram_request_headers %q: {{err}}", headersJson), err)
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

func submitCallerIdentityRequest(headers http.Header, u *url.URL) (*GetCallerIdentityResult, error) {
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

	result := &GetCallerIdentityResult{}
	if err := json.NewDecoder(response.Body).Decode(result); err != nil {
		return nil, errwrap.Wrapf("error decoding reponse: {{err}}", err)
	}
	return result, nil
}

type GetCallerIdentityResult struct {
	AccountID    string `json:"AccountId"`
	RequestID    string `json:"RequestID"`
	PrincipalID  string `json:"PrincipalID"`
	IdentityType string `json:"IdentityType"`
	ARN          string `json:"ARN"`
	UserID       string `json:"UserID"`
}

type ramEntity struct {
	ACS           string
	AccountNumber string
	Type          string
	Path          string
	FriendlyName  string
	SessionInfo   string
}

// TODO I don't think this is accurate or needed, this entire method, need to test.
// Returns a Vault-internal canonical ARN for referring to an RAM entity
func (e *ramEntity) canonicalArn() string {
	entityType := e.Type
	if entityType == "assumed-role" {
		entityType = "role"
	}
	return fmt.Sprintf("arn:%s:ram::%s:%s/%s", e.ACS, e.AccountNumber, entityType, e.FriendlyName)
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
