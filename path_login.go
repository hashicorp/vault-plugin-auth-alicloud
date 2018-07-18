package ali

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/sts"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathLogin(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "login$",
		Fields: map[string]*framework.FieldSchema{
			"identity_request_url": {
				Type:        framework.TypeString,
				Description: "Base64-encoded full URL against which to make the Alibaba request.",
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

	b64Url := data.Get("identity_request_url").(string)
	if b64Url == "" {
		return nil, errors.New("missing identity_request_url")
	}
	identityReqUrl, err := base64.StdEncoding.DecodeString(b64Url)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode identity_request_url: %s", err)
	}
	if _, err := url.Parse(string(identityReqUrl)); err != nil {
		return nil, fmt.Errorf("error parsing identity_request_url: %s", err)
	}

	b64Header := data.Get("identity_request_headers").(string)
	if b64Header == "" {
		return nil, errors.New("missing identity_request_headers")
	}
	headers, err := parseHeaders(b64Header)
	if err != nil {
		return nil, fmt.Errorf("error parsing identity_request_headers: %v", err)
	}
	if headers == nil {
		return nil, errors.New("nil response when parsing identity_request_headers")
	}

	callerIdentity, err := getCallerIdentity(headers, string(identityReqUrl))
	if err != nil {
		return nil, fmt.Errorf("error making upstream request: %v", err)
	}

	parsedARN, err := parseARN(callerIdentity.Arn)
	if err != nil {
		return nil, fmt.Errorf("unable to parse entity's arn %s due to %s", callerIdentity.Arn, err)
	}
	if parsedARN.Type != arnTypeAssumedRole {
		return nil, fmt.Errorf("only role arn types are supported at this time, but %s was provided", callerIdentity.Arn)
	}

	roleEntry, err := b.roleMgr.Read(ctx, req.Storage, parsedARN.RoleName)
	if err != nil {
		return nil, err
	}
	if roleEntry == nil {
		return nil, fmt.Errorf("entry for role %s not found", parsedARN.RoleName)
	}

	if !parsedARN.IsMemberOf(roleEntry.ARN) {
		return nil, errors.New("the caller's arn does not match the role's arn")
	}
	return &logical.Response{
		Auth: &logical.Auth{
			Period:   roleEntry.Period,
			Policies: roleEntry.Policies,
			Metadata: map[string]string{
				"account_id":    callerIdentity.AccountId,
				"user_id":       callerIdentity.UserId,
				"role_id":       callerIdentity.RoleId,
				"arn":           callerIdentity.Arn,
				"identity_type": callerIdentity.IdentityType,
				"principal_id":  callerIdentity.PrincipalId,
				"request_id":    callerIdentity.RequestId,
				"role_name":     parsedARN.RoleName,
			},
			InternalData: map[string]interface{}{
				"role_name": parsedARN.RoleName,
			},
			DisplayName: callerIdentity.PrincipalId,
			LeaseOptions: logical.LeaseOptions{
				Renewable: true,
				TTL:       roleEntry.TTL,
				MaxTTL:    roleEntry.MaxTTL,
			},
			Alias: &logical.Alias{
				Name: callerIdentity.PrincipalId,
			},
		},
	}, nil
}

func (b *backend) pathLoginRenew(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	arn := req.Auth.Metadata["arn"]
	if arn == "" {
		return nil, errors.New("unable to retrieve arn from metadata during renewal")
	}

	roleName := ""
	roleNameIfc, ok := req.Auth.InternalData["role_name"]
	if ok {
		roleName = roleNameIfc.(string)
	}
	if roleName == "" {
		return nil, errors.New("error retrieving role_name during renewal")
	}

	roleEntry, err := b.roleMgr.Read(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if roleEntry == nil {
		return nil, errors.New("role entry not found")
	}

	if roleEntry.ARN.String() != arn {
		return nil, errors.New("the caller's arn does not match the role's arn")
	}

	resp := &logical.Response{Auth: req.Auth}
	resp.Auth.TTL = roleEntry.TTL
	resp.Auth.MaxTTL = roleEntry.MaxTTL
	resp.Auth.Period = roleEntry.Period
	return resp, nil
}

func getCallerIdentity(header http.Header, rawURL string) (*sts.GetCallerIdentityResponse, error) {
	request, err := http.NewRequest(http.MethodPost, rawURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header = header

	// Other clients are available but this one is used because it matches what Alibaba's
	// Go SDK uses and we're trying to match as closely as possible.
	client := &http.Client{}

	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("error making request: %s", err)
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		b, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return nil, fmt.Errorf("error reading response body: %s", err)
		}
		return nil, fmt.Errorf("received %d checking caller identity: %s", response.StatusCode, b)
	}

	result := &sts.GetCallerIdentityResponse{}
	if err := json.NewDecoder(response.Body).Decode(result); err != nil {
		return nil, fmt.Errorf("error decoding response: %s", err)
	}
	return result, nil
}

func parseHeaders(b64Header string) (http.Header, error) {
	b, err := base64.StdEncoding.DecodeString(b64Header)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode identity_request_headers")
	}
	var headers http.Header
	if err := json.Unmarshal(b, &headers); err != nil {
		return nil, fmt.Errorf("failed to JSON decode identity_request_headers %s: %s", b, err)
	}
	return headers, nil
}

const pathLoginSyn = `
Authenticates an RAM entity with Vault.
`

const pathLoginDesc = `
Authenticate Alibaba entities using an arbitrary RAM principal.

RAM principals are authenticated by processing a signed sts:GetCallerIdentity
request and then parsing the response to see who signed the request.
`
