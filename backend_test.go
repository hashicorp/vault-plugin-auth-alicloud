package ali

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/auth/credentials"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/sts"
	"github.com/hashicorp/vault-plugin-auth-alibaba/tools"
	"github.com/hashicorp/vault/logical"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var (
	testCtx     = context.Background()
	testStorage = &logical.InmemStorage{}
	testBackend = func() logical.Backend {
		conf := &logical.BackendConfig{
			System: &logical.StaticSystemView{
				DefaultLeaseTTLVal: time.Hour,
				MaxLeaseTTLVal:     time.Hour,
			},
		}
		b, err := Factory(testCtx, conf)
		if err != nil {
			panic(err)
		}
		return b
	}()
	testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := `{
			"RequestId": "2C9BE469-4A35-44D5-9529-CAA280B11603",
			"AccountId": "1968132000123456",
			"UserId": "216959339000654321",
			"AccountId": "5128828231865463",
			"RoleId": "1234",
			"Arn": "acs:ram::5128828231865463:assumed-role/elk/vm-ram-i-rj978rorvlg76urhqh7q",
			"IdentityType": "assumed-role",
			"PrincipalId": "vm-ram-i-rj978rorvlg76urhqh7q"
		}`
		w.Write([]byte(response))
	}))
)

func TestBackend(t *testing.T) {
	defer testServer.Close()

	// Exercise all the role endpoints.
	t.Run("EmptyList", EmptyList)
	t.Run("CreateRole", CreateRole)
	t.Run("ReadRole", ReadRole)
	t.Run("ListOfOne", ListOfOne)
	t.Run("UpdateRole", UpdateRole)
	t.Run("ReadUpdatedRole", ReadUpdatedRole)
	t.Run("ListOfOne", ListOfOne)
	t.Run("DeleteRole", DeleteRole)
	t.Run("EmptyList", EmptyList)

	// Create the role again so we can test logging in.
	t.Run("CreateRole", CreateRole)
	t.Run("LoginSuccess", LoginSuccess)
}

func CreateRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/elk",
		Storage:   testStorage,
		Data: map[string]interface{}{
			"arn":      "acs:ram::5128828231865463:role/elk",
			"policies": "logstash",
			"ttl":      10,
			"max_ttl":  10,
			"period":   1,
		},
	}
	resp, err := testBackend.HandleRequest(testCtx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatal("expected nil response to represent a 204")
	}
}

func ReadRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/elk",
		Storage:   testStorage,
	}
	resp, err := testBackend.HandleRequest(testCtx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected response containing data")
	}
	if resp.Data["arn"] != "acs:ram::5128828231865463:role/elk" {
		t.Fatalf("expected arn of acs:ram::5128828231865463:role/elk but received %s", resp.Data["arn"])
	}
	if resp.Data["policies"].([]string)[0] != "logstash" {
		t.Fatalf("expected policy of logstash but received %s", resp.Data["policies"].([]string)[0])
	}
	if resp.Data["ttl"].(time.Duration) != 10 {
		t.Fatalf("expected ttl of 10 but received %d", resp.Data["ttl"].(time.Duration))
	}
	if resp.Data["max_ttl"].(time.Duration) != 10 {
		t.Fatalf("expected max_ttl of 10 but received %d", resp.Data["max_ttl"].(time.Duration))
	}
	if resp.Data["period"].(time.Duration) != 1 {
		t.Fatalf("expected period of 1 but received %d", resp.Data["period"].(time.Duration))
	}
}

func UpdateRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/elk",
		Storage:   testStorage,
		Data: map[string]interface{}{
			"max_ttl": 100,
		},
	}
	resp, err := testBackend.HandleRequest(testCtx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatal("expected nil response to represent a 204")
	}
}

func ReadUpdatedRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/elk",
		Storage:   testStorage,
	}
	resp, err := testBackend.HandleRequest(testCtx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatalf("expected response containing data")
	}
	if resp.Data["arn"] != "acs:ram::5128828231865463:role/elk" {
		t.Fatalf("expected arn of acs:ram::5128828231865463:role/elk but received %s", resp.Data["arn"])
	}
	if resp.Data["policies"].([]string)[0] != "logstash" {
		t.Fatalf("expected policy of logstash but received %s", resp.Data["policies"].([]string)[0])
	}
	if resp.Data["ttl"].(time.Duration) != 10 {
		t.Fatalf("expected ttl of 10 but received %d", resp.Data["ttl"].(time.Duration))
	}
	if resp.Data["max_ttl"].(time.Duration) != 100 {
		t.Fatalf("expected max_ttl of 100 but received %d", resp.Data["max_ttl"].(time.Duration))
	}
	if resp.Data["period"].(time.Duration) != 1 {
		t.Fatalf("expected period of 1 but received %d", resp.Data["period"].(time.Duration))
	}
}

func DeleteRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "role/elk",
		Storage:   testStorage,
	}
	resp, err := testBackend.HandleRequest(testCtx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatal("expected nil response to represent a 204")
	}
}

func EmptyList(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ListOperation,
		Path:      "role/",
		Storage:   testStorage,
	}
	resp, err := testBackend.HandleRequest(testCtx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected response containing data")
	}
	if resp.Data["keys"] != nil {
		t.Fatal("no keys should have been returned")
	}
}

func ListOfOne(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ListOperation,
		Path:      "role/",
		Storage:   testStorage,
	}
	resp, err := testBackend.HandleRequest(testCtx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected response containing data")
	}
	if len(resp.Data["keys"].([]string)) != 1 {
		t.Fatal("1 key should have been returned")
	}
	if resp.Data["keys"].([]string)[0] != "elk" {
		t.Fatalf("expected elk but received %s", resp.Data["keys"].([]string)[0])
	}
}

func LoginSuccess(t *testing.T) {
	data, err := generateLoginData(testServer.URL, "accessKeyID", "accessKeySecret", "securityToken", "us-west-2")
	if err != nil {
		t.Fatal(err)
	}
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   testStorage,
		Data:      data,
	}
	resp, err := testBackend.HandleRequest(testCtx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected response containing data")
	}
	if resp.Auth == nil {
		t.Fatal("should have received an auth")
	}
	if resp.Auth.Period != time.Second {
		t.Fatalf("expected period of 1 second but received %d", resp.Auth.Period)
	}
	if len(resp.Auth.Policies) != 1 {
		t.Fatalf("expected 1 policy but received %d", len(resp.Auth.Policies))
	}
	if resp.Auth.Policies[0] != "logstash" {
		t.Fatalf("expected logstash but received %s", resp.Auth.Policies[0])
	}
	if resp.Auth.Metadata["account_id"] != "5128828231865463" {
		t.Fatalf("expected 5128828231865463 but received %s", resp.Auth.Metadata["account_id"])
	}
	if resp.Auth.Metadata["user_id"] != "216959339000654321" {
		t.Fatalf("expected 216959339000654321 but received %s", resp.Auth.Metadata["user_id"])
	}
	if resp.Auth.Metadata["role_id"] != "1234" {
		t.Fatalf("expected 1234 but received %s", resp.Auth.Metadata["role_id"])
	}
	if resp.Auth.Metadata["arn"] != "acs:ram::5128828231865463:assumed-role/elk/vm-ram-i-rj978rorvlg76urhqh7q" {
		t.Fatalf("expected acs:ram::5128828231865463:assumed-role/elk/vm-ram-i-rj978rorvlg76urhqh7q but received %s", resp.Auth.Metadata["arn"])
	}
	if resp.Auth.Metadata["identity_type"] != "assumed-role" {
		t.Fatalf("expected assumed-role but received %s", resp.Auth.Metadata["identity_type"])
	}
	if resp.Auth.Metadata["principal_id"] != "vm-ram-i-rj978rorvlg76urhqh7q" {
		t.Fatalf("expected vm-ram-i-rj978rorvlg76urhqh7q but received %s", resp.Auth.Metadata["principal_id"])
	}
	if resp.Auth.Metadata["request_id"] != "2C9BE469-4A35-44D5-9529-CAA280B11603" {
		t.Fatalf("expected 2C9BE469-4A35-44D5-9529-CAA280B11603 but received %s", resp.Auth.Metadata["request_id"])
	}
	if resp.Auth.Metadata["role_name"] != "elk" {
		t.Fatalf("expected elk but received %s", resp.Auth.Metadata["role_name"])
	}
	if resp.Auth.InternalData["role_name"] != "elk" {
		t.Fatalf("expected elk but received %s", resp.Auth.InternalData["role_name"])
	}
	if resp.Auth.DisplayName != "vm-ram-i-rj978rorvlg76urhqh7q" {
		t.Fatalf("expected vm-ram-i-rj978rorvlg76urhqh7q but received %s", resp.Auth.DisplayName)
	}
	if !resp.Auth.LeaseOptions.Renewable {
		t.Fatal("auth should be renewable")
	}
	if resp.Auth.LeaseOptions.TTL != 10*time.Second {
		t.Fatal("ttl should be 10 seconds")
	}
	if resp.Auth.LeaseOptions.MaxTTL != 10*time.Second {
		t.Fatal("max ttl should be 10 seconds")
	}
	if resp.Auth.Alias.Name != "vm-ram-i-rj978rorvlg76urhqh7q" {
		t.Fatalf("expected vm-ram-i-rj978rorvlg76urhqh7q but received %s", resp.Auth.Alias.Name)
	}
}

// generateLoginData is just like GenerateLoginData in the tools package,
// but it allows you to inject a testURL for a local http test server
// so the request can be intercepted and the response can be spoofed.
func generateLoginData(testURL, accessKeyID, accessKeySecret, securityToken, region string) (map[string]interface{}, error) {
	creds := credentials.NewStsTokenCredential(accessKeyID, accessKeySecret, securityToken)

	config := sdk.NewConfig()

	// This call always must be https but the config doesn't default to that.
	config.Scheme = "https"

	// Prepare to record the request using a proxy that will capture it and throw an error so it's not executed.
	capturer := &tools.RequestCapturer{}
	transport := &http.Transport{}
	transport.Proxy = capturer.Proxy
	config.HttpTransport = transport

	client, err := sts.NewClientWithOptions(region, config, creds)
	if err != nil {
		return nil, err
	}

	if _, err := client.GetCallerIdentity(sts.CreateGetCallerIdentityRequest()); err != nil {
		// This is expected because it's thrown from the RequestCapturer's Proxy method.
	}

	getCallerIdentityRequest, err := capturer.GetCapturedRequest()
	if err != nil {
		return nil, err
	}

	// This is where the magic happens and we inject the test server's URL,
	// which will be where Vault ultimately sends the login request.
	realBaseUrl := "https://sts.aliyuncs.com"
	rawUrl := getCallerIdentityRequest.URL.String()
	if !strings.Contains(rawUrl, realBaseUrl) {
		return nil, errors.New("the getCallerIdentityRequest base URL has changed so this test needs to be updated or it will fire real requests")
	} else {
		rawUrl = strings.Replace(rawUrl, realBaseUrl, testURL, -1)
	}

	u := base64.StdEncoding.EncodeToString([]byte(rawUrl))
	b, err := json.Marshal(getCallerIdentityRequest.Header)
	if err != nil {
		return nil, err
	}
	headers := base64.StdEncoding.EncodeToString(b)
	return map[string]interface{}{
		"identity_request_url":     u,
		"identity_request_headers": headers,
	}, nil
}
