package alicloud

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/auth/credentials/providers"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/vault-plugin-auth-alicloud/tools"
	"github.com/hashicorp/vault/logical"
)

var (
	testCtx     = context.Background()
	testStorage = &logical.InmemStorage{}
	testBackend = func() logical.Backend {
		client := cleanhttp.DefaultClient()
		client.Transport = &fauxRoundTripper{}
		b := newBackend(client)
		conf := &logical.BackendConfig{
			System: &logical.StaticSystemView{
				DefaultLeaseTTLVal: time.Hour,
				MaxLeaseTTLVal:     time.Hour,
			},
		}
		if err := b.Setup(testCtx, conf); err != nil {
			panic(err)
		}
		return b
	}()
)

func TestBackend(t *testing.T) {
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
			"arn":         "acs:ram::5138828231865461:role/elk",
			"policies":    "logstash",
			"ttl":         10,
			"max_ttl":     10,
			"period":      1,
			"bound_cidrs": []string{"127.0.0.1/24"},
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
	if resp.Data["arn"] != "acs:ram::5138828231865461:role/elk" {
		t.Fatalf("expected arn of acs:ram::5138828231865461:role/elk but received %s", resp.Data["arn"])
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
	if resp.Data["arn"] != "acs:ram::5138828231865461:role/elk" {
		t.Fatalf("expected arn of acs:ram::5138828231865461:role/elk but received %s", resp.Data["arn"])
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
	creds, err := providers.NewConfigurationCredentialProvider(&providers.Configuration{
		AccessKeyID:       "accessKeyID",
		AccessKeySecret:   "accessKeySecret",
		AccessKeyStsToken: "securityToken",
	}).Retrieve()
	if err != nil {
		t.Fatal(err)
	}

	data, err := tools.GenerateLoginData(creds, "us-west-2")
	if err != nil {
		t.Fatal(err)
	}
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   testStorage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1/24",
		},
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
	if resp.Auth.Metadata["account_id"] != "5138828231865461" {
		t.Fatalf("expected 5138828231865461 but received %s", resp.Auth.Metadata["account_id"])
	}
	if resp.Auth.Metadata["user_id"] != "216959339000654321" {
		t.Fatalf("expected 216959339000654321 but received %s", resp.Auth.Metadata["user_id"])
	}
	if resp.Auth.Metadata["role_id"] != "1234" {
		t.Fatalf("expected 1234 but received %s", resp.Auth.Metadata["role_id"])
	}
	if resp.Auth.Metadata["arn"] != "acs:ram::5138828231865461:assumed-role/elk/vm-ram-i-rj978rorvlg76urhqh7q" {
		t.Fatalf("expected acs:ram::5138828231865461:assumed-role/elk/vm-ram-i-rj978rorvlg76urhqh7q but received %s", resp.Auth.Metadata["arn"])
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

type fauxRoundTripper struct{}

// This simply returns a spoofed successful response from the GetCallerIdentity endpoint.
func (f *fauxRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	respBody := map[string]string{
		"RequestId":    "2C9BE469-4A35-44D5-9529-CAA280B11603",
		"UserId":       "216959339000654321",
		"AccountId":    "5138828231865461",
		"RoleId":       "1234",
		"Arn":          "acs:ram::5138828231865461:assumed-role/elk/vm-ram-i-rj978rorvlg76urhqh7q",
		"IdentityType": "assumed-role",
		"PrincipalId":  "vm-ram-i-rj978rorvlg76urhqh7q",
	}
	b, err := json.Marshal(respBody)
	if err != nil {
		return nil, err
	}
	resp := &http.Response{
		Body:       ioutil.NopCloser(bytes.NewReader(b)),
		StatusCode: 200,
	}
	return resp, nil
}
