package main

/*

login is a simple tool that attempts to log into Vault
from a remote instance and prints out the results.
This can be useful for debugging login issues with a machine
because the binary can simply be plopped somewhere, the env
variables can be set, and you can try to login and see what
happens.

This does presume that you're using an access key and secret
to build the credentials for your request; however, it is possible
to provide credentials through other means. If that's the case for
your instance, consider editing the code below to match the
type of credentials you're using. It also assumes you've mounted
alibaba at a path of "alibaba". If not, adjust that code as well.

Also, CaptureOutboundIdentityRequest and ConstructVaultLoginRequest
are exported to facilitate easy use by Go developers who want to hit
the Vault API to login.

 */

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/auth/credentials"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/sts"
)

func main() {

	accessKey := os.Getenv("ALIBABA_ACCESS_KEY_ID")
	secretKey := os.Getenv("ALIBABA_SECRET_ACCESS_KEY")
	vaultAddr := os.Getenv("VAULT_ADDR") // ex. 'http://127.0.0.1:8200'

	sampleReq, err := CaptureOutboundIdentityRequest(accessKey, secretKey)
	if err != nil {
		panic(err)
	}

	loginReq, err := ConstructVaultLoginRequest(vaultAddr, sampleReq)
	if err != nil {
		panic(err)
	}

	resp, err := http.DefaultClient.Do(loginReq)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	fmt.Printf("response status code: %d\n", resp.StatusCode)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s", body)
}

type requestCapturer struct {
	request *http.Request
}

func (r *requestCapturer) Proxy(req *http.Request) (*url.URL, error) {
	r.request = req
	return nil, errors.New("throwing an error so we won't actually execute the request")
}

// CaptureOutboundIdentityRequest uses a tool to capture the GetCallerIdentity that would be sent
// by the Alibaba SDK on your behalf if you were to do that call.
// The request isn't actually executed, and instead is returned so it can be used
// to construct the request that will ultimately be sent to Vault to log in.
func CaptureOutboundIdentityRequest(accessKey, secretKey string) (*http.Request, error) {

	creds := credentials.NewAccessKeyCredential(accessKey, secretKey)

	config := sdk.NewConfig()

	// This call always must be https but the config doesn't default to that.
	config.Scheme = "https"

	// Prepare to record the request using a proxy that will capture it and throw an error so it's not executed.
	capturer := &requestCapturer{}
	transport := &http.Transport{}
	transport.Proxy = capturer.Proxy
	config.HttpTransport = transport

	client, err := sts.NewClientWithOptions("us-east-1", config, creds)
	if err != nil {
		return nil, err
	}

	if _, err := client.GetCallerIdentity(sts.CreateGetCallerIdentityRequest()); err != nil {
		// This is expected because it's thrown from the requestCapturer's Proxy method.
	}
	return capturer.request, nil
}

func ConstructVaultLoginRequest(vaultAddr string, outboundIdentityRequest *http.Request) (*http.Request, error) {
	// Base64 encode the URL.
	u := base64.URLEncoding.EncodeToString([]byte(outboundIdentityRequest.URL.String()))

	// Base64 endode the jsonified headers.
	b, err := json.Marshal(outboundIdentityRequest.Header)
	if err != nil {
		return nil, err
	}
	headers := base64.StdEncoding.EncodeToString(b)

	body := map[string]interface{}{
		"identity_request_url":     u,
		"identity_request_headers": headers,
	}
	b, err = json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return http.NewRequest(http.MethodPost, vaultAddr + "/v1/alibaba/login", bytes.NewReader(b))
}