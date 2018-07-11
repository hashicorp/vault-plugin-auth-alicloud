package tools

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/auth/credentials"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/sts"
)

// Generates the necessary data to send to the Vault server for generating a token
// This is useful for other API clients to use
func GenerateLoginData(accessKeyID, accessKeySecret, securityToken, region string) (map[string]interface{}, error) {
	creds := credentials.NewStsTokenCredential(accessKeyID, accessKeySecret, securityToken)

	config := sdk.NewConfig()

	// This call always must be https but the config doesn't default to that.
	config.Scheme = "https"

	// Prepare to record the request using a proxy that will capture it and throw an error so it's not executed.
	capturer := &RequestCapturer{}
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

	u := base64.StdEncoding.EncodeToString([]byte(getCallerIdentityRequest.URL.String()))
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

/*
RequestCapturer fulfills the Proxy method of http.Transport, so can be used to replace
the Proxy method on any transport method to simply capture the request.
Its Proxy method always returns an error so the request won't actually be fired.
This is useful for quickly finding out what final request a client is sending.
*/
type RequestCapturer struct {
	request *http.Request
}

func (r *RequestCapturer) Proxy(req *http.Request) (*url.URL, error) {
	r.request = req
	return nil, errors.New("throwing an error so we won't actually execute the request")
}

func (r *RequestCapturer) GetCapturedRequest() (*http.Request, error) {
	if r.request == nil {
		return nil, errors.New("no request captured")
	}
	return r.request, nil
}
