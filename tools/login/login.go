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
alicloud at a path of "alicloud". If not, adjust that code as well.

Also, CaptureOutboundIdentityRequest and ConstructVaultLoginRequest
are exported to facilitate easy use by Go developers who want to hit
the Vault API to login.

*/

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/auth/credentials/providers"
	"github.com/hashicorp/vault-plugin-auth-alicloud/tools"
)

func main() {

	region := os.Getenv("REGION")        // ex. 'us-west-1'
	roleName := os.Getenv("ROLE_NAME")   // ex. 'developers'
	vaultAddr := os.Getenv("VAULT_ADDR") // ex. 'http://127.0.0.1:8200'

	if region == "" {
		panic("REGION must be set")
	}
	if roleName == "" {
		panic("ROLE_NAME must be set")
	}
	if vaultAddr == "" {
		panic("VAULT_ADDR must be set")
	}

	// Credentials can be provided either explicitly via env vars,
	// or we will try to derive them from instance metadata.
	credentialChain := []providers.Provider{
		providers.NewEnvCredentialProvider(),
		providers.NewInstanceMetadataProvider(),
	}
	creds, err := providers.NewChainProvider(credentialChain).Retrieve()
	if err != nil {
		panic(err)
	}

	loginData, err := tools.GenerateLoginData(roleName, creds, region)
	if err != nil {
		panic(err)
	}

	b, err := json.Marshal(loginData)
	if err != nil {
		panic(err)
	}

	loginReq, err := http.NewRequest(http.MethodPost, vaultAddr+"/v1/auth/alicloud/login", bytes.NewReader(b))
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
