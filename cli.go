package ali

import (
	"fmt"
	"strings"

	"github.com/hashicorp/vault-plugin-auth-alibaba/tools"
	"github.com/hashicorp/vault/api"
)

type CLIHandler struct{}

func (h *CLIHandler) Auth(c *api.Client, m map[string]string) (*api.Secret, error) {
	mount, ok := m["mount"]
	if !ok {
		mount = "alibaba"
	}
	role := m["role"]

	loginData, err := tools.GenerateLoginData(m["access_key_id"], m["access_key_secret"], m["security_token"], m["region"])
	if err != nil {
		return nil, err
	}

	loginData["role"] = role
	path := fmt.Sprintf("auth/%s/login", mount)

	secret, err := c.Logical().Write(path, loginData)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, fmt.Errorf("empty response from credential provider")
	}
	return secret, nil
}

func (h *CLIHandler) Help() string {
	help := `
Usage: vault login -method=alibaba [CONFIG K=V...]

  The Alibaba auth method allows users to authenticate with Alibaba RAM
  credentials.

  The Alibaba RAM credentials may be specified explicitly via the command line:

      $ vault login -method=alibaba access_key_id=... access_key_secret=... security_token=... region=...

Configuration:

  access_key_id=<string>
      Explicit Alibaba access key ID

  access_key_secret=<string>
      Explicit Alibaba secret access key

  security_token=<string>
      Explicit Alibaba security token

  region=<string>
	  Explicit Alibaba region

  mount=<string>
      Path where the AWS credential method is mounted. This is usually provided
      via the -path flag in the "vault login" command, but it can be specified
      here as well. If specified here, it takes precedence over the value for
      -path. The default value is "aws".

  role=<string>
      Name of the role to request a token against
`

	return strings.TrimSpace(help)
}
