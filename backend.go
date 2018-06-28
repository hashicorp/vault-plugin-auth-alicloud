package ali

import (
	"context"
	"fmt"
	"sync"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/ram"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := Backend(conf)
	if err != nil {
		return nil, err
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

type backend struct {
	*framework.Backend

	roleMgr *RoleManager

	// Lock to make changes to any of the backend's configuration endpoints.
	configMutex sync.RWMutex

	resolveArnToUniqueIDFunc func(ctx context.Context, s logical.Storage, arn string) (string, error)
}

func Backend(conf *logical.BackendConfig) (*backend, error) {
	roleMgr := &RoleManager{}
	b := &backend{
		roleMgr:             roleMgr,
	}

	b.resolveArnToUniqueIDFunc = b.resolveArnToRealUniqueId

	b.Backend = &framework.Backend{
		AuthRenew: b.pathLoginRenew,
		Help:      backendHelp,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login",
			},
			SealWrapStorage: []string{
				"config/client",
			},
		},
		Paths: []*framework.Path{
			pathLogin(b),
			pathListRole(b),
			pathListRoles(b),
			pathRole(b),
			pathConfigClient(b),
		},
		BackendType: logical.TypeCredential,
	}
	return b, nil
}

// Putting this here so we can inject a fake resolver into the backend for unit testing
// purposes
func (b *backend) resolveArnToRealUniqueId(ctx context.Context, s logical.Storage, arn string) (string, error) {
	entity, err := parseRamArn(arn)
	if err != nil {
		return "", err
	}

	iamClient, err := b.getRAMClient(ctx, s)
	if err != nil {
		return "", err
	}
	switch entity.Type {
	case "user":
		req := ram.CreateGetUserRequest()
		req.UserName = entity.FriendlyName
		userInfo, err := iamClient.GetUser(req)
		if err != nil {
			return "", err
		}
		if userInfo == nil {
			return "", fmt.Errorf("got nil result from GetUser")
		}
		return userInfo.User.UserId, nil
	case "role":
		req := ram.CreateGetRoleRequest()
		req.RoleName = entity.FriendlyName
		roleInfo, err := iamClient.GetRole(req)
		if err != nil {
			return "", err
		}
		if roleInfo == nil {
			return "", fmt.Errorf("got nil result from GetRole")
		}
		return roleInfo.Role.RoleId, nil
	default:
		return "", fmt.Errorf("unrecognized error type %#v", entity.Type)
	}
}

const backendHelp = `
That Alibaba RAM auth method allows entities to authenticate based on their
identity and pre-configured roles.
`
