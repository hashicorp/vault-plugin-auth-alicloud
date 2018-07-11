package ali

import (
	"context"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &backend{
		roleMgr: &RoleManager{},
	}
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
		},
		BackendType: logical.TypeCredential,
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

type backend struct {
	*framework.Backend
	roleMgr *RoleManager
}

const backendHelp = `
That Alibaba RAM auth method allows entities to authenticate based on their
identity and pre-configured roles.
`
