package ali

import (
	"context"
	"sync"
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/patrickmn/go-cache"
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

	// remoteRoleCache is a cache for the roles we receive in a "ListRoles" response
	// from Alibaba, allowing us to reduce the number of calls we make for this possibly
	// expensive, paginating operation.
	remoteRoleCache *cache.Cache

	// Lock to make changes to any of the backend's configuration endpoints.
	configMutex sync.RWMutex

	resolveArnToUniqueIDFunc func(ctx context.Context, s logical.Storage, arn string) (string, error)
}

func Backend(conf *logical.BackendConfig) (*backend, error) {
	roleMgr := &RoleManager{}
	b := &backend{
		roleMgr:         roleMgr,
		remoteRoleCache: cache.New(time.Minute, time.Minute),
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
			pathConfigClient(b),
		},
		BackendType: logical.TypeCredential,
	}
	return b, nil
}

const backendHelp = `
That Alibaba RAM auth method allows entities to authenticate based on their
identity and pre-configured roles.
`
