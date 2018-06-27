package alibaba

import (
	"context"
	"fmt"
	"time"

	"sync"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/ram"
	"github.com/hashicorp/vault/builtin/credential/alibaba/common"
	"github.com/hashicorp/vault/builtin/credential/alibaba/ecsmethod"
	"github.com/hashicorp/vault/builtin/credential/alibaba/ecsmethod/blacklist"
	"github.com/hashicorp/vault/builtin/credential/alibaba/ecsmethod/whitelist"
	"github.com/hashicorp/vault/builtin/credential/alibaba/rammethod"
	"github.com/hashicorp/vault/helper/consts"
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

	whitelistConfig *whitelist.ConfigHandler
	whitelistTidy   *whitelist.TidyHandler
	whitelist       *whitelist.Handler

	blacklistConfig *blacklist.ConfigHandler
	blacklistTidy   *blacklist.TidyHandler
	blacklist       *blacklist.Handler

	stsConfig *rammethod.ConfigHandler

	roleMgr  *common.RoleManager
	roleTags *ecsmethod.RoleTagHandler

	// Lock to make changes to any of the backend's configuration endpoints.
	configMutex sync.RWMutex

	// Duration after which the periodic function of the backend needs to
	// tidy the blacklist and whitelistConfig entries.
	tidyCooldownPeriod time.Duration

	// nextTidyTime holds the time at which the periodic func should initiate
	// the tidy operations. This is set by the periodicFunc based on the value
	// of tidyCooldownPeriod.
	nextTidyTime time.Time

	// Map of AWS unique IDs to the full ARN corresponding to that unique ID
	// This avoids the overhead of an AWS API hit for every login request
	// using the IAM auth method when bound_iam_principal_arn contains a wildcard
	iamUserIdToArnCache *cache.Cache

	// AWS Account ID of the "default" AWS credentials
	// This cache avoids the need to call GetCallerIdentity repeatedly to learn it
	// We can't store this because, in certain pathological cases, it could change
	// out from under us, such as a standby and active Vault server in different AWS
	// accounts using their IAM instance profile to get their credentials.
	defaultAWSAccountID string

	resolveArnToUniqueIDFunc func(ctx context.Context, s logical.Storage, arn string) (string, error)
}

func Backend(conf *logical.BackendConfig) (*backend, error) {
	roleMgr := &common.RoleManager{}
	b := &backend{
		// Setting the periodic func to be run once in an hour.
		// If there is a real need, this can be made configurable.
		tidyCooldownPeriod:  time.Hour,
		iamUserIdToArnCache: cache.New(7*24*time.Hour, 24*time.Hour),
		whitelistConfig:     &whitelist.ConfigHandler{},
		whitelistTidy:       &whitelist.TidyHandler{},
		whitelist:           &whitelist.Handler{},
		blacklistConfig:     &blacklist.ConfigHandler{},
		blacklistTidy:       &blacklist.TidyHandler{},
		blacklist:           &blacklist.Handler{RoleMgr: roleMgr},
		roleMgr:             roleMgr,
		stsConfig:           &rammethod.ConfigHandler{},
		roleTags:            &ecsmethod.RoleTagHandler{RoleMgr: roleMgr},
	}

	b.resolveArnToUniqueIDFunc = b.resolveArnToRealUniqueId

	b.Backend = &framework.Backend{
		PeriodicFunc: b.periodicFunc,
		AuthRenew:    b.pathLoginRenew,
		Help:         backendHelp,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login",
			},
			LocalStorage: []string{
				"whitelistConfig/identity/",
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
			b.roleTags.PathRoleTag(),
			pathConfigClient(b),
			b.stsConfig.PathConfigSts(),
			b.stsConfig.PathListSts(),
			b.blacklistConfig.PathConfigTidyRoletagBlacklist(),
			b.blacklist.PathListRoletagBlacklist(),
			b.blacklist.PathRoletagBlacklist(),
			b.blacklistTidy.PathTidyRoletagBlacklist(),
			b.whitelistConfig.PathConfigTidyIdentityWhitelist(),
			b.whitelist.PathListIdentityWhitelist(),
			b.whitelist.PathIdentityWhitelist(),
			b.whitelistTidy.PathTidyIdentityWhitelist(),
		},
		Invalidate:  b.invalidate,
		BackendType: logical.TypeCredential,
	}
	// TODO it's a little weird this doesn't happen above
	b.blacklist.System = b.System()
	b.roleTags.System = b.System()

	return b, nil
}

// TODO does this really belong here or with the blacklist, whitelistConfig, etc.?
// periodicFunc performs the tasks that the backend wishes to do periodically.
// Currently this will be triggered once in a minute by the RollbackManager.
//
// The tasks being done currently by this function are to cleanup the expired
// entries of both blacklist role tags and whitelistConfig identities. Tidying is done
// not once in a minute, but once in an hour, controlled by 'tidyCooldownPeriod'.
// Tidying of blacklist and whitelistConfig are by default enabled. This can be
// changed using `config/tidy/roletags` and `config/tidy/identities` endpoints.
func (b *backend) periodicFunc(ctx context.Context, req *logical.Request) error {
	// Run the tidy operations for the first time. Then run it when current
	// time matches the nextTidyTime.
	if b.nextTidyTime.IsZero() || !time.Now().Before(b.nextTidyTime) {
		if b.System().LocalMount() || !b.System().ReplicationState().HasState(consts.ReplicationPerformanceSecondary) {
			// safety_buffer defaults to 180 days for roletag blacklist
			safety_buffer := 15552000
			tidyBlacklistConfigEntry, err := b.blacklistConfig.LockedConfigTidyRoleTags(ctx, req.Storage)
			if err != nil {
				return err
			}
			skipBlacklistTidy := false
			// check if tidying of role tags was configured
			if tidyBlacklistConfigEntry != nil {
				// check if periodic tidying of role tags was disabled
				if tidyBlacklistConfigEntry.DisablePeriodicTidy {
					skipBlacklistTidy = true
				}
				// overwrite the default safety_buffer with the configured value
				safety_buffer = tidyBlacklistConfigEntry.SafetyBuffer
			}
			// tidy role tags if explicitly not disabled
			if !skipBlacklistTidy {
				b.blacklistTidy.TidyBlacklistRoleTag(ctx, req.Storage, safety_buffer)
			}
		}

		// We don't check for replication state for whitelistConfig identities as
		// these are locally stored

		safety_buffer := 259200
		tidyWhitelistConfigEntry, err := b.whitelistConfig.LockedConfigTidyIdentities(ctx, req.Storage)
		if err != nil {
			return err
		}
		skipWhitelistTidy := false
		// check if tidying of identities was configured
		if tidyWhitelistConfigEntry != nil {
			// check if periodic tidying of identities was disabled
			if tidyWhitelistConfigEntry.DisablePeriodicTidy {
				skipWhitelistTidy = true
			}
			// overwrite the default safety_buffer with the configured value
			safety_buffer = tidyWhitelistConfigEntry.SafetyBuffer
		}
		// tidy identities if explicitly not disabled
		if !skipWhitelistTidy {
			b.whitelistTidy.TidyWhitelistIdentity(ctx, req.Storage, safety_buffer)
		}

		// Update the time at which to run the tidy functions again.
		b.nextTidyTime = time.Now().Add(b.tidyCooldownPeriod)
	}
	return nil
}

func (b *backend) invalidate(ctx context.Context, key string) {
	switch key {
	case "config/client":
		b.configMutex.Lock()
		defer b.configMutex.Unlock()
		// TODO if you end up caching clients again, flush them here
		b.defaultAWSAccountID = ""
	}
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
		userInfo, err := iamClient.GetUser(&ram.GetUserRequest{UserName: entity.FriendlyName})
		if err != nil {
			return "", err
		}
		if userInfo == nil {
			return "", fmt.Errorf("got nil result from GetUser")
		}
		return userInfo.User.UserId, nil
	case "role":
		roleInfo, err := iamClient.GetRole(&ram.GetRoleRequest{RoleName: entity.FriendlyName})
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
aws-ec2 auth method takes in PKCS#7 signature of an AWS EC2 instance and a client
created nonce to authenticates the EC2 instance with Vault.

Authentication is backed by a preconfigured role in the backend. The role
represents the authorization of resources by containing Vault's policies.
Role can be created using 'role/<role>' endpoint.

If there is need to further restrict the capabilities of the role on the instance
that is using the role, 'role_tag' option can be enabled on the role, and a tag
can be generated using 'role/<role>/tag' endpoint. This tag represents the
subset of capabilities set on the role. When the 'role_tag' option is enabled on
the role, the login operation requires that a respective role tag is attached to
the EC2 instance which performs the login.
`
