package ali

import (
	"context"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"errors"
)

func pathConfigClient(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/client$",
		Fields: map[string]*framework.FieldSchema{
			"access_key": {
				Type:        framework.TypeString,
				Default:     "",
				Description: "Alibaba Access Key ID for the account used to make Alibaba API requests.",
			},
			"secret_key": {
				Type:        framework.TypeString,
				Default:     "",
				Description: "Alibaba Secret Access Key for the account used to make Alibaba API requests.",
			},
			"instance_identity_audience": {
				Type:    framework.TypeString,
				Default: "",
				Description: `The value to require in the "audience" header as part of GetCallerIdentity requests that 
are used in the RAM auth method. If not set, then no value is required or validated. If set, clients must include an 
"audience" header in the headers of login requests, and further this header must be among the signed headers validated 
by Alibaba. This is to protect against different types of replay attacks, for example a signed request sent to a dev 
server being resent to a production server. Consider setting this to the Vault server's DNS name. See https://www.alibabacloud.com/help/doc-detail/67254.htm 
for more.`,
			},
		},

		ExistenceCheck: b.pathConfigClientExistenceCheck,

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.pathConfigClientCreateUpdate,
			logical.UpdateOperation: b.pathConfigClientCreateUpdate,
			logical.DeleteOperation: b.pathConfigClientDelete,
			logical.ReadOperation:   b.pathConfigClientRead,
		},

		HelpSynopsis:    pathConfigClientHelpSyn,
		HelpDescription: pathConfigClientHelpDesc,
	}
}

// Establishes dichotomy of request operation between CreateOperation and UpdateOperation.
// Returning 'true' forces an UpdateOperation, CreateOperation otherwise.
func (b *backend) pathConfigClientExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	entry, err := b.lockedClientConfigEntry(ctx, req.Storage)
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

// Fetch the client configuration required to access the Alibaba API, after acquiring an exclusive lock.
func (b *backend) lockedClientConfigEntry(ctx context.Context, s logical.Storage) (*clientConfig, error) {
	b.configMutex.RLock()
	defer b.configMutex.RUnlock()
	return b.nonLockedClientConfigEntry(ctx, s)
}

// Fetch the client configuration required to access the Alibaba API.
func (b *backend) nonLockedClientConfigEntry(ctx context.Context, s logical.Storage) (*clientConfig, error) {
	entry, err := s.Get(ctx, "config/client")
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result clientConfig
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (b *backend) pathConfigClientRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	clientConfig, err := b.lockedClientConfigEntry(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if clientConfig == nil {
		return nil, nil
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"access_key":                 clientConfig.AccessKey,
			"instance_identity_audience": clientConfig.InstanceIdentityAudience,
		},
	}, nil
}

func (b *backend) pathConfigClientDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.configMutex.Lock()
	defer b.configMutex.Unlock()
	if err := req.Storage.Delete(ctx, "config/client"); err != nil {
		return nil, err
	}
	return nil, nil
}

// pathConfigClientCreateUpdate is used to register the 'aws_secret_key' and 'aws_access_key'
// that can be used to interact with alibaba ECS API.
func (b *backend) pathConfigClientCreateUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.configMutex.Lock()
	defer b.configMutex.Unlock()

	configEntry, err := b.nonLockedClientConfigEntry(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if configEntry == nil {
		configEntry = &clientConfig{}
	}

	if accessKeyStr, ok := data.GetOk("access_key"); ok {
		configEntry.AccessKey = accessKeyStr.(string)
	} else if req.Operation == logical.CreateOperation {
		return nil, errors.New("access_key is required")
	}

	if secretKeyStr, ok := data.GetOk("secret_key"); ok {
		configEntry.SecretKey = secretKeyStr.(string)
	} else if req.Operation == logical.CreateOperation {
		return nil, errors.New("secret_key is required")
	}

	if headerValStr, ok := data.GetOk("instance_identity_audience"); ok {
		configEntry.InstanceIdentityAudience = headerValStr.(string)
	}

	entry, err := logical.StorageEntryJSON("config/client", configEntry)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

type clientConfig struct {
	AccessKey                string `json:"access_key"`
	SecretKey                string `json:"secret_key"`
	InstanceIdentityAudience string `json:"instance_identity_audience"`
}

const pathConfigClientHelpSyn = `
Configure Alibaba RAM credentials that are used to query identity details from the Alibaba API.
`

const pathConfigClientHelpDesc = `
The 'access_key' and 'secret_key' parameters configured here should map to an Alibaba RAM user that
has permission to make the ram:GetInstanceProfile API call.
`
