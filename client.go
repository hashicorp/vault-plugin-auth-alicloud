package ali

import (
	"context"
	"errors"
	"os"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/auth"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/auth/credentials"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ram"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/sts"
	"github.com/hashicorp/vault/logical"
)

const (
	EnvVarAccessKeyID     = "ALIBABA_ACCESS_KEY_ID"
	EnvVarSecretAccessKey = "ALIBABA_SECRET_ACCESS_KEY"
)

func (b *backend) getSTSClient(ctx context.Context, s logical.Storage, regionID string) (*sts.Client, error) {
	credential, err := b.getCredential(ctx, s)
	if err != nil {
		return nil, err
	}
	return sts.NewClientWithOptions(regionID, sdk.NewConfig(), credential)
}

func (b *backend) getRAMClient(ctx context.Context, s logical.Storage) (*ram.Client, error) {
	credential, err := b.getCredential(ctx, s)
	if err != nil {
		return nil, err
	}
	config := sdk.NewConfig()
	config.Scheme = "https"
	return ram.NewClientWithOptions("", config, credential)
}

func (b *backend) getCredential(ctx context.Context, s logical.Storage) (auth.Credential, error) {
	// Read the configured secret key and access key
	config, err := b.nonLockedClientConfigEntry(ctx, s)
	if err != nil {
		return nil, err
	}

	if config != nil {
		if config.AccessKey != "" && config.SecretKey != "" {
			return credentials.NewAccessKeyCredential(config.AccessKey, config.SecretKey), nil
		}
	}

	// Read the secret key and access key from the outer environment.
	accessKey := os.Getenv(EnvVarAccessKeyID)
	secretKey := os.Getenv(EnvVarSecretAccessKey)
	if accessKey != "" && secretKey != "" {
		return credentials.NewAccessKeyCredential(accessKey, secretKey), nil
	}
	return nil, errors.New("unable to determine credential")
}
