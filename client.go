package ali

import (
	"errors"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/auth"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/auth/credentials"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ram"
)

// There's only one endpoint for RAM, yet its client demands that you have the endpoint
// because it's reused for other things. It always uses an endpoint to go through its list
// of endpoints in each region and pull out the correct one.
// For RAM, it will always resolve to "https://ram.aliyuncs.com"
// no matter what region you plug in.
// For support on this assertion, see
// https://www.alibabacloud.com/help/doc-detail/28672.htm?spm=a2c63.p38356.b99.49.7e001606Bs8ENp and
// https://github.com/aliyun/alibaba-cloud-sdk-go/blob/61403c78b5eb7b3360e31ec12aa8b03d14d735eb/sdk/endpoints/endpoints_config.go#L425
const ramRegion = "us-east-1"

func getRAMClient(storedConf *clientConfig) (*ram.Client, error) {
	credential, err := getCredential(storedConf)
	if err != nil {
		return nil, err
	}
	config := sdk.NewConfig()
	config.Scheme = "https"
	return ram.NewClientWithOptions(ramRegion, config, credential)
}

func getCredential(storedConf *clientConfig) (auth.Credential, error) {
	if storedConf != nil {
		if storedConf.AccessKey != "" && storedConf.SecretKey != "" {
			return credentials.NewAccessKeyCredential(storedConf.AccessKey, storedConf.SecretKey), nil
		}
	}
	return nil, errors.New("unable to determine credential")
}
