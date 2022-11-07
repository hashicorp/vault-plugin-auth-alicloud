package alicloud

// EndpointMap is taken from the alicloud documentation and is only the Europe
// and Americas endpoints. See the endpoint docs at:
// https://www.alibabacloud.com/help/en/resource-access-management/latest/api-doc-sts-2015-04-01-endpoint
//
// Alicloud Support said that there is not an API to fetch all sts endpoints.
// See the ticket at:
// https://workorder-intl.console.aliyun.com/console.htm?msctype=email&mscareaid=sg&mscsiteid=intl&mscmsgid=1690222110700066955&spm=a2c4k.11991735.enc.2&lang=en&accounttraceid=887ed555fd4c43cca57281472422b2ddierr#/ticket/detail/?ticketId=G21GFGGG
var EndpointMap = map[string]string{
	"us-east-1":    "sts.us-east-1.aliyuncs.com",
	"us-west-1":    "sts.us-west-1.aliyuncs.com",
	"eu-west-1":    "sts.eu-west-1.aliyuncs.com",
	"eu-central-1": "sts.eu-central-1.aliyuncs.com",
}
