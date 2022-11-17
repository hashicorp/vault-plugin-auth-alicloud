## Unreleased

Change:
* Require the `role` field on login

Bug Fixes:
* fix regression in vault login command that caused login to fail

Improvements:
* Update dependencies [GH-43](https://github.com/hashicorp/vault-plugin-auth-alicloud/pull/43)
  * github.com/aliyun/alibaba-cloud-sdk-go v1.61.1842
  * github.com/hashicorp/go-hclog v1.3.1
  * github.com/hashicorp/go-uuid v1.0.3
  * github.com/hashicorp/vault/api v1.8.2
  * github.com/hashicorp/vault/sdk v0.6.1

## 0.12.0
### May 25, 2022

* dep: update golang/x/sys to 9388b58f7150 [[GH-36](https://github.com/hashicorp/vault-plugin-auth-alicloud/pull/36)]
