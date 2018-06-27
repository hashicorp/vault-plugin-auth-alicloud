package common

import "time"

// Struct to hold the information associated with a Vault role
type RoleEntry struct {
	AuthType                 string        `json:"auth_type" `
	BoundAmiIDs              []string      `json:"bound_ami_id_list"`
	BoundAccountIDs          []string      `json:"bound_account_id_list"`
	BoundEc2InstanceIDs      []string      `json:"bound_ec2_instance_id_list"`
	BoundIamPrincipalARNs    []string      `json:"bound_iam_principal_arn_list"`
	BoundIamPrincipalIDs     []string      `json:"bound_iam_principal_id_list"`
	BoundIamRoleARNs         []string      `json:"bound_iam_role_arn_list"`
	BoundRegions             []string      `json:"bound_region_list"`
	BoundVSwitchIDs          []string      `json:"bound_vswitch_id_list"`
	BoundVpcIDs              []string      `json:"bound_vpc_id_list"`
	InferredEntityType       string        `json:"inferred_entity_type"`
	InferredAWSRegion        string        `json:"inferred_aws_region"`
	ResolveAWSUniqueIDs      bool          `json:"resolve_aws_unique_ids"`
	RoleTag                  string        `json:"role_tag"`
	AllowInstanceMigration   bool          `json:"allow_instance_migration"`
	TTL                      time.Duration `json:"ttl"`
	MaxTTL                   time.Duration `json:"max_ttl"`
	Policies                 []string      `json:"policies"`
	DisallowReauthentication bool          `json:"disallow_reauthentication"`
	HMACKey                  string        `json:"hmac_key"`
	Period                   time.Duration `json:"period"`
}

func (r *RoleEntry) ToResponseData() map[string]interface{} {
	responseData := map[string]interface{}{
		"auth_type":                r.AuthType,
		"bound_ami_id":             r.BoundAmiIDs,
		"bound_account_id":         r.BoundAccountIDs,
		"bound_ec2_instance_id":    r.BoundEc2InstanceIDs,
		"bound_iam_principal_arn":  r.BoundIamPrincipalARNs,
		"bound_iam_principal_id":   r.BoundIamPrincipalIDs,
		"bound_iam_role_arn":       r.BoundIamRoleARNs,
		"bound_region":             r.BoundRegions,
		"bound_subnet_id":          r.BoundVSwitchIDs,
		"bound_vpc_id":             r.BoundVpcIDs,
		"inferred_entity_type":     r.InferredEntityType,
		"inferred_aws_region":      r.InferredAWSRegion,
		"resolve_aws_unique_ids":   r.ResolveAWSUniqueIDs,
		"role_tag":                 r.RoleTag,
		"allow_instance_migration": r.AllowInstanceMigration,
		"ttl":                       r.TTL / time.Second,
		"max_ttl":                   r.MaxTTL / time.Second,
		"policies":                  r.Policies,
		"disallow_reauthentication": r.DisallowReauthentication,
		"period":                    r.Period / time.Second,
	}

	convertNilToEmptySlice := func(data map[string]interface{}, field string) {
		if data[field] == nil || len(data[field].([]string)) == 0 {
			data[field] = []string{}
		}
	}
	convertNilToEmptySlice(responseData, "bound_ami_id")
	convertNilToEmptySlice(responseData, "bound_account_id")
	convertNilToEmptySlice(responseData, "bound_iam_principal_arn")
	convertNilToEmptySlice(responseData, "bound_iam_principal_id")
	convertNilToEmptySlice(responseData, "bound_iam_role_arn")
	convertNilToEmptySlice(responseData, "bound_region")
	convertNilToEmptySlice(responseData, "bound_subnet_id")
	convertNilToEmptySlice(responseData, "bound_vpc_id")

	return responseData
}
