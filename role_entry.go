package ali

import "time"

// Struct to hold the information associated with a Vault role
type RoleEntry struct {
	BoundIamPrincipalARNs   []string      `json:"bound_iam_principal_arn_list"`
	ResolveAlibabaUniqueIDs bool          `json:"resolve_aws_unique_ids"`
	TTL                     time.Duration `json:"ttl"`
	MaxTTL                  time.Duration `json:"max_ttl"`
	Policies                []string      `json:"policies"`
	Period                  time.Duration `json:"period"`
}

func (r *RoleEntry) ToResponseData() map[string]interface{} {
	responseData := map[string]interface{}{
		"resolve_aws_unique_ids":  r.ResolveAlibabaUniqueIDs,
		"ttl":      r.TTL / time.Second,
		"max_ttl":  r.MaxTTL / time.Second,
		"policies": r.Policies,
		"period":   r.Period / time.Second,
	}

	if r.BoundIamPrincipalARNs == nil {
		responseData["bound_iam_principal_arn"] = []string{}
	} else {
		responseData["bound_iam_principal_arn"] =  r.BoundIamPrincipalARNs
	}

	return responseData
}
