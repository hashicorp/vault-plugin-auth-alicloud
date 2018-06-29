package ali

import "time"

// Struct to hold the information associated with a Vault authTypeRole
type RoleEntry struct {
	ARN      string        `json:"arn"`
	AuthType authType      `json:"auth_type"`
	Policies []string      `json:"policies"`
	TTL      time.Duration `json:"ttl"`
	MaxTTL   time.Duration `json:"max_ttl"`
	Period   time.Duration `json:"period"`
}

func (r *RoleEntry) ToResponseData() map[string]interface{} {
	responseData := map[string]interface{}{
		"arn":      r.ARN,
		"policies": r.Policies,
		"ttl":      r.TTL / time.Second,
		"max_ttl":  r.MaxTTL / time.Second,
		"period":   r.Period / time.Second,
	}

	if r.ARN == "" {
		responseData["arn"] = []string{}
	} else {
		responseData["arn"] = r.ARN
	}

	return responseData
}
