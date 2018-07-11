package ali

import "time"

type roleEntry struct {
	ARN      *arn          `json:"arn"`
	Policies []string      `json:"policies"`
	TTL      time.Duration `json:"ttl"`
	MaxTTL   time.Duration `json:"max_ttl"`
	Period   time.Duration `json:"period"`
}

func (r *roleEntry) ToResponseData() map[string]interface{} {
	return map[string]interface{}{
		"arn":      r.ARN.String(),
		"policies": r.Policies,
		"ttl":      r.TTL / time.Second,
		"max_ttl":  r.MaxTTL / time.Second,
		"period":   r.Period / time.Second,
	}
}
