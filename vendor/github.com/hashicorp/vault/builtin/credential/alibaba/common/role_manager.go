package common

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"time"

	"crypto/subtle"

	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"

	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/logical"
)

const RoleTagVersion = "v1"

type RoleManager struct {
	// Lock to make changes to role entries
	roleMutex sync.RWMutex
}

// Read returns the properties set on the given role. This method
// acquires the read lock before reading the role from the storage.
func (m *RoleManager) Read(ctx context.Context, s logical.Storage, roleName string) (*RoleEntry, error) {
	if roleName == "" {
		return nil, fmt.Errorf("missing role name")
	}

	m.roleMutex.RLock()
	defer m.roleMutex.RUnlock()
	return m.nonLockedAWSRole(ctx, s, roleName)
}

func (m *RoleManager) List(ctx context.Context, s logical.Storage) ([]string, error) {
	m.roleMutex.RLock()
	defer m.roleMutex.RUnlock()
	return s.List(ctx, "role/")
}

// Update creates or updates a role in the storage. This method
// acquires the write lock before creating or updating the role at the storage.
func (m *RoleManager) Update(ctx context.Context, s logical.Storage, roleName string, roleEntry *RoleEntry) error {
	if roleName == "" {
		return fmt.Errorf("missing role name")
	}

	if roleEntry == nil {
		return fmt.Errorf("nil role entry")
	}

	m.roleMutex.Lock()
	defer m.roleMutex.Unlock()

	return m.nonLockedSetAWSRole(ctx, s, roleName, roleEntry)
}

func (m *RoleManager) Delete(ctx context.Context, s logical.Storage, roleName string) error {
	m.roleMutex.Lock()
	defer m.roleMutex.Unlock()
	return s.Delete(ctx, "role/"+strings.ToLower(roleName))
}

// nonLockedSetAWSRole creates or updates a role in the storage. This method
// does not acquire the write lock before reading the role from the storage. If
// locking is desired, use Update instead.
func (m *RoleManager) nonLockedSetAWSRole(ctx context.Context, s logical.Storage, roleName string,
	roleEntry *RoleEntry) error {
	if roleName == "" {
		return fmt.Errorf("missing role name")
	}

	if roleEntry == nil {
		return fmt.Errorf("nil role entry")
	}

	entry, err := logical.StorageEntryJSON("role/"+strings.ToLower(roleName), roleEntry)
	if err != nil {
		return err
	}

	if err := s.Put(ctx, entry); err != nil {
		return err
	}

	return nil
}

// nonLockedAWSRole returns the properties set on the given role. This method
// does not acquire the read lock before reading the role from the storage. If
// locking is desired, use Read instead.
// This method also does NOT check to see if a role upgrade is required. It is
// the responsibility of the caller to check if a role upgrade is required and,
// if so, to upgrade the role
func (m *RoleManager) nonLockedAWSRole(ctx context.Context, s logical.Storage, roleName string) (*RoleEntry, error) {
	if roleName == "" {
		return nil, fmt.Errorf("missing role name")
	}

	entry, err := s.Get(ctx, "role/"+strings.ToLower(roleName))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result RoleEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// Parses the tag from string form into a struct form. This method
// also verifies the correctness of the parsed role tag.
func (m *RoleManager) ParseAndVerifyRoleTagValue(ctx context.Context, s logical.Storage, tag string) (*RoleTag, error) {
	tagItems := strings.Split(tag, ":")

	// Tag must contain version, nonce, policies and HMAC
	if len(tagItems) < 4 {
		return nil, fmt.Errorf("invalid tag")
	}

	rTag := &RoleTag{}

	// Cache the HMAC value. The last item in the collection.
	rTag.HMAC = tagItems[len(tagItems)-1]

	// Remove the HMAC from the list.
	tagItems = tagItems[:len(tagItems)-1]

	// Version will be the first element.
	rTag.Version = tagItems[0]
	if rTag.Version != RoleTagVersion {
		return nil, fmt.Errorf("invalid role tag version")
	}

	// Nonce will be the second element.
	rTag.Nonce = tagItems[1]

	// Delete the version and nonce from the list.
	tagItems = tagItems[2:]

	for _, tagItem := range tagItems {
		var err error
		switch {
		case strings.HasPrefix(tagItem, "i="):
			rTag.InstanceID = strings.TrimPrefix(tagItem, "i=")
		case strings.HasPrefix(tagItem, "r="):
			rTag.Role = strings.TrimPrefix(tagItem, "r=")
		case strings.HasPrefix(tagItem, "p="):
			rTag.Policies = strings.Split(strings.TrimPrefix(tagItem, "p="), ",")
		case strings.HasPrefix(tagItem, "d="):
			rTag.DisallowReauthentication, err = strconv.ParseBool(strings.TrimPrefix(tagItem, "d="))
			if err != nil {
				return nil, err
			}
		case strings.HasPrefix(tagItem, "m="):
			rTag.AllowInstanceMigration, err = strconv.ParseBool(strings.TrimPrefix(tagItem, "m="))
			if err != nil {
				return nil, err
			}
		case strings.HasPrefix(tagItem, "t="):
			rTag.MaxTTL, err = time.ParseDuration(fmt.Sprintf("%ss", strings.TrimPrefix(tagItem, "t=")))
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unrecognized item %q in tag", tagItem)
		}
	}

	if rTag.Role == "" {
		return nil, fmt.Errorf("missing role name")
	}

	roleEntry, err := m.Read(ctx, s, rTag.Role)
	if err != nil {
		return nil, err
	}
	if roleEntry == nil {
		return nil, fmt.Errorf("entry not found for %q", rTag.Role)
	}

	// Create a HMAC of the plaintext value of role tag and compare it with the given value.
	verified, err := verifyRoleTagValue(rTag, roleEntry)
	if err != nil {
		return nil, err
	}
	if !verified {
		return nil, fmt.Errorf("role tag signature verification failed")
	}

	return rTag, nil
}

// verifyRoleTagValue rebuilds the role tag's plaintext part, computes the HMAC
// from it using the role specific HMAC key and compares it with the received HMAC.
func verifyRoleTagValue(rTag *RoleTag, roleEntry *RoleEntry) (bool, error) {
	if rTag == nil {
		return false, fmt.Errorf("nil role tag")
	}

	if roleEntry == nil {
		return false, fmt.Errorf("nil role entry")
	}

	// Fetch the plaintext part of role tag
	rTagPlaintext, err := PrepareRoleTagPlaintextValue(rTag)
	if err != nil {
		return false, err
	}

	// Compute the HMAC of the plaintext
	hmacB64, err := CreateRoleTagHMACBase64(roleEntry.HMACKey, rTagPlaintext)
	if err != nil {
		return false, err
	}

	return subtle.ConstantTimeCompare([]byte(rTag.HMAC), []byte(hmacB64)) == 1, nil
}

// Creates base64 encoded HMAC using a per-role key.
func CreateRoleTagHMACBase64(key, value string) (string, error) {
	if key == "" {
		return "", fmt.Errorf("invalid HMAC key")
	}
	hm := hmac.New(sha256.New, []byte(key))
	hm.Write([]byte(value))

	// base64 encode the hmac bytes.
	return base64.StdEncoding.EncodeToString(hm.Sum(nil)), nil
}

// PrepareRoleTagPlaintextValue builds the role tag value without the HMAC in it.
func PrepareRoleTagPlaintextValue(rTag *RoleTag) (string, error) {
	if rTag == nil {
		return "", fmt.Errorf("nil role tag")
	}
	if rTag.Version == "" {
		return "", fmt.Errorf("missing version")
	}
	if rTag.Nonce == "" {
		return "", fmt.Errorf("missing nonce")
	}
	if rTag.Role == "" {
		return "", fmt.Errorf("missing role")
	}

	// Attach Version, Nonce, Role, DisallowReauthentication and AllowInstanceMigration
	// fields to the role tag.
	value := fmt.Sprintf("%s:%s:r=%s:d=%s:m=%s", rTag.Version, rTag.Nonce, rTag.Role, strconv.FormatBool(rTag.DisallowReauthentication), strconv.FormatBool(rTag.AllowInstanceMigration))

	// Attach the policies only if they are specified.
	if len(rTag.Policies) != 0 {
		value = fmt.Sprintf("%s:p=%s", value, strings.Join(rTag.Policies, ","))
	}

	// Attach instance_id if set.
	if rTag.InstanceID != "" {
		value = fmt.Sprintf("%s:i=%s", value, rTag.InstanceID)
	}

	// Attach max_ttl if it is provided.
	if int(rTag.MaxTTL.Seconds()) > 0 {
		value = fmt.Sprintf("%s:t=%d", value, int(rTag.MaxTTL.Seconds()))
	}

	return value, nil
}

// Struct RoleTag represents a role tag in a struct form.
type RoleTag struct {
	Version                  string        `json:"version"`
	InstanceID               string        `json:"instance_id"`
	Nonce                    string        `json:"nonce"`
	Policies                 []string      `json:"policies"`
	MaxTTL                   time.Duration `json:"max_ttl"`
	Role                     string        `json:"role"`
	HMAC                     string        `json:"hmac"`
	DisallowReauthentication bool          `json:"disallow_reauthentication"`
	AllowInstanceMigration   bool          `json:"allow_instance_migration"`
}

func (rTag1 *RoleTag) Equal(rTag2 *RoleTag) bool {
	return rTag1 != nil &&
		rTag2 != nil &&
		rTag1.Version == rTag2.Version &&
		rTag1.Nonce == rTag2.Nonce &&
		policyutil.EquivalentPolicies(rTag1.Policies, rTag2.Policies) &&
		rTag1.MaxTTL == rTag2.MaxTTL &&
		rTag1.Role == rTag2.Role &&
		rTag1.HMAC == rTag2.HMAC &&
		rTag1.InstanceID == rTag2.InstanceID &&
		rTag1.DisallowReauthentication == rTag2.DisallowReauthentication &&
		rTag1.AllowInstanceMigration == rTag2.AllowInstanceMigration
}
