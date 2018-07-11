package ttls

import (
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/logical"
	"errors"
)

// TODO this is actually PR'd in https://github.com/hashicorp/vault/pull/4910
// so if/when that's merged, strip this and use that.
type MountHandler struct {
	// ConfigTTL is the TTL being set at a mount's config level.
	// For example, if your plugin were the Azure secrets engine,
	// and you had a path for an overall config like <mount>/config,
	// this would be the TTL at that level.
	ConfigTTL 		time.Duration

	// ConfigMaxTTL is the MaxTTL being set at a mount's config level.
	// For example, if your plugin were the Azure secrets engine,
	// and you had a path for an overall config like <mount>/config,
	// this would be the MaxTTL at that level.
	ConfigMaxTTL 	time.Duration

	// RoleTTL is the TTL being set at a role level, which is a lower
	// and more specific level than the config level.
	RoleTTL 		time.Duration

	// RoleMaxTTL is the MaxTTL being set at a role level, which is a lower
	// and more specific level than the config level.
	RoleMaxTTL 		time.Duration
}

func (h *MountHandler) Validate(system logical.SystemView) error {

	merr := &multierror.Error{}

	// Verify the config-level TTL's alone.
	if h.ConfigTTL < 0 {
		merr = multierror.Append(merr, errors.New("config ttl < 0"))
	}
	if h.ConfigMaxTTL < 0 {
		merr = multierror.Append(merr, errors.New("config max_ttl < 0"))
	}
	if h.ConfigTTL > system.DefaultLeaseTTL() {
		merr = multierror.Append(merr, errors.New("config ttl > system defined TTL"))
	}
	if h.ConfigMaxTTL > system.MaxLeaseTTL() {
		merr = multierror.Append(merr, errors.New("config max_ttl > system defined max TTL"))
	}
	if h.ConfigTTL > h.ConfigMaxTTL && h.ConfigMaxTTL != 0 {
		merr = multierror.Append(merr, errors.New("config ttl > config max_ttl"))
	}

	// Verify the role-level TTL's alone.
	if h.RoleTTL < 0 {
		merr = multierror.Append(merr, errors.New("role ttl < 0"))
	}
	if h.RoleMaxTTL < 0 {
		merr = multierror.Append(merr, errors.New("role max_ttl < 0"))
	}
	if h.RoleTTL > system.DefaultLeaseTTL() {
		merr = multierror.Append(merr, errors.New("role ttl > system defined TTL"))
	}
	if h.RoleMaxTTL > system.MaxLeaseTTL() {
		merr = multierror.Append(merr, errors.New("role max_ttl > system defined max TTL"))
	}
	if h.RoleTTL > h.RoleMaxTTL && h.RoleMaxTTL != 0 {
		merr = multierror.Append(merr, errors.New("role ttl > role max_ttl"))
	}

	// Verify the config and role TTL's in relation to each other.
	if h.RoleTTL > h.ConfigTTL && h.ConfigTTL != 0 {
		merr = multierror.Append(merr, errors.New("role ttl > config ttl"))
	}
	if h.RoleMaxTTL > h.ConfigMaxTTL && h.ConfigMaxTTL != 0 {
		merr = multierror.Append(merr, errors.New("role max_ttl > config max_ttl"))
	}
	return merr.ErrorOrNil()
}

func (h *MountHandler) SetSecretTTLs(system logical.SystemView, secret *logical.Secret) error {
	// First, validate TTL's so we can make further assumptions about their relationships.
	if err := h.Validate(system); err != nil {
		return err
	}
	// Now that we've arrived here, we know that TTL's are valid, so we just need to set them
	// in order of precedence. Config TTL's should be set first so they can be overridden by
	// role TTL's if they exist.
	if h.ConfigTTL > 0 {
		secret.TTL = h.ConfigTTL
	}
	if h.ConfigMaxTTL > 0 {
		secret.MaxTTL = h.ConfigMaxTTL
	}
	if h.RoleTTL > 0 {
		secret.TTL = h.RoleTTL
	}
	if h.RoleMaxTTL > 0 {
		secret.MaxTTL = h.RoleMaxTTL
	}
	return nil
}
