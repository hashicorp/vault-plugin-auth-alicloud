# Copyright IBM Corp. 2018, 2025
# SPDX-License-Identifier: MPL-2.0

schema = "2"

project "vault-plugin-auth-alicloud" {
  team = "vault"
  slack {
    notification_channel = "C09LD1XT5MX"
  }
  github {
    organization     = "hashicorp"
    repository       = "vault-plugin-auth-alicloud"
    release_branches = ["main", "release/**"]
  }
}

event "merge" {
}

event "build" {
  depends = ["merge"]
  action "build" {
    organization = "hashicorp"
    repository   = "vault-plugin-auth-alicloud"
    workflow     = "build"
  }
}

event "prepare" {
  depends = ["build"]
  action "prepare" {
    organization = "hashicorp"
    repository   = "crt-workflows-common"
    workflow     = "prepare"
    depends      = ["build"]
  }

  notification {
    on = "fail"
  }
}

event "trigger-staging" {
  // This event is dispatched by the bob trigger-promotion command
  // and is required - do not delete.
}

event "promote-staging" {
  depends = ["trigger-staging"]
  action "promote-staging" {
    organization = "hashicorp"
    repository   = "crt-workflows-common"
    workflow     = "promote-staging"
    config       = "release-metadata.hcl"
  }

  notification {
    on = "always"
  }
}

event "trigger-production" {
  // This event is dispatched by the bob trigger-promotion command
  // and is required - do not delete.
}

event "promote-production" {
  depends = ["trigger-production"]
  action "promote-production" {
    organization = "hashicorp"
    repository   = "crt-workflows-common"
    workflow     = "promote-production"
  }

  notification {
    on = "always"
  }
}
