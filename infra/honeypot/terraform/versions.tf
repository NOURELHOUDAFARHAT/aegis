# The honeypot sensor on Oracle Cloud Infrastructure, Always Free tier.
#
# Credentials are NOT in this folder. The provider reads them from a profile in
# ~/.oci/config, which the OCI console generates when you add an API key. That
# keeps OCIDs, key fingerprints and private-key paths out of every file here.

terraform {
  required_version = ">= 1.9"

  required_providers {
    oci = {
      source  = "oracle/oci"
      version = "~> 9.1"
    }
  }
}

provider "oci" {
  config_file_profile = var.oci_profile
  region              = var.region
}
