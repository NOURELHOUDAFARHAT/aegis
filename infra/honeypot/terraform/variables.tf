# ---------------------------------------------------------------------------
# Account
# ---------------------------------------------------------------------------

variable "region" {
  description = "Your OCI home region, e.g. eu-paris-1. Always Free compute exists only in the home region."
  type        = string
}

variable "oci_profile" {
  description = "Profile name in ~/.oci/config holding the API key."
  type        = string
  default     = "DEFAULT"
}

variable "compartment_ocid" {
  description = "Where to create resources. The tenancy OCID means the root compartment."
  type        = string
}

# ---------------------------------------------------------------------------
# Who may administer the VM
# ---------------------------------------------------------------------------

variable "admin_cidr" {
  description = <<-EOT
    The only network allowed to reach the real SSH port: your home IP as a /32,
    e.g. 203.0.113.7/32. Home IPs change; if you are locked out, update this
    and run terraform apply again.
  EOT
  type        = string

  validation {
    condition = (
      can(cidrnetmask(var.admin_cidr)) &&
      tonumber(split("/", var.admin_cidr)[1]) >= 24
    )
    error_message = "admin_cidr must be a valid CIDR of /24 or narrower. The admin port must never be open to the whole internet."
  }
}

variable "admin_ssh_port" {
  description = "The real OpenSSH port. Port 22 is given to the honeypot."
  type        = number
  default     = 22222

  validation {
    condition     = var.admin_ssh_port > 1024 && var.admin_ssh_port < 65536 && var.admin_ssh_port != 2222 && var.admin_ssh_port != 2223
    error_message = "admin_ssh_port must be above 1024 and must not collide with Cowrie's internal ports 2222/2223."
  }
}

variable "admin_ssh_public_key_path" {
  description = "Public key for the 'ubuntu' admin user."
  type        = string
}

variable "reader_ssh_public_key_path" {
  description = <<-EOT
    Public key AEGIS uses to pull logs. It is installed for a separate 'aegis'
    user that can run exactly one read-only command and nothing else.
  EOT
  type        = string
}

# ---------------------------------------------------------------------------
# Machine
# ---------------------------------------------------------------------------

variable "shape" {
  description = "VM.Standard.A1.Flex (Arm, preferred) or VM.Standard.E2.1.Micro (x86, 1 GB) if A1 capacity is unavailable."
  type        = string
  default     = "VM.Standard.A1.Flex"

  validation {
    condition     = contains(["VM.Standard.A1.Flex", "VM.Standard.E2.1.Micro"], var.shape)
    error_message = "Only the two Always Free shapes are allowed, so this configuration can never create a billed VM."
  }
}

variable "ocpus" {
  description = "A1 only. The Always Free A1 allowance is 2 OCPUs in total since 15 June 2026."
  type        = number
  default     = 1

  validation {
    condition     = var.ocpus >= 1 && var.ocpus <= 2
    error_message = "ocpus must be 1 or 2 to stay inside the Always Free A1 allowance."
  }
}

variable "memory_gb" {
  description = "A1 only. The Always Free A1 allowance is 12 GB in total since 15 June 2026."
  type        = number
  default     = 6

  validation {
    condition     = var.memory_gb >= 1 && var.memory_gb <= 12
    error_message = "memory_gb must be between 1 and 12 to stay inside the Always Free A1 allowance."
  }
}

variable "boot_volume_gb" {
  description = "Boot volume size. Always Free includes 200 GB of block storage in total."
  type        = number
  default     = 50

  validation {
    condition     = var.boot_volume_gb >= 50 && var.boot_volume_gb <= 200
    error_message = "boot_volume_gb must be between 50 (the OCI minimum) and 200 (the Always Free total)."
  }
}

variable "availability_domain_index" {
  description = "Which availability domain to use. Change it if A1 reports 'Out of capacity'."
  type        = number
  default     = 0
}

# ---------------------------------------------------------------------------
# Honeypot
# ---------------------------------------------------------------------------

variable "enable_telnet" {
  description = "Also emulate Telnet on port 23. Telnet is where IoT botnets such as Mirai recruit."
  type        = bool
  default     = true
}
